const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;
const uart = hal.uart.instance.num(0);
const timer = hal.system_timer.num(0);
const loop = @import("loop.zig");

// logging
pub const microzig_options: microzig.Options = .{
    .log_level = .debug,
    .logFn = hal.uart.log,
};
const log = std.log.scoped(.main);

// pin configuration
const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    // external led connected to the gpio 15 pin
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};
const pins = pin_config.pins();

pub fn main() !void {
    pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // init cyw43 chip
    var wifi_driver: hal.drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{});
    var led = wifi.gpio(0); // on-board led
    led.toggle();

    // main loop
    var blink_interval: loop.Interval = .init(200);
    var reset_interval: loop.Interval = .init(100);
    while (true) {
        const now = timer.read_low();
        if (blink_interval.is_reached_by(now)) {
            pins.led.toggle();
            led.toggle();
        }
        if (reset_interval.is_reached_by(now)) {
            loop.check_reset(uart);
        }
    }
}
