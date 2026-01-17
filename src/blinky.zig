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

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // init cyw43 chip
    var wifi_driver: hal.drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{});
    var led = wifi.gpio(0); // on-board led
    led.toggle();

    var scan = try wifi.scan_poller();
    while (try scan.poll()) {
        if (scan.result()) |res| {
            log.debug(
                "ssid: {s:<20}, channel: {}, open: {:<5}, ap mac {x}",
                .{ res.ssid, res.channel, res.security.open(), res.ap_mac },
            );
        }
        hal.time.sleep_ms(10);
    }

    // main loop
    var ticks: u32 = 0;
    while (true) : (ticks +%= 1) {
        if (ticks % 2 == 0) {
            pins.led.toggle();
            led.toggle();
        }
        loop.check_reset(uart);
        hal.time.sleep_ms(100);
    }
}
