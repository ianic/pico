const std = @import("std");
const microzig = @import("microzig");

const hal = microzig.hal;
const gpio = hal.gpio;
const time = hal.time;
const uart = hal.uart.instance.num(0);
const drivers = hal.drivers;

pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
};
const log = std.log.scoped(.main);

// Compile-time pin configuration
const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    // external led connected to the gpio 15 pin
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};
const pins = pin_config.pins();

pub fn main() !void {
    pin_config.apply();
    // Init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // Init cyw43 chip
    var wifi_driver: drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{});
    var led = wifi.gpio(0); // on-board led
    led.toggle();

    while (true) {
        pins.led.toggle();
        led.toggle();
        time.sleep_ms(500);
        check_reboot();
    }
}

// Puts pico in bootsel mode by uart command.
fn check_reboot() void {
    const MAGICREBOOTCODE: u8 = 0xAB;
    const v = uart.read_word() catch {
        uart.clear_errors();
        return;
    } orelse return;
    if (v == MAGICREBOOTCODE) {
        log.warn("reboot cmd received", .{});
        hal.rom.reset_to_usb_boot();
    }
}
