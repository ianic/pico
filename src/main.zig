const std = @import("std");
const microzig = @import("microzig");

const hal = microzig.hal;
const gpio = hal.gpio;
const time = hal.time;
const uart = hal.uart.instance.num(0);

pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
};

// Compile-time pin configuration
const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};
const pins = pin_config.pins();

pub fn main() !void {
    pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    const led = pins.led;
    while (true) {
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
        std.log.warn("Reboot cmd received", .{});
        hal.rom.reset_to_usb_boot();
    }
}
