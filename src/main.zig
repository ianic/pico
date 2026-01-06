const std = @import("std");
const microzig = @import("microzig");
const rp2xxx = microzig.hal;
const gpio = rp2xxx.gpio;
const time = rp2xxx.time;

// Compile-time pin configuration
const pin_config = rp2xxx.pins.GlobalConfiguration{
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};
const pins = pin_config.pins();

pub fn main() !void {
    pin_config.apply();
    const led = pins.led;

    while (true) {
        led.toggle();
        time.sleep_ms(250);
    }
}
