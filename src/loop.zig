const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;

const log = std.log.scoped(.loop);

pub const Interval = struct {
    const Self = @This();

    every: u32 = 0,
    timeout: u32 = 0,

    pub fn init(ms: usize) Self {
        return .{
            .every = ms * 1000,
        };
    }

    pub fn is_reached_by(self: *Interval, now: u32) bool {
        if (self.timeout <= now) {
            if (self.timeout & 0x80_00_00_00 == 0 and now & 0x80_00_00_00 > 0)
                return false;

            self.timeout = now +% self.every;
            return true;
        }
        return false;
    }
};

// Puts pico in bootsel mode is command is received on uart.
pub fn check_reset(uart: hal.uart.UART) void {
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

const testing = std.testing;

test "u32 overflow" {
    var interval: Interval = .{
        .every = 100,
        .timeout = (1 << 32) - 50,
    };

    var now: u32 = (1 << 32) - 51;
    try testing.expect(!interval.is_reached_by(now));
    now += 2;
    try testing.expect(interval.is_reached_by(now));
    now += 48;
    try testing.expect(!interval.is_reached_by(now));
    now +%= 50;
    try testing.expect(!interval.is_reached_by(now));
    now += 2;
    try testing.expect(interval.is_reached_by(now));
}
