/// Exports for the lwip
/// Required from modules/network/src/include/arch.cc#L26
const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;
const printz = @import("printz/root.zig");

/// Time since boot in milliseconds.
export fn lwip_sys_now() u32 {
    const ts = hal.time.get_time_since_boot();
    return @truncate(ts.to_us() / 1000);
}

var rng: ?hal.rand.Ascon = null;

export fn lwip_rand() u32 {
    return switch (hal.compatibility.chip) {
        .RP2350 => hal.rand.trng.random_blocking(),
        .RP2040 => brk: {
            if (rng == null) {
                rng = .init();
            }
            var val: u32 = 0;
            rng.?.fill(std.mem.asBytes(&val));
            break :brk val;
        },
    };
}

const log = std.log.scoped(.lwip);

export fn lwip_diag2(fmt: [*:0]const u8, ...) void {
    var args = @cVaStart();
    defer @cVaEnd(&args);

    var buf: [256]u8 = undefined;
    const n = printz.vsnprintf(&buf, buf.len, fmt, &args);
    if (n > 0) {
        log.debug("{s}", .{buf[0..@intCast(n)]});
    }
}
