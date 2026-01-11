const std = @import("std");
const microzig = @import("microzig");

const MicroBuild = microzig.MicroBuild(.{
    .rp2xxx = true,
});

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const mz_dep = b.dependency("microzig", .{});
    const mb = MicroBuild.init(b, mz_dep) orelse return;
    const target = mb.ports.rp2xxx.boards.raspberrypi.pico2_arm;

    const net_dep = b.dependency("net", .{
        .target = b.resolveTargetQuery(target.zig_target),
        .optimize = optimize,
        .lwip_mem_size = 32 * 1024,
        .lwip_pbuf_pool_size = 32,
    });
    const net_mod = net_dep.module("net");

    const apps: []const []const u8 = &.{
        "blinky",
        "udp",
    };
    inline for (apps) |app| {
        const firmware = mb.add_firmware(.{
            .name = app,
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/" ++ app ++ ".zig"),
            .imports = &.{
                .{ .name = "net", .module = net_mod },
            },
        });
        mb.install_firmware(firmware, .{});
    }
}
