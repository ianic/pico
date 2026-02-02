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
        .mem_size = 32 * 1024,
        .pbuf_pool_size = 32,
        .mtu = 1500,
        // Cyw43 driver requires 22 bytes of header and 4 bytes of footer.
        // header + ethernet + mtu + footer = 22 + 14 + 1500 + 4 = 1540
        .pbuf_length = 1540,
        .pbuf_header_length = 22,
    });
    const net_mod = net_dep.module("net");

    const apps: []const []const u8 = &.{
        "blinky",
        "udp",
        "pong",
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
        mb.install_firmware(firmware, .{ .format = .elf });
    }

    { // generate and load blob
        const generate = b.addExecutable(.{
            .name = "pfs",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/pfs.zig"),
                .target = b.graph.host,
            }),
        });
        const tool_step = b.addRunArtifact(generate);
        tool_step.addArg("--output-file");
        const output = tool_step.addOutputFileArg("pfs.bin");

        const load = b.addSystemCommand(&.{"picotool"});
        load.addArgs(&.{ "load", "--offset", "0x10300000", "--verify" });
        load.addFileArg(output);
        load.step.dependOn(&b.addInstallFileWithDir(output, .prefix, "psf.bin").step);

        const blob_step = b.step("blob", "Upload files blob to the pico");
        blob_step.dependOn(&load.step);
    }
}
