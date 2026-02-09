const std = @import("std");
const microzig = @import("microzig");

const MicroBuild = microzig.MicroBuild(.{
    .rp2xxx = true,
});

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const app_to_deploy = b.option([]const u8, "deploy", "App to deploy after build");

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
    const link_mod = b.dependency("link", .{}).module("link");

    const apps: []const []const u8 = &.{
        "blinky",
        "udp",
        "pong",
        "inet",
    };
    inline for (apps) |app| {
        const firmware = mb.add_firmware(.{
            .name = app,
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/" ++ app ++ ".zig"),
            .imports = &.{
                .{ .name = "net", .module = net_mod },
                .{ .name = "link", .module = link_mod },
            },
        });
        mb.install_firmware(firmware, .{});
        const install_elf = mb.add_install_firmware(firmware, .{ .format = .elf });

        if (app_to_deploy) |name| {
            if (std.mem.eql(u8, app, name)) {
                const write_deploy_script = b.addWriteFile("deploy.sh", b.fmt(
                    "#!/bin/bash                                                \n" ++
                        "set -e                                                 \n" ++
                        "elf={0s}.elf                                           \n" ++
                        "bin={0s}.bin                                           \n" ++
                        "cd zig-out/firmware                                    \n" ++
                        "arm-none-eabi-objcopy -O binary $elf $bin              \n" ++
                        "printf '\xAB' > /dev/ttyACM0 || true                   \n" ++
                        "until picotool load --offset 0x10000000 -x -f $bin; do \n" ++
                        "    sleep 1                                            \n" ++
                        "done                                                   \n",
                    .{name},
                ));
                const run_deploy_script = b.addSystemCommand(&[_][]const u8{
                    "bash", //,"zig-out/deploy.sh",
                });
                run_deploy_script.addFileArg(
                    write_deploy_script.getDirectory().join(b.allocator, "deploy.sh") catch @panic("OOM"),
                );
                run_deploy_script.step.dependOn(&install_elf.step);
                mb.builder.getInstallStep().dependOn(&run_deploy_script.step);
            }
        }
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

    { // zig build test
        const test_mod = b.createModule(.{
            .root_source_file = b.path("src/net/root.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "link", .module = link_mod },
            },
        });
        const unit_tests = b.addTest(.{
            .root_module = test_mod,
        });
        const run_unit_tests = b.addRunArtifact(unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }
}
