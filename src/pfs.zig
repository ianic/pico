const std = @import("std");
const assert = std.debug.assert;

const usage =
    \\Usage: ./psf [options]
    \\
    \\Options:
    \\  --output-file OUTPUT_BIN_FILE
    \\
;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    var opt_output_file: ?[]const u8 = null;

    {
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, "-h", arg) or std.mem.eql(u8, "--help", arg)) {
                try std.fs.File.stdout().writeAll(usage);
                return std.process.cleanExit();
            } else if (std.mem.eql(u8, "--output-file", arg)) {
                i += 1;
                if (i > args.len) fatal("expected arg after '{s}'", .{arg});
                if (opt_output_file != null) fatal("duplicated {s} argument", .{arg});
                opt_output_file = args[i];
            } else {
                fatal("unrecognized arg: '{s}'", .{arg});
            }
        }
    }
    const output_file = opt_output_file orelse fatal("missing --output-file", .{});

    const input_files: []const []const u8 = &.{
        "/home/ianic/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_61.bin",
        "/home/ianic/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_88.bin",
        "/home/ianic/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_clm.bin",
    };

    var index = try std.Io.Writer.Allocating.initCapacity(arena, 4);
    var iw = &index.writer;
    defer index.deinit();

    var blob = std.Io.Writer.Allocating.init(arena);
    var bw = &blob.writer;
    defer blob.deinit();

    var offset: u32 = input_files.len * 8;
    for (input_files) |path| {
        const basename = std.fs.path.basename(path)[8..];
        const bytes = try std.fs.cwd().readFileAlloc(arena, path, 4 * 1024 * 1024);
        defer arena.free(bytes);
        std.debug.print("{s} {d} {s}\n", .{ basename, bytes.len, path });

        try iw.writeInt(u32, offset, .little);
        try iw.writeInt(u32, @intCast(bytes.len), .little);
        const padding: u8 = (4 - @as(u8, @intCast(bytes.len & 0b11)) & 0b11);
        offset += @intCast(bytes.len + padding);

        try bw.writeAll(bytes);
        for (0..padding) |_| {
            try bw.writeByte(0);
        }
    }

    const output = try std.fs.cwd().createFile(output_file, .{});
    defer output.close();
    var ow = output.writer(&.{});
    try ow.interface.writeAll(index.written());
    try ow.interface.writeAll(blob.written());

    return std.process.cleanExit();
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(format, args);
    std.process.exit(1);
}

test "load" {
    const testing = std.testing;
    const gpa = testing.allocator;

    const files: []const []const u8 = &.{
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_61.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_88.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_clm.bin",
    };

    var index = try std.Io.Writer.Allocating.initCapacity(gpa, 4);
    var iw = &index.writer;
    defer index.deinit();

    var blob = std.Io.Writer.Allocating.init(gpa);
    var bw = &blob.writer;
    defer blob.deinit();

    var offset: u32 = files.len * 8;
    for (files) |path| {
        const basename = std.fs.path.basename(path)[8..];
        const bytes = try std.fs.cwd().readFileAlloc(gpa, path, 4 * 1024 * 1024);
        defer gpa.free(bytes);
        std.debug.print("{s} {d} {s}\n", .{ basename, bytes.len, path });

        try iw.writeInt(u32, offset, .little);
        try iw.writeInt(u32, @intCast(bytes.len), .little);
        const padding: u8 = (4 - @as(u8, @intCast(bytes.len & 0b11)) & 0b11);
        offset += @intCast(bytes.len + padding);

        try bw.writeAll(bytes);
        for (0..padding) |_| {
            try bw.writeByte(0);
        }
    }

    const output = try std.fs.cwd().createFile("pfs.bin", .{});
    defer output.close();
    var ow = output.writer(&.{});
    try ow.interface.writeAll(index.written());
    try ow.interface.writeAll(blob.written());
}

test "parse" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const path = "pfs.bin";

    const bytes = try std.fs.cwd().readFileAlloc(gpa, path, 4 * 1024 * 1024);
    defer gpa.free(bytes);

    const index = 1;
    const offset = std.mem.readInt(u32, bytes[8 * index ..][0..4], .little);
    const size = std.mem.readInt(u32, bytes[8 * index ..][4..8], .little);

    const content = bytes[offset..][0..size];

    std.debug.print("index: {} content: {x}\n", .{ index, content[0..64] });
}

pub fn fileFromBlob(addr: usize, index: usize) []const u8 {
    const index_buf = @as([*]const u8, @ptrFromInt(addr))[8 * index ..][0..8];

    const offset = std.mem.readInt(u32, index_buf[0..4], .little);
    const size = std.mem.readInt(u32, index_buf[4..8], .little);

    return @as([*]const u8, @ptrFromInt(addr))[offset..][0..size];
}
