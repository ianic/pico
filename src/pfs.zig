const std = @import("std");
const assert = std.debug.assert;

test "load" {
    const testing = std.testing;

    const files: []const []const u8 = &.{
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_61.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_88.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_clm.bin",
    };

    const gpa = testing.allocator;

    var header = try std.Io.Writer.Allocating.initCapacity(gpa, 4);
    var hw = &header.writer;

    var content = std.Io.Writer.Allocating.init(gpa);
    var cw = &content.writer;

    // var header: []u8 = gpa.alloc(u8, 4);
    // var header_pos: usize = 4;
    // var content: []u8 = &.{};
    // var content_pos: usize = 0;
    // defer gpa.free(content);

    var offset: u32 = 0;
    for (files) |path| {
        const basename = std.fs.path.basename(path);
        const bytes = try std.fs.cwd().readFileAlloc(gpa, path, 1024 * 1024); // 1MB
        defer gpa.free(bytes);
        std.debug.print("{s} {d} {s}\n", .{ basename, bytes.len, path });

        try hw.ensureUnusedCapacity(1 + basename.len + 4 + 4);
        try hw.writeByte(@intCast(basename.len));
        try hw.writeAll(basename);
        try hw.writeInt(u32, offset, .little);
        try hw.writeInt(u32, @intCast(bytes.len), .little);
        offset += @intCast(bytes.len);

        try cw.ensureUnusedCapacity(bytes.len);
        try cw.writeAll(bytes);

        // header = try gpa.realloc(content, header_pos + 1 + basename.len + 4 + 4);
        // header[header_pos] = @intCast(basename.len);
        // content_pos += 1;
        // @memcpy(content[content_pos..][0..basename.len], basename);

        // content = try gpa.realloc(content, content_pos + 1 + basename.len + 4 + bytes.len);

        // content_pos += basename.len;
        // std.mem.writeInt(u32, content[content_pos..][0..4], @intCast(bytes.len), .little);
        // content_pos += 4;
        // @memcpy(content[content_pos..][0..bytes.len], bytes);
        // content_pos += bytes.len;
        // assert(content_pos == content.len);
    }

    const header_buf = try header.toOwnedSlice();
    std.mem.writeInt(u32, header_buf[0..4], @intCast(header_buf.len), .little);
    const content_buf = try content.toOwnedSlice();
    defer gpa.free(header_buf);
    defer gpa.free(content_buf);

    const output = try std.fs.cwd().createFile("pfs.bin", .{});
    defer output.close();
    var ow = output.writer(&.{});
    try ow.interface.writeAll(header_buf);
    try ow.interface.writeAll(content_buf);
}
