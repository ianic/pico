const std = @import("std");
const assert = std.debug.assert;

const Entry = extern struct {
    name: [12]u8 = @splat(0),
    size: u32 = 0,

    fn sizeWithPadding(self: @This()) u32 {
        const padding: u8 = (4 - @as(u8, @intCast(self.size & 0b11)) & 0b11);
        return self.size + padding;
    }
};

test "load" {
    const testing = std.testing;
    const gpa = testing.allocator;

    const files: []const []const u8 = &.{
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_61.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_88.bin",
        "../../../../Code/microzig/drivers/wireless/cyw43/firmware/43439A0_clm.bin",
    };

    var fat = try std.Io.Writer.Allocating.initCapacity(gpa, 4);
    var fw = &fat.writer;
    defer fat.deinit();

    var blob = std.Io.Writer.Allocating.init(gpa);
    var bw = &blob.writer;
    defer blob.deinit();

    var offset: u32 = 0;
    for (files) |path| {
        const basename = std.fs.path.basename(path)[8..];
        const bytes = try std.fs.cwd().readFileAlloc(gpa, path, 1024 * 1024); // 1MB
        defer gpa.free(bytes);
        std.debug.print("{s} {d} {s}\n", .{ basename, bytes.len, path });

        try fw.ensureUnusedCapacity(@sizeOf(Entry));
        var entry: Entry = .{ .size = @intCast(bytes.len) };
        const name_len = @min(basename.len, entry.name.len);
        @memcpy(entry.name[0..name_len], basename[0..name_len]);
        try fw.writeAll(std.mem.asBytes(&entry));

        offset += @intCast(bytes.len);

        const padding: u8 = (4 - @as(u8, @intCast(bytes.len & 0b11)) & 0b11);
        try bw.ensureUnusedCapacity(bytes.len + padding);
        try bw.writeAll(bytes);
        for (0..padding) |_| {
            try bw.writeByte(0);
        }
    }

    try fw.ensureUnusedCapacity(@sizeOf(Entry));
    const entry: Entry = .{};
    try fw.writeAll(std.mem.asBytes(&entry));

    const output = try std.fs.cwd().createFile("pfs.bin", .{});
    defer output.close();
    var ow = output.writer(&.{});
    try ow.interface.writeAll(fat.written());
    try ow.interface.writeAll(blob.written());
}

test "parse" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const path = "pfs.bin";

    const bytes = try std.fs.cwd().readFileAlloc(gpa, path, 4 * 1024 * 1024);
    defer gpa.free(bytes);

    var rdr = std.Io.Reader.fixed(bytes);

    const name = "7_95_61.bin";
    var size: u32 = 0;
    var offset: u32 = 0;
    var entries: u32 = 0;
    while (true) {
        const entry = try rdr.takeStruct(Entry, .little);
        entries += 1;
        if (entry.size == 0) break;
        if (size > 0) continue;
        if (std.mem.eql(u8, name, entry.name[0..name.len])) {
            size = entry.size;
            continue;
        }
        std.debug.print(
            "entry: {s} size: {} withPadding: {} offset: {}\n",
            .{ entry.name, entry.size, entry.sizeWithPadding(), offset },
        );
        offset += entry.sizeWithPadding();
    }
    std.debug.print("{} {} {}\n", .{ size, entries, offset });

    std.debug.print("{x}\n", .{bytes[@sizeOf(Entry) * entries ..][offset..][0..size][0..64]});
}
