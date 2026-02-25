const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub fn CircularBuffer(comptime T: type, comptime len: usize) type {
    return struct {
        const Self = @This();

        items: [len]T = undefined,
        head: usize = len - 1,
        count: usize = 0,

        pub fn add(self: *Self, t: T) void {
            const idx = self.next();
            self.items[idx] = t;
            self.head = idx;
            self.count += if (self.count < self.items.len) 1 else 0;
        }

        pub fn update(self: *Self, t: T) void {
            self.items[self.head] = t;
        }

        pub fn last(self: *Self) ?T {
            if (self.count == 0) return null;
            return self.items[self.head];
        }

        fn next(self: Self) usize {
            return (self.head + 1) % self.items.len;
        }

        fn tail(self: *Self) ?usize {
            if (self.count == 0) return null;
            if (self.count <= self.items.len) return 0;
            return (self.head + 1) % self.items.len;
        }

        pub fn content(self: *Self) struct { []T, []T } {
            if (self.count < self.items.len) return .{ self.items[0..self.count], &.{} };
            return .{ self.items[self.head + 1 ..], self.items[0 .. self.head + 1] };
        }

        pub fn iterator(self: *Self) Iterator {
            const ls, const rs = self.content();
            return .{
                .s1 = ls,
                .s2 = rs,
            };
        }

        const Iterator = struct {
            s1: []T,
            s2: []T,

            pub fn next(itr: *Iterator) ?T {
                if (itr.s2.len == 0 and itr.s1.len == 0) {
                    return null;
                }
                if (itr.s2.len > 0) {
                    const value, itr.s2 = right(itr.s2);
                    return value;
                }
                const value, itr.s1 = right(itr.s1);
                return value;
            }

            fn right(slice: []T) struct { T, []T } {
                const i = slice.len - 1;
                return .{ slice[i], slice[0..i] };
            }
        };
    };
}

test CircularBuffer {
    const T = struct {
        unix: u32 = 0,
        temp: f32 = 0,
    };

    var cb: CircularBuffer(T, 8) = .{};

    try testing.expectEqual(null, cb.tail());
    var s1, var s2 = cb.content();
    try testing.expectEqual(0, s1.len);
    try testing.expectEqual(0, s2.len);

    for (0..7) |i| {
        cb.add(.{ .unix = @intCast(i + 1), .temp = @floatFromInt(20 + i) });
        try testing.expectEqual(cb.head, i);
        try testing.expectEqual(i + 1, cb.count);
        try testing.expectEqual(0, cb.tail().?);
    }

    s1, s2 = cb.content();
    try testing.expectEqual(7, s1.len);
    try testing.expectEqual(0, s2.len);
    for (s1, 1..) |v, i| {
        try testing.expectEqual(i, v.unix);
        //std.debug.print("{}\n", .{v});
    }

    {
        var i: usize = 7;
        var iter = cb.iterator();
        while (iter.next()) |v| {
            try testing.expectEqual(i, v.unix);
            i -= 1;
        }
    }

    for (7..12) |i| {
        cb.add(.{ .unix = @intCast(i + 1), .temp = @floatFromInt(20 + i) });
    }

    s1, s2 = cb.content();
    try testing.expectEqual(4, s1.len);
    try testing.expectEqual(4, s2.len);

    for (s1, 5..) |v, i| {
        try testing.expectEqual(i, v.unix);
    }
    for (s2, 9..) |v, i| {
        try testing.expectEqual(i, v.unix);
    }

    for (12..13) |i| {
        cb.add(.{ .unix = @intCast(i + 1), .temp = @floatFromInt(20 + i) });
    }

    s1, s2 = cb.content();
    try testing.expectEqual(3, s1.len);
    try testing.expectEqual(5, s2.len);
    std.debug.print("\n", .{});
    for (s1, 6..) |v, i| {
        try testing.expectEqual(i, v.unix);
        //std.debug.print("{}\n", .{v});
    }
    for (s2, 9..) |v, i| {
        try testing.expectEqual(i, v.unix);
        //std.debug.print("{}\n", .{v});
    }

    {
        var i: usize = 13;
        var iter = cb.iterator();
        while (iter.next()) |v| {
            try testing.expectEqual(i, v.unix);
            i -= 1;
        }
    }
}
