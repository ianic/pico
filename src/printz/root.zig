//! Zig library implementing `printf`

inline fn fmtOptions(specifier: Specifier, ap: *VaList) Number {
    const mode: Number.Mode = switch (specifier.type) {
        .d,
        .i,
        .u,
        .f,
        .F,
        .g,
        .G,
        // these 2 should be printex in hex :thinking:
        .a,
        .A,
        => .decimal,

        .e,
        .E,
        => .scientific,

        .o,
        => .octal,

        .x,
        .X,
        => .hex,

        else => unreachable,
    };

    const case: Case = switch (specifier.type) {
        .d,
        .i,
        .o,
        .u,
        .x,
        .e,
        .f,
        .g,
        .a,
        => .lower,

        .X,
        .E,
        .F,
        .G,
        .A,
        => .upper,

        else => unreachable,
    };

    const precision: ?usize = switch (specifier.precision) {
        .none => null,
        .arg => @intCast(@cVaArg(ap, c_int)),
        .number => |val| val,
    };

    const width: ?usize = switch (specifier.width) {
        .none => null,
        .arg => @intCast(@cVaArg(ap, c_int)),
        .number => |val| val,
    };

    const alignment: Alignment = if (specifier.flags.minus)
        .left
    else
        .right;

    const fill: u8 = if (!specifier.flags.minus and specifier.flags.zero)
        '0'
    else
        ' ';

    return .{
        .mode = mode,
        .case = case,
        .precision = precision,
        .width = width,
        .alignment = alignment,
        .fill = fill,
    };
}

pub export fn snprintf(buffer: [*c]u8, len: usize, format: [*c]const u8, ...) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);

    return vsnprintf(buffer, len, format, &ap);
}

pub export fn vsnprintf(buffer: [*c]u8, len: usize, format: [*c]const u8, ap: *VaList) c_int {
    var writer: Writer = .fixed(buffer[0..len]);
    return impl(&writer, format, ap) catch return -1;
}

inline fn impl(w: *Writer, format: [*c]const u8, ap: *VaList) !c_int {
    const slice: [:0]const u8 = std.mem.sliceTo(format, 0);
    var parser: Parser = .init(slice);

    while (try parser.next()) |token| {
        const specifier = switch (token) {
            .specifier => |specifier| specifier,
            .text => |text| {
                _ = try w.write(text);
                continue;
            },
        };

        switch (specifier.type) {
            .c => try printChar(w, ap, specifier),
            .s => try printStr(w, ap, specifier),
            .p => try printPtr(w, ap, specifier),
            .n => try handleN(w, ap, specifier),
            .@"%" => try printPercent(w, ap, specifier),
            else => try printNum(w, ap, specifier),
        }
    }

    // dump buffer, return count of bytes written
    try w.flush();

    // terminator shouldn't be counted (?)
    var bytes: c_int = @intCast(w.end);
    while (bytes > 0) {
        const last: usize = @intCast(bytes - 1);
        if (w.buffer[last] == 0 or w.buffer[last] == '\n') {
            bytes -= 1;
            continue;
        }
        break;
    }
    return bytes;
}

inline fn printChar(writer: *Writer, ap: *VaList, _: Specifier) Writer.Error!void {
    // FIXME: wint_t
    const int = @cVaArg(ap, c_int);
    const c: u8 = @intCast(int); // FIXME: c_uchar
    try writer.writeByte(c);
}

inline fn printStr(writer: *Writer, ap: *VaList, specifier: Specifier) Writer.Error!void {
    // FIXME: wchar_t

    const s = @cVaArg(ap, [*c]const u8);

    const slice: []const u8 = switch (specifier.precision) {
        .none => std.mem.sliceTo(s, 0),
        .arg => s[0..@intCast(@cVaArg(ap, c_int))],
        .number => |number| s[0..number],
    };

    if (numValue(specifier.width, ap)) |width| {
        if (width > slice.len) {
            for (slice.len..width) |_| {
                try writer.writeByte(' ');
            }
        }
    }

    try writer.print("{s}", .{slice});
}

inline fn printPtr(writer: *Writer, ap: *VaList, _: Specifier) Writer.Error!void {
    const p = @cVaArg(ap, *void);
    const i = @intFromPtr(p);
    _ = try writer.write("0x");
    try writer.printInt(i, 16, .lower, .{});
}

inline fn handleN(writer: *Writer, ap: *VaList, specifier: Specifier) Writer.Error!void {
    try writer.flush();
    const count = writer.end;

    switch (specifier.modifier) {
        .none => {
            const ptr = @cVaArg(ap, *c_int);
            ptr.* = @intCast(count);
        },
        .hh => {
            const ptr = @cVaArg(ap, *c_char);
            ptr.* = @intCast(count);
        },
        .h => {
            const ptr = @cVaArg(ap, *c_short);
            ptr.* = @intCast(count);
        },
        .ll => {
            const ptr = @cVaArg(ap, *c_longlong);
            ptr.* = @intCast(count);
        },
        .l => {
            const ptr = @cVaArg(ap, *c_long);
            ptr.* = @intCast(count);
        },
    }
}

fn printPercent(writer: *Writer, _: *VaList, _: Specifier) Writer.Error!void {
    try writer.writeByte('%');
}

inline fn printNum(writer: *Writer, ap: *VaList, specifier: Specifier) Writer.Error!void {
    const options = fmtOptions(specifier, ap);

    switch (specifier.type) {
        .d,
        .i,
        => {
            const base = options.mode.base() orelse unreachable;

            const value: c_longlong = switch (specifier.modifier) {
                .none => @cVaArg(ap, c_int),
                .hh => @cVaArg(ap, c_char),
                .h => @cVaArg(ap, c_short),
                .ll => @cVaArg(ap, c_longlong),
                .l => @cVaArg(ap, c_long),
            };

            try writer.printInt(value, base, options.case, .{
                .precision = options.precision,
                .width = options.width,
                .alignment = options.alignment,
                .fill = options.fill,
            });
        },

        .o,
        .u,
        .x,
        .X,
        => {
            const value: c_ulonglong = switch (specifier.modifier) {
                .none => @cVaArg(ap, c_uint),
                .hh => @cVaArg(ap, u8), // FIXME: c_uchar
                .h => @cVaArg(ap, c_ushort),
                .ll => @cVaArg(ap, c_ulonglong),
                .l => @cVaArg(ap, c_ulong),
            };

            const base = options.mode.base() orelse unreachable;

            if (specifier.flags.hash) {
                switch (specifier.type) {
                    .o => try writer.writeByte('0'),
                    .x => _ = try writer.write("0x"),
                    .X => _ = try writer.write("0X"),
                    else => {},
                }
            }

            try writer.printInt(value, base, options.case, .{
                .precision = options.precision,
                .width = options.width,
                .alignment = options.alignment,
                .fill = options.fill,
            });
        },

        .e,
        .E,
        .f,
        .F,
        .a,
        .A,
        => {
            const value = @cVaArg(ap, f32);
            try writer.printFloat(value, options);
        },

        .g,
        .G,
        => {
            const value = @cVaArg(ap, f32);

            const e_options = blk: {
                var opts = options;
                opts.mode = .scientific;
                break :blk opts;
            };
            const e_len = try floatLen(value, e_options);

            const f_options = blk: {
                var opts = options;
                opts.mode = .decimal;
                break :blk opts;
            };
            const f_len = try floatLen(value, f_options);

            try writer.printFloat(
                value,
                // use shorter config
                if (e_len < f_len)
                    e_options
                else
                    f_options,
            );
        },

        else => unreachable,
    }
}

inline fn numValue(num: Num, ap: *VaList) ?usize {
    return switch (num) {
        .none => null,
        .arg => @intCast(@cVaArg(ap, c_int)),
        .number => |number| number,
    };
}

fn floatLen(value: anytype, options: Number) !usize {
    const discarding: Writer.Discarding = .init(&.{});
    var writer: Writer = discarding.writer;

    try writer.printFloat(value, options);
    try writer.flush();

    return @intCast(discarding.count);
}

const MAX_LEN = std.math.maxInt(usize);

const std = @import("std");
const Alignment = std.fmt.Alignment;
const Case = std.fmt.Case;
const Number = std.fmt.Number;
const VaList = std.builtin.VaList;
const Writer = std.io.Writer;

const Num = @import("token.zig").Num;
pub const Parser = @import("Parser.zig");
pub const Specifier = @import("token.zig").Specifier;

test vsnprintf {
    var buf: [20]u8 = undefined;
    const a: u32 = 1;
    const b: u32 = 2;
    const count = snprintf(&buf, buf.len, "a: %d, b: %d", a, b);
    try std.testing.expectEqual(10, count);
    try std.testing.expectEqualSlices(u8, "a: 1, b: 2", buf[0..@intCast(count)]);
}
