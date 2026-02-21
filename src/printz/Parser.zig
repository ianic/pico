//! Analyze a format string

// TODO: diagnostic on syntax error

i: usize,
str: []const u8,

pub fn init(str: []const u8) Parser {
    return .{
        .i = 0,
        .str = str,
    };
}

pub fn next(self: *Parser) Error!?Token {
    if (self.i >= self.str.len) return null;

    const slice = self.str[self.i..];

    const maybe_index = std.mem.indexOf(u8, slice, "%");
    const index = maybe_index orelse {
        self.i += slice.len;
        return .{
            .text = slice,
        };
    };

    // slice is '...%'
    if (index != 0) {
        self.i += index;
        return .{
            .text = slice[0..index],
        };
    }

    // slice is '%...'
    const parsed = try parseSpecifier(slice);
    self.i += parsed.offset; // is the -1 ok?

    return .{
        .specifier = parsed.value,
    };
}

const Error = error{
    InvalidFormat,
};

fn parseFlags(slice: []const u8) Error!Parsed(Flags) {
    var flags: Flags = .empty;
    var offset: usize = 0;

    for (slice) |c| {
        switch (c) {
            '#' => flags.hash = true,
            '0' => flags.zero = true,
            '-' => flags.minus = true,
            ' ' => flags.space = true,
            '+' => flags.plus = true,
            else => return .{
                .value = flags,
                .offset = offset,
            },
        }

        offset += 1;
    }

    // `for` did not run (empty slice)
    return error.InvalidFormat;
}

fn parseNum(slice: []const u8) Error!Parsed(Num) {
    return switch (slice[0]) {
        '*' => .{
            .value = .arg,
            .offset = 1,
        },
        // NOTE: leading 0 is no allowed (??)
        '1'...'9' => {
            var number: usize = 0;

            for (slice, 0..) |c, i| {
                switch (c) {
                    '0'...'9' => number = (number * 10) + (c - '0'),
                    else => return .{
                        .value = .{ .number = number },
                        .offset = i,
                    },
                }
            }

            // `for` will always run
            // we already accessed `slice[0]`, slice is not empty
            unreachable;
        },
        else => .{
            .value = .none,
            .offset = 0,
        },
    };
}

fn parseWidth(slice: []const u8) Error!Parsed(Num) {
    return parseNum(slice);
}

fn parsePrecision(slice: []const u8) Error!Parsed(Num) {
    if (slice[0] != '.') {
        return .{
            .value = .none,
            .offset = 0,
        };
    }

    const num = try parseWidth(slice[1..]);

    // just '.' means width=0
    if (num.value == .none) {
        return .{
            .value = .{
                .number = 0,
            },
            .offset = 1 + num.offset,
        };
    }

    return .{
        .value = num.value,
        .offset = 1 + num.offset,
    };
}

fn parseModifier(slice: []const u8) Error!Parsed(Modifier) {
    return switch (slice[0]) {
        'h' => if (slice[1] == 'h')
            .{
                .value = .hh,
                .offset = 2,
            }
        else
            .{
                .value = .h,
                .offset = 1,
            },
        'l' => if (slice[1] == 'l')
            .{
                .value = .ll,
                .offset = 2,
            }
        else
            .{
                .value = .l,
                .offset = 1,
            },
        else => .{
            .value = .none,
            .offset = 0,
        },
    };
}

fn parseType(slice: []const u8) Error!Parsed(Type) {
    const typ: Type = switch (slice[0]) {
        'd' => .d,
        'i' => .i,
        'o' => .o,
        'u' => .u,
        'x' => .x,
        'X' => .X,
        'e' => .e,
        'E' => .E,
        'f' => .f,
        'F' => .F,
        'g' => .g,
        'G' => .G,
        'a' => .a,
        'A' => .A,
        'c' => .c,
        's' => .s,
        'p' => .p,
        'n' => .n,
        '%' => .@"%",
        else => return error.InvalidFormat,
    };

    return .{
        .value = typ,
        .offset = 1,
    };
}

fn parseSpecifier(slice: []const u8) Error!Parsed(Specifier) {
    var offset: usize = 0;

    if (slice[0] != '%') return error.InvalidFormat;
    offset += 1;

    const flags = try parseFlags(slice[offset..]);
    offset += flags.offset;

    const width = try parseWidth(slice[offset..]);
    offset += width.offset;

    const precision = try parsePrecision(slice[offset..]);
    offset += precision.offset;

    const modifier = try parseModifier(slice[offset..]);
    offset += modifier.offset;

    const typ = try parseType(slice[offset..]);
    offset += typ.offset;

    return .{
        .value = .{
            .flags = flags.value,
            .width = width.value,
            .precision = precision.value,
            .modifier = modifier.value,
            .type = typ.value,
        },
        .offset = offset,
    };
}

fn Parsed(T: type) type {
    return struct {
        value: T,
        offset: usize,
    };
}

const std = @import("std");
const Parser = @This();
const token = @import("token.zig");
const Flags = token.Flags;
const Modifier = token.Modifier;
const Num = token.Num;
const Specifier = token.Specifier;
const Token = token.Token;
const Type = token.Type;
