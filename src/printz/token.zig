//! Things found in a format string

/// each element is either text or a specifier
pub const Token = union(enum) {
    text: []const u8,
    specifier: Specifier,

    pub fn format(
        self: Token,
        writer: *std.io.Writer,
    ) std.io.Writer.Error!void {
        switch (self) {
            .text => |text| try writer.print("text = '{s}'", .{text}),
            .specifier => |specifier| try writer.print("specifier = {}", .{specifier}),
        }
    }
};

pub const Specifier = struct {
    flags: Flags,
    width: Num,
    precision: Num,
    modifier: Modifier,
    type: Type,
};

/// which type to be read using `@cVaArg`
pub const Type = enum {
    // int
    d,
    i,
    // unsiged int
    o,
    u,
    x,
    X,
    // double (scientific)
    e,
    E,
    // double (point)
    f,
    F,
    // double (shorter between both above)
    g,
    G,
    // double (hex)
    a,
    A,
    // int -> unsigned char (wint_t -> wcrtomb if 'l' present)
    c,
    // const char * (const wchar_t * if 'l' present)
    s,
    // void *, in hex
    p,
    // bytes written so far, into an int *
    n,
    // write a '%'
    @"%",
};

pub const Flags = packed struct(u5) {
    hash: bool,
    zero: bool,
    minus: bool,
    space: bool,
    plus: bool,

    pub const empty: Flags = @bitCast(@as(u5, 0));
};

pub const Num = union(enum) {
    none,
    arg,
    number: usize,
};

pub const Modifier = enum {
    none,
    hh,
    h,
    l,
    ll,
};

const std = @import("std");
