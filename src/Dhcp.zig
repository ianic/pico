const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const log = std.log.scoped(.dhcp);

const testing = std.testing;
const hexToBytes = @import("testu.zig").hexToBytes;
const net = @import("net.zig");

const Dhcp = @This();

const Mac = [6]u8;
const Addr = [4]u8;

state: State = .initial,
ts: u32 = 0, // timestamp of the last state change
transaction_id: u32 = 0,
args: Args,

const Args = struct {
    mac: Mac,

    addr: Addr = @splat(0),
    subnet_mask: Addr = @splat(0),
    broadcast_addr: Addr = @splat(0xff),

    gateway: Addr = @splat(0),
    dns_server: Addr = @splat(0),
    dhcp_server: Addr = @splat(0),

    lease_time: u32 = 0, // release when expires
    renewal_time: u32 = 0, // renew/get new from the same server
    rebinding_time: u32 = 0, // get new from any server

    mtu: u16 = 0,
};

const State = enum {
    initial,
    discover, // discover massage is sent
    offer, // offer is recived
    request, // request message is sent
    bound, // server acknowledged request
};

const Boot = extern struct {
    op: u8 = 1, // operation request = 1, reply = 2
    htype: u8 = 1, // hardware type, ethernet = 1
    heln: u8 = 6, // number of bytes in chaddr (mac)
    hops: u8 = 0,
    xid: u32 = 0, // transaction id
    secs: u16 = 0,
    flags: [2]u8 = .{ 0x80, 0x00 }, // broadcast flag set
    ciaddr: [4]u8 = @splat(0),
    yiaddr: [4]u8 = @splat(0), // your ip address
    siaddr: [4]u8 = @splat(0),
    giaddr: [4]u8 = @splat(0),
    chaddr: [16]u8 = @splat(0), // client hardware address
    _: [64 + 128]u8 = @splat(0),

    fn decode(bytes: []const u8) !Boot {
        return try net.decodeAny(Boot, bytes, 0);
    }

    fn write(self: Boot, w: *std.Io.Writer) !void {
        try net.writeAny(w, self);
    }
};

pub fn init(mac: Mac) Dhcp {
    return .{ .args = .{ .mac = mac } };
}

pub fn tx(self: *Dhcp, tx_bytes: []u8, now: u32) !usize {
    again: switch (self.state) {
        .initial, .offer => |current| {
            if (self.transaction_id == 0) {
                self.transaction_id = now;
            }
            const n = try self.encode(tx_bytes);
            self.setState(if (current == .initial) .discover else .request, now);
            return n;
        },
        // TODO timeout (1000ms) should be randomized and exponentially increasing
        // rfc: https://datatracker.ietf.org/doc/html/rfc2131 page 23 (randomized exponential backoff algorithm)
        .discover, .request => if (now -% self.ts >= 1000) {
            self.setState(.initial, now);
            break :again;
        },
        .bound => if ((now -% self.ts) / 1000 >= self.args.lease_time) {
            self.setState(.offer, now);
            break :again;
        },
    }
    return 0;
}

fn setState(self: *Dhcp, new_state: State, now: u32) void {
    if (self.state == new_state) return;
    if (self.state == .bound or new_state == .initial) {
        self.transaction_id = now;
    }
    self.state = new_state;
    self.ts = now;
    log.debug("dhcp state {s:<8} => {s:<8} ts: {}", .{ @tagName(self.state), @tagName(new_state), now });
}

fn encode(self: *Dhcp, buffer: []u8) !usize {
    var w = std.Io.Writer.fixed(buffer);

    // boot header
    var boot: Boot = .{ .xid = self.transaction_id };
    @memcpy(boot.chaddr[0..6], &self.args.mac);
    try boot.write(&w);

    // dhcp options
    try w.writeAll(&magic_cookie);
    { // message type
        try w.writeByte(@intFromEnum(Options.message_type));
        try w.writeByte(1);
        try w.writeByte(@intFromEnum(if (self.state == .offer) MessageType.request else MessageType.discover));
    }
    if (self.state == .offer) {
        try w.writeByte(@intFromEnum(Options.dhcp_server));
        try w.writeByte(4);
        try w.writeAll(&self.args.dhcp_server);

        try w.writeByte(@intFromEnum(Options.requested_ip));
        try w.writeByte(4);
        try w.writeAll(&self.args.addr);
    }
    { // max message size 1500
        try w.writeByte(@intFromEnum(Options.max_dhcp_message_size));
        try w.writeByte(2);
        try w.writeInt(u16, 1500, .big);
    }
    { // parameter request list
        try w.writeByte(@intFromEnum(Options.parameter_request_list));
        try w.writeByte(4);
        try w.writeByte(@intFromEnum(Options.subnet_mask));
        try w.writeByte(@intFromEnum(Options.gateway));
        try w.writeByte(@intFromEnum(Options.broadcast_addr));
        try w.writeByte(@intFromEnum(Options.dns_server));
    }
    try w.writeByte(@intFromEnum(Options.end));

    return w.end;
}

pub fn rx(self: *Dhcp, rx_bytes: []const u8, now: u32) !void {
    var bytes: []const u8 = rx_bytes;

    // parse boot
    const boot = try Dhcp.Boot.decode(bytes);
    bytes = bytes[@sizeOf(Boot)..];
    if (boot.op != 2 or !mem.eql(u8, boot.chaddr[0..self.args.mac.len], &self.args.mac)) {
        return; // not response or not for me
    }
    if (boot.xid != self.transaction_id) {
        log.debug("dhcp wrong transaction id {} expected {}", .{ boot.xid, self.transaction_id });
        return;
    }
    if (bytes.len < 4 and !mem.eql(u8, bytes[0..4], &magic_cookie)) {
        return; // invalid
    }
    bytes = bytes[4..];

    // parse options
    var args: Args = .{ .addr = boot.yiaddr, .mac = self.args.mac };
    var message_type: ?MessageType = null;
    var r = std.Io.Reader.fixed(bytes);
    while (r.seek < r.end) {
        const option = try r.takeEnum(Options, .little);
        if (option == .pad) continue;
        if (option == .end) break;
        const val = try r.take(try r.takeByte());
        switch (option) {
            .message_type => {
                if (val.len != 1) return error.InsufficientBuffer;
                message_type = @enumFromInt(val[0]);
            },
            .subnet_mask => args.subnet_mask = try asAddr(val),
            .broadcast_addr => args.broadcast_addr = try asAddr(val),
            .gateway => args.gateway = try asAddr(val),
            .dns_server => args.dns_server = try asAddr(val),
            .dhcp_server => args.dhcp_server = try asAddr(val),
            .lease_time => args.lease_time = try asInt(u32, val),
            .renewal_time => args.renewal_time = try asInt(u32, val),
            .rebinding_time => args.rebinding_time = try asInt(u32, val),
            .mtu => args.mtu = try asInt(u16, val),
            else => {
                log.debug("unhandled dhcp option {} {x}\n", .{ option, val });
            },
        }
    }
    if (message_type == null) return;

    // ref: https://datatracker.ietf.org/doc/html/rfc2131#autoid-12
    // for states illustrated:251
    switch (self.state) {
        else => {},
        .discover => {
            if (message_type.? == .offer) {
                self.args = args;
                self.setState(.offer, now);
            }
        },
        .request => {
            if (message_type.? == .ack) {
                self.args = args;
                self.setState(.bound, now);
            }
            if (message_type.? == .nak) {
                self.setState(.initial, now);
            }
        },
    }
}

const magic_cookie: [4]u8 = .{ 0x63, 0x82, 0x53, 0x63 };

// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
const Options = enum(u8) {
    pad = 0,

    subnet_mask = 1,
    gateway = 3,
    dns_server = 6,
    domain_name = 15,
    mtu = 26,
    broadcast_addr = 28,
    requested_ip = 50,
    lease_time = 51,
    message_type = 53,
    dhcp_server = 54,

    client_id = 61, // my mac

    // in dhcp discover, request
    parameter_request_list = 55,
    max_dhcp_message_size = 57,
    renewal_time = 58,
    rebinding_time = 59,

    end = 0xff,
    _,
};

// ref: https://datatracker.ietf.org/doc/html/rfc2132#section-9.6
const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,
};

fn asAddr(bytes: []const u8) !Addr {
    if (bytes.len < 4) return error.InsufficientBuffer;
    return bytes[0..4].*;
}

fn asInt(T: type, bytes: []const u8) !T {
    const l = @divExact(@typeInfo(T).int.bits, 8);
    if (bytes.len < l) return error.InsufficientBuffer;
    return mem.readInt(T, bytes[0..l], .big);
}

test "parse dhcp offer" {
    const bytes: []const u8 = &hexToBytes("02010600000000000000800000000000c0a8cfaac0a8cf01000000002ccf67f3b7ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a8cf01330400000e103a04000007083b0400000c4e0104ffffff001c04c0a8cfff1a0205dc0304c0a8cf010604c0a8cf01ff00000000");

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .discover;

    try dhcp.rx(bytes, 0);
    try testing.expectEqual(.offer, dhcp.state);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 170 }, &dhcp.args.addr);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &dhcp.args.subnet_mask);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 255 }, &dhcp.args.broadcast_addr);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.args.dhcp_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.args.dns_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.args.gateway);
    try testing.expectEqual(3600, dhcp.args.lease_time);
    try testing.expectEqual(1800, dhcp.args.renewal_time);
    try testing.expectEqual(3150, dhcp.args.rebinding_time);
    try testing.expectEqual(1500, dhcp.args.mtu);
}

test "create dhcp request" {
    const expected: []const u8 = &hexToBytes(
        \\ 01 01 06 00 0a 0b 0c 0d 00 00 80 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 2c cf 67 f3
        \\ b7 ea 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 63 82 53 63
        \\ 35 01 03 36 04 c0 a8 be 01 32 04 c0 a8 be ce 39
        \\ 02 05 dc 37 04 01 03 1c 06 ff
    );

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .offer;
    dhcp.args.addr = .{ 192, 168, 190, 206 };
    dhcp.args.dhcp_server = .{ 192, 168, 190, 1 };
    dhcp.transaction_id = 0x0a0b0c0d;

    var buffer: [512]u8 = undefined;
    const n = try dhcp.encode(&buffer);
    try testing.expectEqualSlices(u8, expected, buffer[0..n]);
}

test "parse dhcp ack" {
    const bytes: []const u8 = &hexToBytes(
        \\ 02 01 06 00 00 00 10 de 00 00 80 00 00 00 00 00
        \\ c0 a8 be ce c0 a8 be 01 00 00 00 00 2c cf 67 f3
        \\ b7 ea 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 63 82 53 63
        \\ 35 01 05 36 04 c0 a8 be 01 33 04 00 00 a8 c0 3a
        \\ 04 00 00 54 60 3b 04 00 00 93 a8 01 04 ff ff ff
        \\ 00 1c 04 c0 a8 be ff 1a 02 05 dc 03 04 c0 a8 be
        \\ 01 06 04 c0 a8 be 01 ff 00 00 00 00
    );

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .request;
    dhcp.transaction_id = 0x10de;

    try dhcp.rx(bytes, 0);
    try testing.expectEqual(.bound, dhcp.state);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 206 }, &dhcp.args.addr);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &dhcp.args.subnet_mask);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 255 }, &dhcp.args.broadcast_addr);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.args.dhcp_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.args.dns_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.args.gateway);
    try testing.expectEqual(43200, dhcp.args.lease_time);
    try testing.expectEqual(21600, dhcp.args.renewal_time);
    try testing.expectEqual(37800, dhcp.args.rebinding_time);
    try testing.expectEqual(1500, dhcp.args.mtu);
}
