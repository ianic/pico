const std = @import("std");
const mem = std.mem;
const log = std.log.scoped(.dhcp);
const testing = std.testing;

const hexToBytes = @import("testu.zig").hexToBytes;
const protocol = @import("protocol.zig");
const Mac = protocol.Mac;
const Addr = protocol.Addr;
const Timer = @import("root.zig").Timer;

const Dhcp = @This();

const response_wait_ms = 1000;

state: State = .initial,
transaction_id: u32 = 0,

ipc: protocol.IpConfig,
opt: Options = .{},
timer: Timer = .{},
// TODO timeout (1000ms) should be randomized and exponentially increasing
// rfc: https://datatracker.ietf.org/doc/html/rfc2131 page 23 (randomized exponential backoff algorithm)

const Options = struct {
    // intervals are in seconds
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
        return try protocol.decodeAny(Boot, bytes, 0);
    }

    fn write(self: Boot, w: *std.Io.Writer) !void {
        try protocol.writeAny(w, self);
    }
};

pub fn init(mac: Mac) Dhcp {
    return .{ .ipc = .{ .mac = mac } };
}

pub fn tx(self: *Dhcp, tx_bytes: []u8, now: u32) !usize {
    sw: switch (self.state) {
        .initial, .offer => |current| {
            if (self.transaction_id == 0) {
                self.transaction_id = now;
            }
            self.setState(current); // needed for encode
            const n = try self.encode(tx_bytes);
            self.setState(if (current == .initial) .discover else .request);
            self.timer = .{ .start = now, .duration = response_wait_ms };
            return n;
        },
        .discover, .request => if (self.timer.expired(now)) {
            continue :sw .initial;
        },
        .bound => if (self.timer.expired(now)) {
            self.transaction_id = now;
            continue :sw .offer;
        },
    }
    return 0;
}

fn setState(self: *Dhcp, new_state: State) void {
    if (self.state == new_state) return;
    log.debug("dhcp state {s:<8} => {s:<8} transaction_id: {}", .{ @tagName(self.state), @tagName(new_state), self.transaction_id });
    self.state = new_state;
}

fn encode(self: *Dhcp, buffer: []u8) !usize {
    var w = std.Io.Writer.fixed(buffer);

    // boot header
    var boot: Boot = .{ .xid = self.transaction_id };
    @memcpy(boot.chaddr[0..6], &self.ipc.mac);
    try boot.write(&w);

    // dhcp options
    try w.writeAll(&magic_cookie);
    { // message type
        try w.writeByte(@intFromEnum(Option.message_type));
        try w.writeByte(1);
        try w.writeByte(@intFromEnum(if (self.state == .offer) MessageType.request else MessageType.discover));
    }
    if (self.state == .offer) {
        try w.writeByte(@intFromEnum(Option.dhcp_server));
        try w.writeByte(4);
        try w.writeAll(&self.ipc.dhcp_server);

        try w.writeByte(@intFromEnum(Option.requested_ip));
        try w.writeByte(4);
        try w.writeAll(&self.ipc.addr);
    }
    { // max message size
        try w.writeByte(@intFromEnum(Option.max_dhcp_message_size));
        try w.writeByte(2);
        try w.writeInt(u16, 1472, .big);
    }
    { // parameter request list
        try w.writeByte(@intFromEnum(Option.parameter_request_list));
        try w.writeByte(4);
        try w.writeByte(@intFromEnum(Option.subnet_mask));
        try w.writeByte(@intFromEnum(Option.gateway));
        try w.writeByte(@intFromEnum(Option.broadcast_addr));
        try w.writeByte(@intFromEnum(Option.dns_server));
    }
    try w.writeByte(@intFromEnum(Option.end));

    return w.end;
}

pub fn rx(self: *Dhcp, rx_bytes: []const u8, now: u32) !void {
    var bytes: []const u8 = rx_bytes;

    // parse boot
    const boot = try Dhcp.Boot.decode(bytes);
    bytes = bytes[@sizeOf(Boot)..];
    if (boot.op != 2 or !mem.eql(u8, boot.chaddr[0..self.ipc.mac.len], &self.ipc.mac)) {
        log.debug("invalid boot op: {} chaddr: {x}", .{ boot.op, boot.chaddr });
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
    var ipc: protocol.IpConfig = .{ .addr = boot.yiaddr, .mac = self.ipc.mac };
    var opt: Options = .{};
    var message_type: ?MessageType = null;

    var r = std.Io.Reader.fixed(bytes);
    while (r.seek < r.end) {
        const option = try r.takeEnum(Option, .little);
        if (option == .pad) continue;
        if (option == .end) break;
        const val = try r.take(try r.takeByte());
        switch (option) {
            .message_type => {
                if (val.len != 1) return error.InsufficientBuffer;
                message_type = @enumFromInt(val[0]);
            },
            .subnet_mask => ipc.subnet_mask = try asAddr(val),
            .broadcast_addr => ipc.broadcast_addr = try asAddr(val),
            .gateway => ipc.gateway = try asAddr(val),
            .dns_server => ipc.dns_server = try asAddr(val),
            .dhcp_server => ipc.dhcp_server = try asAddr(val),
            .lease_time => opt.lease_time = try asInt(u32, val),
            .renewal_time => opt.renewal_time = try asInt(u32, val),
            .rebinding_time => opt.rebinding_time = try asInt(u32, val),
            .mtu => opt.mtu = try asInt(u16, val),
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
                self.ipc = ipc;
                self.opt = opt;
                self.setState(.offer);
            }
        },
        .request => {
            if (message_type.? == .ack) {
                self.ipc = ipc;
                self.opt = opt;
                self.setState(.bound);
                self.timer = .{ .start = now, .duration = self.opt.lease_time * 1000 };
            }
            if (message_type.? == .nak) {
                self.setState(.initial);
                self.timer = .{};
            }
        },
    }
}

const magic_cookie: [4]u8 = .{ 0x63, 0x82, 0x53, 0x63 };

// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
const Option = enum(u8) {
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
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 170 }, &dhcp.ipc.addr);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &dhcp.ipc.subnet_mask);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 255 }, &dhcp.ipc.broadcast_addr);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.ipc.dhcp_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.ipc.dns_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 207, 1 }, &dhcp.ipc.gateway);
    try testing.expectEqual(3600, dhcp.opt.lease_time);
    try testing.expectEqual(1800, dhcp.opt.renewal_time);
    try testing.expectEqual(3150, dhcp.opt.rebinding_time);
    try testing.expectEqual(1500, dhcp.opt.mtu);
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
        \\ 02 05 c0 37 04 01 03 1c 06 ff
    );

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .offer;
    dhcp.ipc.addr = .{ 192, 168, 190, 206 };
    dhcp.ipc.dhcp_server = .{ 192, 168, 190, 1 };
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
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 206 }, &dhcp.ipc.addr);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &dhcp.ipc.subnet_mask);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 255 }, &dhcp.ipc.broadcast_addr);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.ipc.dhcp_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.ipc.dns_server);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 190, 1 }, &dhcp.ipc.gateway);
    try testing.expectEqual(43200, dhcp.opt.lease_time);
    try testing.expectEqual(21600, dhcp.opt.renewal_time);
    try testing.expectEqual(37800, dhcp.opt.rebinding_time);
    try testing.expectEqual(1500, dhcp.opt.mtu);
}
