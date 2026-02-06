const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const Link = @import("link");

const log = std.log.scoped(.net);

const broadcast_mac: Mac = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const broadcast_ip: IpAddr = .{ 0xff, 0xff, 0xff, 0xff };

const arp_table_len = 8;
const tx_link_header = 22;

pub const Net = struct {
    const Self = @This();

    identification: u16 = 0,
    driver: Link,
    tx_buffer: []u8,
    rx_buffer: []u8,
    arp_table: ArpTable(arp_table_len) = .{},
    dhcp: Dhcp,
    link_state: Link.RecvResponse.LinkState = .down,

    fn ip_identification(self: *Self) u16 {
        self.identification +%= 1;
        return self.identification;
    }

    pub fn poll(self: *Self, now: u32) !u32 {
        while (true) {
            const rsp = try self.driver.vtable.recv(self.driver.ptr, self.rx_buffer);
            if (rsp.len > 0) {
                try self.handle(self.rx_buffer[rsp.head..][0..rsp.len], now);
            }
            if (rsp.link_state != self.link_state) {
                self.link_state = rsp.link_state;
            }
            if (rsp.next_packet_available) |npa| if (!npa) break;
        }
        if (self.link_state == .up) {
            try self.dhcp_tick(now);
        }
        return if (self.dhcp.state == .bound) 60_000 else 1_000;
    }

    fn dhcp_tick(self: *Self, now: u32) !void {
        again: switch (self.dhcp.state) {
            .initial, .offer => |current| {
                if (self.dhcp.state == .initial) {
                    self.dhcp.transaction_id = now;
                }
                const n = try self.dhcp.encode(self.eth_tx_buffer());
                try self.send(n);
                self.dhcp.set_state(if (current == .initial) .discover else .request, now);
            },
            // TODO timeout (1000ms) should be randomized and exponentially increasing
            // rfc: https://datatracker.ietf.org/doc/html/rfc2131 page 23 (randomized exponential backoff algorithm)
            .discover, .request => if (now -% self.dhcp.ts >= 1000) {
                self.dhcp.set_state(.initial, now);
                break :again;
            },
            .bound => if ((now -% self.dhcp.ts) / 1000 >= self.dhcp.args.lease_time) {
                self.dhcp.set_state(.offer, now);
                break :again;
            },
        }
    }

    fn eth_tx_buffer(self: *Self) []u8 {
        return self.tx_buffer[tx_link_header..];
    }

    fn send(self: *Self, pos: usize) Link.Error!void {
        try self.driver.vtable.send(
            self.driver.ptr,
            self.tx_buffer[0 .. tx_link_header + pos],
        );
    }

    pub fn send_arp_request(self: *Self, ip: IpAddr) !void {
        var eth_rsp: Ethernet = .{
            .destination = broadcast_mac,
            .source = self.mac,
            .protocol = .arp,
        };
        var arp_rsp: Arp = .{
            .opcode = .request,
            .sender_mac = self.mac,
            .sender_ip = self.ip,
            .target_mac = broadcast_mac,
            .target_ip = ip,
        };
        var buf = self.eth_tx_buffer();
        var pos = try eth_rsp.encode(buf);
        pos += try arp_rsp.encode(buf[pos..]);
        try self.send(pos);
    }

    fn handle(self: *Self, rx_bytes: []const u8, now: u32) !void {
        var bytes: []const u8 = rx_bytes;
        const eth = try Ethernet.decode(bytes);
        bytes = bytes[@sizeOf(Ethernet)..];

        const addr = self.dhcp.args.addr;
        const mac = self.dhcp.args.mac;

        if (eth.protocol == .arp) {
            const arp = try Arp.decode(bytes);
            bytes = bytes[@sizeOf(Arp)..];

            if (arp.opcode == .request and mem.eql(u8, &arp.target_ip, &addr)) {
                log.debug(
                    "arp request from ip: {any} mac: {x}",
                    .{ arp.sender_ip[0..4], arp.sender_mac[0..6] },
                );
                var eth_rsp: Ethernet = .{
                    .destination = arp.sender_mac,
                    .source = mac,
                    .protocol = .arp,
                };
                var arp_rsp: Arp = .{
                    .opcode = .response,
                    .sender_mac = mac,
                    .sender_ip = addr,
                    .target_mac = arp.sender_mac,
                    .target_ip = arp.sender_ip,
                };
                const buf = self.eth_tx_buffer();
                var pos = try eth_rsp.encode(buf);
                pos += try arp_rsp.encode(buf[pos..]);
                try self.send(pos);
                return;
            }

            if (arp.opcode == .response) {
                self.arp_table.push(arp.sender_ip, arp.sender_mac);
                log.debug(
                    "arp response from ip: {any} mac: {x} arp: {}",
                    .{ arp.sender_ip[0..4], arp.sender_mac[0..6], arp },
                );
            }
        }
        if (eth.protocol == .ip) {
            const ip = try Ip.decode(bytes);
            if (bytes.len < ip.total_length) return error.InsufficientBuffer;
            if (ip.fragment.mf or ip.fragment.offset > 0)
                return error.IpFragmented;

            bytes = bytes[0..ip.total_length][@sizeOf(Ip)..];
            if (ip.protocol == .icmp and mem.eql(u8, &ip.destination, &addr)) {
                const icmp = try Icmp.decode(bytes);
                const data = bytes[@sizeOf(Icmp)..];
                if (icmp.typ == .request) {
                    // log.debug(
                    //     "ping request from ip: {any}, mac: {x}, data.len {}",
                    //     .{ ip.source[0..4], eth.source[0..6], data.len },
                    // );
                    var eth_rsp: Ethernet = .{
                        .destination = eth.source,
                        .source = mac,
                        .protocol = .ip,
                    };
                    var ip_rsp: Ip = .{
                        .service = ip.service,
                        .identification = ip.identification,
                        .protocol = .icmp,
                        .source = ip.destination,
                        .destination = ip.source,
                        .total_length = ip.total_length,
                    };
                    var icmp_rsp: Icmp = .{
                        .typ = .reply,
                        .identifier = icmp.identifier,
                        .sequence = icmp.sequence,
                    };
                    var buf = self.eth_tx_buffer();
                    var pos = try eth_rsp.encode(buf);
                    pos += try ip_rsp.encode(buf[pos..]);
                    pos += try icmp_rsp.encode(buf[pos..], data);
                    @memcpy(buf[pos..][0..data.len], data);
                    pos += data.len;
                    try self.send(pos);
                    return;
                }
            }
            if (ip.protocol == .udp) {
                const udp = try UdpHeader.decode(bytes);
                if (bytes.len < udp.length) return error.InsufficientBuffer;
                bytes = bytes[@sizeOf(UdpHeader)..udp.length];

                // dhcp response
                if (udp.source_port == @intFromEnum(Ports.dhcp_server) and
                    udp.destination_port == @intFromEnum(Ports.dhcp_client))
                {
                    try self.dhcp.handle(bytes, now);
                    try self.dhcp_tick(now);
                }
            }
        }
    }

    pub fn send_dhcp_discover(self: *Self) !void {
        if (self.dhcp.state == .initial) {
            const n = try self.dhcp.encode(self.eth_tx_buffer());
            try self.send(n);
        }
    }
};

pub const Udp = struct {
    const Self = @This();
    ip_identification: u16,
    source: struct {
        ip: IpAddr,
        mac: Mac,
        port: u16,
    },
    destination: struct {
        ip: IpAddr,
        mac: Mac,
        port: u16,
    },

    const header_len = @sizeOf(Ethernet) + @sizeOf(Ip) + @sizeOf(UdpHeader);

    // /// Buffer for the udp payload. Preserving space for the udp header at the
    // /// start of the net.tx_buffer. If this is used for the payload then there
    // /// is no need for memcpy in send.
    // pub fn tx_buffer(self: *Self) []u8 {
    //     return self.net.eth_tx_buffer()[header_len..];
    // }

    // pub fn send(self: *Self, payload: []const u8) !void {
    //     try self.net.send(self.net.eth_tx_buffer(), self.encode(payload));
    // }

    fn encode(self: *Self, buffer: []u8, payload: []const u8) !usize {
        var eth: Ethernet = .{
            .source = self.source.mac,
            .destination = self.destination.mac,
            .protocol = .ip,
        };
        var ip: Ip = .{
            .identification = self.ip_identification,
            .protocol = .udp,
            .source = self.source.ip,
            .destination = self.destination.ip,
            .total_length = @intCast(@sizeOf(Ip) + @sizeOf(UdpHeader) + payload.len),
        };
        var udp: UdpHeader = .{
            .source_port = self.source.port,
            .destination_port = self.destination.port,
            .length = @intCast(@sizeOf(UdpHeader) + payload.len),
            .checksum = 0,
        };
        var pos = try eth.encode(buffer[0..]);
        pos += try ip.encode(buffer[pos..]);
        pos += try udp.encode(buffer[pos..], &ip, payload);
        assert(pos == header_len);
        if (&buffer[header_len] != &payload[0]) {
            @memcpy(buffer[header_len..][0..payload.len], payload);
        }
        return header_len + payload.len;
    }
};

const Mac = [6]u8;
const IpAddr = [4]u8;

pub const Ethernet = extern struct {
    const Self = @This();

    const Protocol = enum(u16) {
        arp = 0x0806,
        ip = 0x0800,
        _,
    };

    destination: Mac,
    source: Mac,
    protocol: Protocol,

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, 0);
    }

    pub fn encode(self: Self, bytes: []u8) !usize {
        return try encodeAny(self, bytes);
    }
};

pub const Arp = extern struct {
    const Self = @This();

    const Hardware = enum(u16) {
        ethernet = 0x0001,
        _,
    };

    const Protocol = enum(u16) {
        ipv4 = 0x0800,
        _,
    };

    const Opcode = enum(u16) {
        unknown = 0,
        request = 0x0001,
        response = 0x0002,
        rarp_request = 0x0003,
        rarp_response = 0x0004,
        _,
    };

    hardware: Hardware = .ethernet,
    protocol: Protocol = .ipv4,
    hardware_size: u8 = 6,
    protocol_size: u8 = 4,
    opcode: Opcode,
    sender_mac: Mac,
    sender_ip: IpAddr,
    target_mac: Mac,
    target_ip: IpAddr,

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, 0);
    }

    pub fn encode(self: Self, bytes: []u8) !usize {
        return try encodeAny(self, bytes);
    }
};

pub const Ip = extern struct {
    const Self = @This();

    const Protocol = enum(u8) {
        icmp = 0x01,
        igmp = 0x02,
        tcp = 0x06,
        udp = 0x11,
        _,
    };
    // fields reference: tcp/ip illustrated, page 183

    header: packed struct {
        length: u4 = 5, // number of 4 byte words in this header
        version: u4 = 4, // 4 for ip v4
    } = .{},
    service: packed struct { // used for special processing when it is forwarded
        ecn: u2 = 0, // explicit congestion notification
        ds: u6 = 0, // differentiated services field
    } = .{},
    total_length: u16, // this header and payload length
    identification: u16, // all fragments have same identification
    fragment: packed struct {
        offset: u13 = 0,
        mf: bool = false, // more fragment follows (this is not the last fragment)
        df: bool = true, // don't fragment, this is the only/last fragment
        _: u1 = 0,
    } = .{},
    ttl: u8 = 64, // time to live
    protocol: Protocol, // type of data found in payload
    checksum: u16 = 0, // checksum of the this header only
    source: IpAddr, // source ip address
    destination: IpAddr, // destintaion ip address

    pub fn decode(bytes: []const u8) !Self {
        const header_length: u8 = (bytes[0] & 0x0f) * 4;
        if (bytes.len < header_length) return error.InsufficientBuffer;
        return try decodeAny(Self, bytes[0..header_length], header_length);
    }

    pub fn encode(self: *Self, bytes: []u8) !usize {
        self.checksum = 0;
        const n = try encodeAny(self.*, bytes);
        set_checksum(Self, "", bytes[0..n], "");
        return n;
    }

    pub fn payload_length(self: Self) u16 {
        return self.total_length - @as(u16, self.header.length) * 4;
    }

    pub fn options_length(self: Self) u16 {
        return @as(u16, self.header.length) * 4 - @sizeOf(Ip);
    }
};

pub const Icmp = extern struct {
    const Self = @This();

    const Type = enum(u8) {
        reply = 0,
        request = 8,
        unreahable = 3,
        _,
    };

    typ: Type,
    code: u8 = 0,
    checksum: u16 = 0,
    identifier: u16,
    sequence: u16,

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, bytes.len);
    }

    pub fn encode(self: *Self, bytes: []u8, payload: []const u8) !usize {
        self.checksum = 0;
        const n = try encodeAny(self.*, bytes);
        set_checksum(Self, "", bytes[0..n], payload);
        return n;
    }
};

pub const UdpHeader = extern struct {
    const Self = @This();

    source_port: u16,
    destination_port: u16,
    length: u16, // udp header and payload in bytes
    checksum: u16 = 0,

    const PseudoHeader = extern struct {
        source: IpAddr,
        destination: IpAddr,
        _: u8 = 0,
        protocol: Ip.Protocol,
        length: u16,
    };

    pub fn encode(self: *Self, bytes: []u8, ip: *Ip, payload: []const u8) !usize {
        self.checksum = 0;
        var pseudo_header: PseudoHeader = .{
            .source = ip.source,
            .destination = ip.destination,
            .protocol = .udp,
            .length = self.length,
        };
        if (native_endian == .little) {
            std.mem.byteSwapAllFields(PseudoHeader, &pseudo_header);
        }
        const n = try encodeAny(self.*, bytes);
        set_checksum(Self, mem.asBytes(&pseudo_header), bytes[0..n], payload);
        return n;
    }

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, 0);
    }
};

fn ArpTable(len: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            ip: IpAddr = @splat(0),
            mac: Mac = @splat(0),
        };

        entries: [len]Entry = @splat(.{}),
        next: usize = 0,

        fn push(self: *Self, ip: IpAddr, mac: Mac) void {
            self.entries[self.next] = .{ .ip = ip, .mac = mac };
            self.next = (self.next + 1) % len;
        }

        fn pop(self: Self, ip: IpAddr) ?Entry {
            const i: u32 = @bitCast(ip);
            for (self.entries) |entry| {
                const e: u32 = @bitCast(entry.ip);
                if (e == 0) return null;
                if (e == i) return entry;
            }
            return null;
        }
    };
}

comptime {
    assert(@sizeOf(Ethernet) == 14);
    assert(@sizeOf(Arp) == 28);
    assert(@sizeOf(Ip) == 20);
    assert(@sizeOf(Icmp) == 8);
    assert(@sizeOf(UdpHeader) == 8);
}

// c_len number of bytes for checksum calculation
fn decodeAny(T: type, bytes: []const u8, c_len: usize) !T {
    if (c_len > 0) {
        if (0xffff ^ checksum(0, bytes[0..c_len]) != 0) return error.Checksum;
    }
    if (bytes.len < @sizeOf(T)) return error.InsufficientBuffer;

    var t: T = @bitCast(bytes[0..@sizeOf(T)].*);
    if (native_endian == .little) {
        std.mem.byteSwapAllFields(T, &t);
    }
    return t;
}

fn set_checksum(T: type, pseudo_header: []const u8, header: []u8, payload: []const u8) void {
    var sum: u16 = 0;
    if (pseudo_header.len > 0) {
        sum = checksum(sum, pseudo_header);
    }
    sum = checksum(sum, header);
    if (payload.len > 0) {
        sum = checksum(sum, payload);
    }
    mem.writeInt(u16, header[@offsetOf(T, "checksum")..][0..2], 0xffff ^ sum, .little);
}

fn checksum(prev: u16, bytes: []const u8) u16 {
    const round_len = (bytes.len & ~@as(usize, 0x01));
    const slice = mem.bytesAsSlice(u16, bytes[0..round_len]);

    var sum: u16 = prev;
    var last: u16 = prev;
    for (slice) |v| {
        sum +%= v;
        if (sum < last) sum +%= 1;
        last = sum;
    }
    if (bytes.len & 1 > 0)
        sum += bytes[bytes.len - 1];
    if (sum < last) sum +%= 1;
    return sum;
}

pub fn encodeAny(t: anytype, bytes: []u8) !usize {
    const T = @TypeOf(t);
    if (bytes.len < @sizeOf(T)) return error.InsufficientBuffer;
    var mt: T = t; // muttable copy of the t
    if (native_endian == .little) {
        std.mem.byteSwapAllFields(T, &mt);
    }
    @memcpy(bytes[0..@sizeOf(T)], mem.asBytes(&mt));
    return @sizeOf(T);
}

test "arp request" {
    const data = hexToBytes("5847ca75fdbc1ae829c3ec78080600010800060400011ae829c3ec78c0a8be01000000000000c0a8beeb000000000000000000000000000000000000");

    const eth = try Ethernet.decode(&data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x58, 0x47, 0xca, 0x75, 0xfd, 0xbc }, &eth.destination);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1a, 0xe8, 0x29, 0xc3, 0xec, 0x78 }, &eth.source);
    try testing.expectEqual(.arp, eth.protocol);

    const arp = try Arp.decode(data[@sizeOf(Ethernet)..]);
    try testing.expectEqual(.ethernet, arp.hardware);
    try testing.expectEqual(.ipv4, arp.protocol);
    try testing.expectEqual(6, arp.hardware_size);
    try testing.expectEqual(4, arp.protocol_size);

    try testing.expectEqual(.request, arp.opcode);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1a, 0xe8, 0x29, 0xc3, 0xec, 0x78 }, &arp.sender_mac);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, &arp.target_mac);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 1 }, &arp.sender_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 235 }, &arp.target_ip);
    {
        const local_mac = .{ 0x58, 0x47, 0xca, 0x75, 0xfd, 0xbc };
        const local_ip: IpAddr = .{ 192, 168, 190, 235 };
        var eth_rsp: Ethernet = .{
            .destination = arp.sender_mac,
            .source = local_mac,
            .protocol = .arp,
        };
        var arp_rsp: Arp = .{
            .opcode = .response,
            .sender_mac = local_mac,
            .sender_ip = local_ip,
            .target_mac = arp.sender_mac,
            .target_ip = arp.sender_ip,
        };

        var buffer: [128]u8 = undefined;
        var pos: usize = try eth_rsp.encode(&buffer);
        pos += try arp_rsp.encode(buffer[pos..]);
        const rsp = buffer[0..pos];

        const expected = hexToBytes("1ae829c3ec785847ca75fdbc080600010800060400025847ca75fdbcc0a8beeb1ae829c3ec78c0a8be01");
        try testing.expectEqualSlices(u8, &expected, rsp);
    }
}

test "decode arp reponse" {
    const data = hexToBytes("1ae829c3ec785847ca75fdbc080600010800060400025847ca75fdbcc0a8beeb1ae829c3ec78c0a8be01");
    const eth = try Ethernet.decode(&data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1a, 0xe8, 0x29, 0xc3, 0xec, 0x78 }, &eth.destination);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x58, 0x47, 0xca, 0x75, 0xfd, 0xbc }, &eth.source);
    try testing.expectEqual(.arp, eth.protocol);

    const arp = try Arp.decode(data[@sizeOf(Ethernet)..]);
    try testing.expectEqual(.ethernet, arp.hardware);
    try testing.expectEqual(.ipv4, arp.protocol);
    try testing.expectEqual(6, arp.hardware_size);
    try testing.expectEqual(4, arp.protocol_size);

    try testing.expectEqual(.response, arp.opcode);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x58, 0x47, 0xca, 0x75, 0xfd, 0xbc }, &arp.sender_mac);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1a, 0xe8, 0x29, 0xc3, 0xec, 0x78 }, &arp.target_mac);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 235 }, &arp.sender_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 1 }, &arp.target_ip);
}

test "ip decode/encode" {
    const net_bytes = hexToBytes("45000054b055400040018bbcc0a8beebc0a8be5a");
    var ip = try Ip.decode(&net_bytes);
    try testing.expectEqual(4, ip.header.version);
    try testing.expectEqual(5, ip.header.length);
    try testing.expectEqual(84, ip.total_length);
    try testing.expectEqual(0xb055, ip.identification);
    try testing.expect(ip.fragment.df);
    try testing.expectEqual(64, ip.ttl);
    try testing.expectEqual(.icmp, ip.protocol);
    try testing.expectEqual(0x8bbc, ip.checksum);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 235 }, &ip.source);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 90 }, &ip.destination);

    // test checksum calculation
    var bytes: [net_bytes.len]u8 = @splat(0);
    const pos = try ip.encode(&bytes);
    try testing.expectEqualSlices(u8, &net_bytes, bytes[0..pos]);
}

test "icmp decode" {
    const bytes = hexToBytes("0800eb870007002f0bf02569000000001c16000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    const icmp = try Icmp.decode(&bytes);

    try testing.expectEqual(.request, icmp.typ);
    try testing.expectEqual(0, icmp.code);
    try testing.expectEqual(0xeb87, icmp.checksum);
    try testing.expectEqual(47, icmp.sequence);
    try testing.expectEqual(7, icmp.identifier);

    const data = bytes[@sizeOf(Icmp)..];
    try testing.expectEqual(56, data.len);
}

test "decode whole icmp packet" {
    const net_bytes = hexToBytes("2ccf67f3b7ea5847ca75fdbc080045000054b055400040018bbcc0a8beebc0a8be5a0800eb870007002f0bf02569000000001c16000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    var bytes: []const u8 = &net_bytes;

    // ethernet
    var eth = try Ethernet.decode(bytes);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x58, 0x47, 0xca, 0x75, 0xfd, 0xbc }, &eth.source);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea }, &eth.destination);
    try testing.expectEqual(.ip, eth.protocol);

    // ip
    bytes = bytes[@sizeOf(Ethernet)..];
    var ip = try Ip.decode(bytes);
    try testing.expectEqual(4, ip.header.version);
    try testing.expectEqual(5, ip.header.length);
    try testing.expectEqual(84, ip.total_length);
    try testing.expectEqual(0xb055, ip.identification);
    try testing.expect(ip.fragment.df);
    try testing.expectEqual(64, ip.ttl);
    try testing.expectEqual(.icmp, ip.protocol);
    try testing.expectEqual(0x8bbc, ip.checksum);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 235 }, &ip.source);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 190, 90 }, &ip.destination);

    // icmp
    try testing.expectEqual(bytes.len, ip.total_length);
    bytes = bytes[0..ip.total_length][@sizeOf(Ip)..];
    var icmp = try Icmp.decode(bytes);
    try testing.expectEqual(.request, icmp.typ);
    try testing.expectEqual(0, icmp.code);
    try testing.expectEqual(0xeb87, icmp.checksum);
    try testing.expectEqual(47, icmp.sequence);
    try testing.expectEqual(7, icmp.identifier);

    // data
    const data = bytes[@sizeOf(Icmp)..];
    try testing.expectEqual(56, data.len);

    var buffer: [128]u8 = undefined;
    var pos = try eth.encode(&buffer);
    pos += try ip.encode(buffer[pos..]);
    pos += try icmp.encode(buffer[pos..], data);
    @memcpy(buffer[pos..][0..data.len], data);
    pos += data.len;
    try testing.expectEqualSlices(u8, &net_bytes, buffer[0..pos]);
}

pub fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var res: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&res, hex) catch unreachable;
    return res;
}

test "ip with options" {
    var bytes: []const u8 = &hexToBytes("01005e0000fb1ae829c3ec78080046c00020f3d700000102d09ac0a8be01e00000fb9404000011640da0e00000fb");

    const eth = try Ethernet.decode(bytes);
    bytes = bytes[@sizeOf(Ethernet)..];
    const ip = try Ip.decode(bytes);

    try testing.expectEqual(.ip, eth.protocol);
    try testing.expectEqual(6, ip.header.length); // 24 bytes header instead of default 20
    try testing.expectEqual(32, ip.total_length);
    try testing.expectEqual(4, ip.options_length());
    try testing.expectEqual(8, ip.payload_length());
    try testing.expectEqual(.igmp, ip.protocol);
}

test "udp checksum" {
    var ip: Ip = .{
        .source = [_]u8{ 192, 168, 190, 90 },
        .destination = [_]u8{ 192, 168, 190, 235 },
        .protocol = .udp,
        .total_length = 0,
        .identification = 0,
    };
    var udp: UdpHeader = .{
        .source_port = 4660,
        .destination_port = 9999,
        .length = 28,
    };
    const payload: []const u8 = &hexToBytes("68656c6c6f2066726f6d207069636f203238360a");

    var buf: [64]u8 = @splat(0);
    const n = try udp.encode(&buf, &ip, payload);

    const expected = hexToBytes("1234270f001c4cd3");
    try testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "arp table" {
    var at: ArpTable(4) = .{};

    at.push(.{ 192, 168, 1, 10 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00 });
    at.push(.{ 192, 168, 1, 11 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 });
    at.push(.{ 192, 168, 1, 12 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 });
    try testing.expectEqual(0x01, at.pop(.{ 192, 168, 1, 11 }).?.mac[5]);
    try testing.expectEqual(0x02, at.pop(.{ 192, 168, 1, 12 }).?.mac[5]);

    at.push(.{ 192, 168, 1, 13 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 });
    at.push(.{ 192, 168, 1, 14 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04 });
    try testing.expectEqual(0x04, at.pop(.{ 192, 168, 1, 14 }).?.mac[5]);
    try testing.expectEqual(null, at.pop(.{ 192, 168, 1, 10 }));
}

test "create dhcp discover" {
    const expected: []const u8 = &hexToBytes("010106000000000000008000000000000000000000000000000000002ccf67f3b7ea0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101390205dc370401031c06ff");

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });

    var buffer: [1500]u8 = undefined;
    const n = try dhcp.encodePayload(&buffer);
    try testing.expectEqualSlices(u8, expected, buffer[0..n]);
}

test "parse dhcp offer" {
    const bytes: []const u8 = &hexToBytes("02010600000000000000800000000000c0a8cfaac0a8cf01000000002ccf67f3b7ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a8cf01330400000e103a04000007083b0400000c4e0104ffffff001c04c0a8cfff1a0205dc0304c0a8cf010604c0a8cf01ff00000000");
    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .discover;

    try dhcp.handle(bytes, 0);
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
    const expected: []const u8 = &hexToBytes("010106000000000000008000000000000000000000000000000000002ccf67f3b7ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033604c0a8be013204c0a8bece390205dc370401031c06ff");

    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .offer;
    dhcp.args.addr = .{ 192, 168, 190, 206 };
    dhcp.args.dhcp_server = .{ 192, 168, 190, 1 };

    var buffer: [1500]u8 = undefined;
    const n = try dhcp.encodePayload(&buffer);
    try testing.expectEqualSlices(u8, expected, buffer[0..n]);
}

test "parse dhcp ack" {
    const bytes: []const u8 = &hexToBytes("02010600000000000000800000000000c0a8becec0a8be01000000002ccf67f3b7ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053604c0a8be0133040000a8c03a04000054603b04000093a80104ffffff001c04c0a8beff1a0205dc0304c0a8be010604c0a8be01ff00000000");
    var dhcp: Dhcp = .init(.{ 0x2c, 0xcf, 0x67, 0xf3, 0xb7, 0xea });
    dhcp.state = .request;

    try dhcp.handle(bytes, 0);
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

fn asIpAddr(bytes: []const u8) !IpAddr {
    if (bytes.len < 4) return error.InsufficientBuffer;
    return bytes[0..4].*;
}

fn asInt(T: type, bytes: []const u8) !T {
    const l = @divExact(@typeInfo(T).int.bits, 8);
    if (bytes.len < l) return error.InsufficientBuffer;
    return mem.readInt(T, bytes[0..l], .big);
}

const Ports = enum(u16) {
    dhcp_server = 67,
    dhcp_client = 68,
    _,
};

const Dhcp = struct {
    const Self = @This();

    state: State = .initial,
    ts: u32 = 0, // timestamp of the last state change
    transaction_id: u32 = 0,
    args: Args,

    const Args = struct {
        mac: Mac,

        addr: IpAddr = @splat(0),
        subnet_mask: IpAddr = @splat(0),
        broadcast_addr: IpAddr = broadcast_ip,

        gateway: IpAddr = @splat(0),
        dns_server: IpAddr = @splat(0),
        dhcp_server: IpAddr = @splat(0),

        lease_time: u32 = 0, // release when expires
        renewal_time: u32 = 0, // renew from the same server
        rebinding_time: u32 = 0, // renew from any server

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
        heln: u8 = 6, // number of bytes in chaddr
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

        pub fn decode(bytes: []const u8) !Boot {
            return try decodeAny(Boot, bytes, 0);
        }
    };

    pub fn init(mac: Mac) Dhcp {
        return .{ .args = .{ .mac = mac } };
    }

    pub fn set_state(self: *Self, new_state: State, now: u32) void {
        if (self.state == new_state) return;
        log.debug("dhcp state {s:<8} => {s:<8} ts: {}", .{ @tagName(self.state), @tagName(new_state), now });
        self.state = new_state;
        self.ts = now;
    }

    fn encodePayload(self: *Self, buffer: []u8) !usize {
        var w = std.Io.Writer.fixed(buffer);
        var boot: Boot = .{ .xid = self.transaction_id };
        if (native_endian == .little) {
            std.mem.byteSwapAllFields(Boot, &boot);
        }
        @memcpy(boot.chaddr[0..6], &self.args.mac);
        try w.writeAll(mem.asBytes(&boot));
        try w.writeAll(&magic_cookie);
        // message type header
        try w.writeAll(&.{ 0x35, 0x01 });
        if (self.state == .offer) {
            try w.writeByte(@intFromEnum(MessageType.request));

            try w.writeByte(@intFromEnum(Options.dhcp_server));
            try w.writeByte(4);
            try w.writeAll(&self.args.dhcp_server);

            try w.writeByte(@intFromEnum(Options.requested_ip));
            try w.writeByte(4);
            try w.writeAll(&self.args.addr);
        } else {
            try w.writeByte(@intFromEnum(MessageType.discover));
        }
        // max message size 1500
        try w.writeAll(&.{ 0x39, 0x02, 0x05, 0xdc });
        // parameter request list
        try w.writeAll(&.{ 0x37, 0x04, 0x01, 0x03, 0x1c, 0x06 });
        // end
        try w.writeAll(&.{0xff});
        return w.end;
    }

    pub fn encode(self: *Self, buffer: []u8) !usize {
        const n = try self.encodePayload(buffer[Udp.header_len..]);
        var udp: Udp = .{
            .ip_identification = 0,
            .source = .{
                .ip = @splat(0),
                .mac = self.args.mac,
                .port = @intFromEnum(Ports.dhcp_client),
            },
            .destination = .{
                .ip = broadcast_ip,
                .mac = broadcast_mac,
                .port = @intFromEnum(Ports.dhcp_server),
            },
        };
        return try udp.encode(buffer, buffer[Udp.header_len..][0..n]);
    }

    fn handle(self: *Self, payload: []const u8, now: u32) !void {
        var bytes: []const u8 = payload;

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
                .subnet_mask => args.subnet_mask = try asIpAddr(val),
                .broadcast_addr => args.broadcast_addr = try asIpAddr(val),
                .gateway => args.gateway = try asIpAddr(val),
                .dns_server => args.dns_server = try asIpAddr(val),
                .dhcp_server => args.dhcp_server = try asIpAddr(val),
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
                    self.set_state(.offer, now);
                }
            },
            .request => {
                if (message_type.? == .ack) {
                    self.args = args;
                    self.set_state(.bound, now);
                }
                if (message_type.? == .nak) {
                    self.set_state(.initial, now);
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
};
