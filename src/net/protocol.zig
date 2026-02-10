const std = @import("std");
const mem = std.mem;
const native_endian = @import("builtin").cpu.arch.endian();
const assert = std.debug.assert;
const testing = std.testing;
const hexToBytes = @import("testu.zig").hexToBytes;
const log = std.log.scoped(.net_protocol);

pub const Mac = [6]u8;
pub const Addr = [4]u8;

pub const IpConfig = struct {
    mac: Mac,

    addr: Addr = @splat(0),
    subnet_mask: Addr = @splat(0),
    broadcast_addr: Addr = @splat(0xff),

    gateway: Addr = @splat(0),
    dns_server: Addr = @splat(0),
    dhcp_server: Addr = @splat(0),
};

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

pub const Udp = struct {
    const Self = @This();
    ip_identification: u16,
    source: struct {
        addr: Addr,
        mac: Mac,
        port: u16,
    },
    destination: struct {
        addr: Addr,
        mac: Mac,
        port: u16,
    },

    pub const header_len = @sizeOf(Ethernet) + @sizeOf(Ip) + @sizeOf(UdpHeader);

    pub fn encode(self: *Self, buffer: []u8, payload: []const u8) !usize {
        var eth: Ethernet = .{
            .source = self.source.mac,
            .destination = self.destination.mac,
            .protocol = .ip,
        };
        var ip: Ip = .{
            .identification = self.ip_identification,
            .protocol = .udp,
            .source = self.source.addr,
            .destination = self.destination.addr,
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
    sender_ip: Addr,
    target_mac: Mac,
    target_ip: Addr,

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, 0);
    }

    pub fn encode(self: Self, bytes: []u8) !usize {
        return try encodeAny(self, bytes);
    }

    pub fn tx(self: Self, tx_buffer: []u8, ipc: IpConfig) !usize {
        var eth: Ethernet = .{
            .destination = self.sender_mac,
            .source = ipc.mac,
            .protocol = .arp,
        };
        var arp: Arp = .{
            .opcode = .response,
            .sender_mac = ipc.mac,
            .sender_ip = ipc.addr,
            .target_mac = self.sender_mac,
            .target_ip = self.sender_ip,
        };
        var n = try eth.encode(tx_buffer);
        n += try arp.encode(tx_buffer[n..]);
        return n;
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
    source: Addr, // source ip address
    destination: Addr, // destintaion ip address

    pub fn decode(bytes: []const u8) !Self {
        const header_length: u8 = (bytes[0] & 0x0f) * 4;
        if (bytes.len < header_length) return error.InsufficientBuffer;
        return try decodeAny(Self, bytes[0..header_length], header_length);
    }

    fn encode(self: *Self, bytes: []u8) !usize {
        self.checksum = 0;
        const n = try encodeAny(self.*, bytes);
        setChecksum(Self, "", bytes[0..n], "");
        return n;
    }

    fn payloadLength(self: Self) u16 {
        return self.total_length - @as(u16, self.header.length) * 4;
    }

    fn optionsLength(self: Self) u16 {
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

    fn encode(self: *Self, bytes: []u8, payload: []const u8) !usize {
        self.checksum = 0;
        const n = try encodeAny(self.*, bytes);
        setChecksum(Self, "", bytes[0..n], payload);
        return n;
    }

    pub fn tx(
        self: Self,
        tx_buffer: []u8,
        eth_req: Ethernet,
        ip_req: Ip,
        payload: []const u8,
        ipc: IpConfig,
    ) !usize {
        var eth: Ethernet = .{
            .destination = eth_req.source,
            .source = ipc.mac,
            .protocol = .ip,
        };
        var ip: Ip = .{
            .service = ip_req.service,
            .identification = ip_req.identification,
            .protocol = .icmp,
            .source = ip_req.destination,
            .destination = ip_req.source,
            .total_length = ip_req.total_length,
        };
        var icmp: Icmp = .{
            .typ = .reply,
            .identifier = self.identifier,
            .sequence = self.sequence,
        };
        var n = try eth.encode(tx_buffer);
        n += try ip.encode(tx_buffer[n..]);
        n += try icmp.encode(tx_buffer[n..], payload);
        @memcpy(tx_buffer[n..][0..payload.len], payload);
        n += payload.len;
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
        source: Addr,
        destination: Addr,
        _: u8 = 0,
        protocol: Ip.Protocol,
        length: u16,
    };

    fn encode(self: *Self, bytes: []u8, ip: *Ip, payload: []const u8) !usize {
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
        setChecksum(Self, mem.asBytes(&pseudo_header), bytes[0..n], payload);
        return n;
    }

    pub fn decode(bytes: []const u8) !Self {
        return try decodeAny(Self, bytes, 0);
    }
};

comptime {
    assert(@sizeOf(Ethernet) == 14);
    assert(@sizeOf(Arp) == 28);
    assert(@sizeOf(Ip) == 20);
    assert(@sizeOf(Icmp) == 8);
    assert(@sizeOf(UdpHeader) == 8);
}

pub fn decodeAny(T: type, bytes: []const u8, checksum_len: usize) !T {
    if (checksum_len > 0) { // number of bytes for checksum calculation
        if (0xffff ^ checksum(0, bytes[0..checksum_len]) != 0) return error.Checksum;
    }
    if (bytes.len < @sizeOf(T)) return error.InsufficientBuffer;

    var t: T = @bitCast(bytes[0..@sizeOf(T)].*);
    if (native_endian == .little) {
        std.mem.byteSwapAllFields(T, &t);
    }
    return t;
}

fn setChecksum(T: type, pseudo_header: []const u8, header: []u8, payload: []const u8) void {
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

pub fn writeAny(w: *std.Io.Writer, any: anytype) !void {
    const T = @TypeOf(any);
    const n = @sizeOf(T);
    const bytes = try w.writableSlice(n);
    assert(try encodeAny(any, bytes) == n);
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
        const local_ip: Addr = .{ 192, 168, 190, 235 };
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

test "ip with options" {
    var bytes: []const u8 = &hexToBytes("01005e0000fb1ae829c3ec78080046c00020f3d700000102d09ac0a8be01e00000fb9404000011640da0e00000fb");

    const eth = try Ethernet.decode(bytes);
    bytes = bytes[@sizeOf(Ethernet)..];
    const ip = try Ip.decode(bytes);

    try testing.expectEqual(.ip, eth.protocol);
    try testing.expectEqual(6, ip.header.length); // 24 bytes header instead of default 20
    try testing.expectEqual(32, ip.total_length);
    try testing.expectEqual(4, ip.optionsLength());
    try testing.expectEqual(8, ip.payloadLength());
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

pub fn ArpTable(len: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            ip: Addr = @splat(0),
            mac: Mac = @splat(0),
        };

        entries: [len]Entry = @splat(.{}),
        next: usize = 0,

        pub fn push(self: *Self, ip: Addr, mac: Mac) void {
            self.entries[self.next] = .{ .ip = ip, .mac = mac };
            self.next = (self.next + 1) % len;
        }

        pub fn get(self: Self, ip: Addr) ?Entry {
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

test "arp table" {
    var at: ArpTable(4) = .{};

    at.push(.{ 192, 168, 1, 10 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00 });
    at.push(.{ 192, 168, 1, 11 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 });
    at.push(.{ 192, 168, 1, 12 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 });
    try testing.expectEqual(0x01, at.get(.{ 192, 168, 1, 11 }).?.mac[5]);
    try testing.expectEqual(0x02, at.get(.{ 192, 168, 1, 12 }).?.mac[5]);

    at.push(.{ 192, 168, 1, 13 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 });
    at.push(.{ 192, 168, 1, 14 }, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04 });
    try testing.expectEqual(0x04, at.get(.{ 192, 168, 1, 14 }).?.mac[5]);
    try testing.expectEqual(null, at.get(.{ 192, 168, 1, 10 }));
}
