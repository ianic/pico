const std = @import("std");
const mem = std.mem;
const log = std.log.scoped(.net);

const Link = @import("link");
const Dhcp = @import("Dhcp.zig");
const protocol = @import("protocol.zig");
const Addr = protocol.Addr;
const Mac = protocol.Mac;

const arp_table_len = 8;
const tx_link_header = 22;

pub const Net = struct {
    const Self = @This();

    identification: u16 = 0,
    driver: Link,
    tx_buffer: []u8,
    rx_buffer: []u8,
    arp_table: protocol.ArpTable(arp_table_len) = .{},
    dhcp: Dhcp,
    link_state: Link.RecvResponse.LinkState = .down,
    source_port: u16 = 0,
    udp_nodes: std.SinglyLinkedList = .{},

    udp: struct {
        pub fn init(ptr: *@This()) Udp {
            const self: *Self = @alignCast(@fieldParentPtr("udp", ptr));
            return .{
                .net = self,
                .port = self.sourcePort(),
            };
        }
    } = .{},

    fn ipIdentification(self: *Self) u16 {
        self.identification +%= 1;
        return self.identification;
    }

    pub fn poll(self: *Self, now: u32) !u32 {
        while (true) {
            const rsp = try self.driver.vtable.recv(self.driver.ptr, self.rx_buffer);
            if (rsp.len > 0) {
                try self.rx(self.rx_buffer[rsp.head..][0..rsp.len], now);
            }
            if (rsp.link_state != self.link_state) {
                self.link_state = rsp.link_state;
            }
            if (rsp.next_packet_available) |npa| if (!npa) break;
        }
        if (self.link_state == .up)
            if (self.dhcp.timer.expired(now))
                try self.dhcpTx(now);

        return self.dhcp.timer.expiresIn(now);
    }

    fn dhcpTx(self: *Self, now: u32) !void {
        const ipc = self.dhcp.ipc;
        const buffer = self.txBuffer();
        const n = try self.dhcp.tx(buffer[protocol.Udp.header_len..], now);
        if (n > 0) {
            const dhcp_payload = buffer[protocol.Udp.header_len..][0..n];
            var udp: protocol.Udp = .{
                .ip_identification = self.ipIdentification(),
                .source = .{
                    .ip = @splat(0),
                    .mac = ipc.mac,
                    .port = @intFromEnum(Ports.dhcp_client),
                },
                .destination = .{
                    .ip = @splat(0xff),
                    .mac = @splat(0xff),
                    .port = @intFromEnum(Ports.dhcp_server),
                },
            };
            try self.send(try udp.encode(buffer, dhcp_payload));
        }
    }

    // tx buffer with headroom reserved for the link
    fn txBuffer(self: *Self) []u8 {
        return self.tx_buffer[tx_link_header..];
    }

    fn send(self: *Self, pos: usize) Link.Error!void {
        try self.driver.vtable.send(
            self.driver.ptr,
            self.tx_buffer[0 .. tx_link_header + pos],
        );
    }

    pub fn findRoute(self: *Self, addr: Addr) !void {
        const ipc = self.dhcp.ipc;
        var eth: protocol.Ethernet = .{
            .destination = @splat(0xff),
            .source = ipc.mac,
            .protocol = .arp,
        };
        var arp: protocol.Arp = .{
            .opcode = .request,
            .sender_mac = ipc.mac,
            .sender_ip = ipc.addr,
            .target_mac = @splat(0xff),
            .target_ip = addr,
        };
        var buf = self.txBuffer();
        var pos = try eth.encode(buf);
        pos += try arp.encode(buf[pos..]);
        try self.send(pos);
    }

    fn rx(self: *Self, rx_bytes: []const u8, now: u32) !void {
        var bytes: []const u8 = rx_bytes;
        const eth = try protocol.Ethernet.decode(bytes);
        bytes = bytes[@sizeOf(protocol.Ethernet)..];
        const ipc = self.dhcp.ipc;

        switch (eth.protocol) {
            .arp => {
                const arp = try protocol.Arp.decode(bytes);
                bytes = bytes[@sizeOf(protocol.Arp)..];
                switch (arp.opcode) {
                    .request => {
                        if (!mem.eql(u8, &arp.target_ip, &ipc.addr)) return;
                        try self.send(try arp.tx(self.txBuffer(), ipc));
                        log.debug(
                            "arp request from ip: {any} mac: {x}",
                            .{ arp.sender_ip[0..4], arp.sender_mac[0..6] },
                        );
                    },
                    .response => {
                        self.arp_table.push(arp.sender_ip, arp.sender_mac);
                        log.debug(
                            "arp response from ip: {any} mac: {x}",
                            .{ arp.sender_ip, arp.sender_mac },
                        );
                    },
                    else => {},
                }
                return;
            },
            .ip => {
                const ip = try protocol.Ip.decode(bytes);
                if (bytes.len < ip.total_length)
                    return error.InsufficientBuffer;
                if (ip.fragment.mf or ip.fragment.offset > 0)
                    return error.IpFragmented;
                bytes = bytes[0..ip.total_length][@sizeOf(protocol.Ip)..];

                switch (ip.protocol) {
                    .icmp => {
                        if (!mem.eql(u8, &ip.destination, &ipc.addr)) return;
                        const icmp = try protocol.Icmp.decode(bytes);
                        if (icmp.typ == .request) {
                            const payload = bytes[@sizeOf(protocol.Icmp)..];
                            try self.send(try icmp.tx(self.txBuffer(), eth, ip, payload, ipc));
                        }
                    },
                    .udp => {
                        const udp = try protocol.UdpHeader.decode(bytes);
                        if (bytes.len < udp.length) return error.InsufficientBuffer;
                        bytes = bytes[@sizeOf(protocol.UdpHeader)..udp.length];

                        // dhcp response
                        if (udp.source_port == @intFromEnum(Ports.dhcp_server) and
                            udp.destination_port == @intFromEnum(Ports.dhcp_client))
                        {
                            try self.dhcp.rx(bytes, now);
                            try self.dhcpTx(now);
                            return;
                        }

                        var it = self.udp_nodes.first;
                        while (it) |node| : (it = node.next) {
                            const u: *Udp = @fieldParentPtr("node", node);
                            if (u.port == udp.destination_port) {
                                if (u.rx_callback) |cb| {
                                    cb(u, .{ .addr = ip.source, .port = udp.source_port }, bytes);
                                }
                                return;
                            }
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    fn sourcePort(self: *Self) u16 {
        self.source_port +%= 1;
        if (self.source_port < 49152)
            self.source_port = 49152;
        return self.source_port;
    }
};

const Ports = enum(u16) {
    dhcp_server = 67,
    dhcp_client = 68,
    _,
};

test {
    _ = @import("protocol.zig");
    _ = @import("Dhcp.zig");
}

pub const Timer = struct {
    const Self = @This();

    start: u32 = 0,
    duration: u32 = 0,

    pub fn expired(self: Self, now: u32) bool {
        return (now -% self.start >= self.duration);
    }

    pub fn less(self: Self, other: Self) bool {
        return (self.start +% self.duration) < (other.start +% other.duration);
    }

    pub fn expiresIn(self: Self, now: u32) u32 {
        const diff = now -% self.start;
        if (diff >= self.duration) return 0;
        return self.duration - diff;
    }
};

const testing = std.testing;

test Timer {
    const maxU32 = std.math.maxInt(u32);

    const t: Timer = .{ .start = maxU32 - 100, .duration = 1000 };
    try testing.expect(!t.expired(maxU32 - 100));
    try testing.expect(!t.expired(maxU32 - 10));
    try testing.expect(t.expired(maxU32 - 101));
    try testing.expect(!t.expired(100));
    try testing.expect(!t.expired(898));
    try testing.expect(t.expired(899));

    try testing.expectEqual(1000, t.expiresIn(maxU32 - 100));
    try testing.expectEqual(910, t.expiresIn(maxU32 - 10));
    try testing.expectEqual(890, t.expiresIn(9));
    try testing.expectEqual(99, t.expiresIn(800));
    try testing.expectEqual(0, t.expiresIn(900));

    const t2: Timer = .{ .start = maxU32 - 200, .duration = 1300 };
    try testing.expect(t.less(t2));
    try testing.expect(!t2.less(t));

    const t3: Timer = .{};
    try testing.expect(t3.expired(1));
}

pub const Source = struct {
    addr: Addr,
    port: u16,
};
pub const Target = Source;

pub const Udp = struct {
    const Self = @This();
    pub const Callback = *const fn (*Self, Source, []const u8) void;

    net: *Net = undefined,
    port: u16 = 0,
    rx_callback: ?Callback = null,
    node: std.SinglyLinkedList.Node = .{},

    pub fn sendTo(self: *Self, addr: Addr, port: u16, data: []const u8) !void {
        const net = self.net;
        const arp = net.arp_table.get(addr) orelse {
            try net.findRoute(addr);
            return error.NoRouteToTheHost;
        };

        const buffer = net.txBuffer();
        const ipc = net.dhcp.ipc;
        var udp: protocol.Udp = .{
            .ip_identification = net.ipIdentification(),
            .source = .{ .ip = ipc.addr, .mac = ipc.mac, .port = self.port },
            .destination = .{ .ip = addr, .mac = arp.mac, .port = port },
        };
        try self.net.send(try udp.encode(buffer, data));
    }

    pub fn bind(self: *Self, callback: Callback, port: u16) void {
        self.rx_callback = callback;
        if (port > 0) self.port = port;
        self.net.udp_nodes.prepend(&self.node);
    }

    pub fn unbind(self: *Self) void {
        self.net.udp_nodes.remove(&self.node);
    }
};
