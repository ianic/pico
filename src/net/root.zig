const std = @import("std");
const mem = std.mem;
const log = std.log.scoped(.net);

const Link = @import("link");
const Dhcp = @import("Dhcp.zig");
const ptc = @import("protocol.zig");
const Addr = ptc.Addr;
const Mac = ptc.Mac;

const arp_table_len = 8;
const tx_link_header = 22;

pub const Interface = struct {
    const Self = @This();

    identification: u16 = 0,
    driver: Link,
    tx_buffer: []u8,
    rx_buffer: []u8,
    arp_table: ptc.ArpTable(arp_table_len) = .{},
    dhcp: Dhcp,
    link_state: Link.RecvResponse.LinkState = .down,
    source_port: u16 = 0,
    udp_handlers: std.SinglyLinkedList = .{},

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
                const bytes = self.rx_buffer[rsp.head..][0..rsp.len];
                const n = try self.rx(bytes, now);
                if (n != bytes.len) {
                    log.err("link recv: {}, n: {}", .{ bytes.len, n });
                }
            }
            if (rsp.link_state != self.link_state) {
                self.link_state = rsp.link_state;
            }
            if (rsp.next_packet_available) |npa| if (!npa) break;
        }
        if (self.link_state == .up)
            if (self.dhcp.timer.expired(now))
                try self.txDhcp(now);

        return self.dhcp.timer.expiresIn(now);
    }

    fn txDhcp(self: *Self, now: u32) !void {
        const buffer = self.txBuffer();
        const n = try self.dhcp.getMessage(buffer[ptc.Udp.header_len..], now);
        if (n > 0) {
            const dhcp_payload = buffer[ptc.Udp.header_len..][0..n];
            var udp: ptc.Udp = .{
                .ip_identification = self.ipIdentification(),
                .source = .{
                    .addr = @splat(0),
                    .mac = self.dhcp.ipc.mac,
                    .port = @intFromEnum(Ports.dhcp_client),
                },
                .destination = .{
                    .addr = @splat(0xff),
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
        var eth: ptc.Ethernet = .{
            .destination = @splat(0xff),
            .source = ipc.mac,
            .protocol = .arp,
        };
        var arp: ptc.Arp = .{
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

    /// Packet receive. Returns number of bytes consumed from rx_bytes.
    fn rx(self: *Self, rx_bytes: []const u8, now: u32) !usize {
        const ipc = self.dhcp.ipc;

        const eth = try ptc.Ethernet.decode(rx_bytes);
        const eth_payload = rx_bytes[@sizeOf(ptc.Ethernet)..];

        switch (eth.protocol) {
            .arp => {
                const arp = try ptc.Arp.decode(eth_payload);
                switch (arp.opcode) {
                    .request => if (mem.eql(u8, &arp.target_ip, &ipc.addr)) {
                        try self.send(try arp.tx(self.txBuffer(), ipc));
                    },
                    .response => self.arp_table.push(arp.sender_ip, arp.sender_mac),
                    else => {},
                }
                // log.debug("arp {} from ip: {any} mac: {x}", .{ arp.opcode, arp.sender_ip, arp.sender_mac });
                return @sizeOf(ptc.Ethernet) + @sizeOf(ptc.Arp);
            },
            .ip => {
                const ip = try ptc.Ip.decode(eth_payload);
                if (eth_payload.len < ip.total_length)
                    return error.IpLength;
                if (ip.fragment.mf or ip.fragment.offset > 0)
                    return error.IpFragmented;
                const ip_payload = eth_payload[0..ip.total_length][@sizeOf(ptc.Ip)..];

                switch (ip.protocol) {
                    .icmp => if (mem.eql(u8, &ip.destination, &ipc.addr)) {
                        const icmp = try ptc.Icmp.decode(ip_payload);
                        if (icmp.typ == .request) {
                            const icmp_payload = ip_payload[@sizeOf(ptc.Icmp)..];
                            try self.send(try icmp.tx(self.txBuffer(), eth, ip, icmp_payload, ipc));
                        }
                    },
                    .udp => {
                        const udp = try ptc.UdpHeader.decode(ip_payload);
                        if (ip_payload.len < udp.length) return error.UdpLength;
                        const udp_payload = ip_payload[@sizeOf(ptc.UdpHeader)..udp.length];

                        if (udp.source_port == @intFromEnum(Ports.dhcp_server) and
                            udp.destination_port == @intFromEnum(Ports.dhcp_client))
                        { // udp packet is dhcp response
                            try self.dhcp.rx(udp_payload, now);
                            try self.txDhcp(now);
                        } else {
                            // find handler for the incoming packet destination port
                            const src: Source = .{ .addr = ip.source, .port = udp.source_port };
                            var it = self.udp_handlers.first;
                            while (it) |node| : (it = node.next) {
                                const handler: *Udp = @fieldParentPtr("node", node);
                                if (handler.port == udp.destination_port) {
                                    if (handler.rx_callback) |cb| cb(handler, src, udp_payload);
                                    break;
                                }
                            }
                        }
                    },
                    else => {},
                }
                return @sizeOf(ptc.Ethernet) + ip.total_length;
            },
            else => {
                return rx_bytes.len;
            },
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

    net: *Interface = undefined,
    port: u16 = 0,
    rx_callback: ?Callback = null,
    node: std.SinglyLinkedList.Node = .{},

    pub fn txBuffer(self: Self) []u8 {
        return self.net.txBuffer()[ptc.Udp.header_len..];
    }

    pub fn sendTo(self: *Self, addr: Addr, port: u16, data: []const u8) !void {
        // TODO provjeri da je link up i da imam ip adrese
        const net = self.net;
        const arp = net.arp_table.get(addr) orelse {
            try net.findRoute(addr);
            return error.NoRouteToTheHost;
        };

        const buffer = net.txBuffer();
        const ipc = net.dhcp.ipc;
        var udp: ptc.Udp = .{
            .ip_identification = net.ipIdentification(),
            .source = .{ .addr = ipc.addr, .mac = ipc.mac, .port = self.port },
            .destination = .{ .addr = addr, .mac = arp.mac, .port = port },
        };
        try self.net.send(try udp.encode(buffer, data));
    }

    pub fn bind(self: *Self, callback: Callback, port: u16) void {
        self.rx_callback = callback;
        if (port > 0) self.port = port;
        self.net.udp_handlers.prepend(&self.node);
    }

    pub fn unbind(self: *Self) void {
        self.net.udp_handlers.remove(&self.node);
    }
};
