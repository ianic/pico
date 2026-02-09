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
        if (self.link_state == .up) {
            try self.dhcpTx(now);
        }
        return if (self.dhcp.state == .bound) 60_000 else 1_000;
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

    pub fn sendArpRequest(self: *Self, ip: Addr) !void {
        var eth: protocol.Ethernet = .{
            .destination = @splat(0xff),
            .source = self.mac,
            .protocol = .arp,
        };
        var arp: protocol.Arp = .{
            .opcode = .request,
            .sender_mac = self.mac,
            .sender_ip = self.ip,
            .target_mac = @splat(0xff),
            .target_ip = ip,
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
                            "arp response from ip: {any} mac: {x} arp: {}",
                            .{ arp.sender_ip[0..4], arp.sender_mac[0..6], arp },
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
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
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
