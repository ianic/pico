const std = @import("std");
const net = @import("net");
const microzig = @import("microzig");
const hal = microzig.hal;
const uart = hal.uart.instance.num(0);
const timer = hal.system_timer.num(0);

const loop = @import("loop.zig");
const secrets = @import("secrets.zig");

// logging
pub const microzig_options: microzig.Options = .{
    .log_level = .debug,
    .logFn = hal.uart.log,
};
const log = std.log.scoped(.main);

// pin configuration
const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    // external led connected to the gpio 15 pin
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // init cyw43 chip
    var wifi_driver: hal.drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{});
    var led = wifi.gpio(0); // on-board led

    // var pool_interval: loop.Interval = .init(10);
    var jp = try wifi.join_init(secrets.ssid, secrets.pwd, secrets.join_opt);

    var ticker: loop.Ticker = .{ .interval = 10 };
    while (true) : (ticker.next()) {
        if (ticker.every(5)) {
            led.toggle();
        }
        try jp.poll();
        if (jp.is_connected()) break;
    }
    led.put(0);

    // init lwip network interface
    var nic: net.Interface = .{ .link = .adapt(wifi.interface()) };
    try nic.init(wifi.mac, .{});

    // udp init
    var udp: net.Udp = try .init(&nic);
    // listen for udp packets on port 9999 and call on_recv for each received packet
    try udp.bind(9999, on_recv);

    // main loop
    led.put(1);
    ticker = .{};
    while (true) : (ticker.next()) {
        if (ticker.every(200)) {
            pins.led.toggle();
            led.toggle();
        }
        if (ticker.every(100)) {
            loop.check_reset(uart);
        }
        nic.poll() catch |err| {
            log.err("net pool {}", .{err});
        };
    }
}

fn on_recv(udp: *net.Udp, bytes: []u8, opt: net.Udp.RecvOptions) void {
    // show received packet
    log.debug(
        "received {} bytes, from: {f}, last: {}, data: {s}",
        .{ bytes.len, opt.src, opt.last_fragment, data_head(bytes, 32) },
    );
    // echo same data to the source address and port 9999
    udp.send(bytes, .{ .addr = opt.src.addr, .port = 9999 }) catch |err| {
        log.err("udp send {}", .{err});
    };
}

// log helper
pub fn data_head(bytes: []u8, max: usize) []u8 {
    const head: []u8 = bytes[0..@min(max, bytes.len)];
    std.mem.replaceScalar(u8, head, '\n', ' ');
    return head;
}
