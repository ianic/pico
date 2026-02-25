const std = @import("std");
const Atomic = std.atomic.Value;
const microzig = @import("microzig");
const cpu = microzig.cpu;
const hal = microzig.hal;
const time = hal.time;
const gpio = hal.gpio;
const pio = hal.pio;
const drivers = hal.drivers;
const loop = @import("loop.zig");
const pfs = @import("pfs.zig");
const TempSensor = @import("temp_sensor.zig").TempSensor;

const uart = hal.uart.instance.num(0);

pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
    .interrupts = .{
        .IO_IRQ_BANK0 = .{ .c = gpio_interrupt },
        .UART0_IRQ = .{ .c = uart_interrupt },
        .TIMER0_IRQ_0 = .{ .c = net_timer_interrupt },
        .TIMER0_IRQ_1 = .{ .c = sensor_timer_interrupt },
    },
};
const log = std.log.scoped(.main);

const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
    .GPIO22 = .{ .name = "temp", .direction = .out, .function = .SIO },
    .GPIO21 = .{ .name = "rel2", .direction = .out, .function = .SIO },
    .GPIO20 = .{ .name = "rel1", .direction = .out, .function = .SIO },
};

comptime {
    _ = @import("lwip_exports.zig");
}

const net = @import("net");
const secrets = @import("secrets.zig");

const blob_addr = 0x1030_0000;
const timer = hal.system_timer.num(0);
var wifi_driver: drivers.WiFi = .{};

var session_id: u32 = 0;
var reading_ts: u32 = 0;
var readings: @import("ring_buffer.zig").CircularBuffer(Reading, 32 * 1024) = .{};

const reading_byte_size: usize = @divExact(@bitSizeOf(Reading), 8);

const Reading = packed struct {
    ts: u32,
    temp: u16,
    relay: u1 = 0,
    _padding: u7 = 0,
};

pub fn add_reading(temp: u16, relay: u1) void {
    const ts = net.sntp.unix();
    reading_ts = ts;

    if (readings.last()) |last| {
        if (last.temp == temp and last.relay == relay) {
            var upd = last;
            upd.ts = ts;
            readings.update(upd);
            return;
        }
    }
    readings.add(.{
        .ts = ts,
        .temp = temp,
        .relay = relay,
    });
}

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);
    // uart interrupt
    uart.set_interrupts_enabled(.{ .rx = true, .rt = true });
    microzig.interrupt.enable(.UART0_IRQ);

    // Enable gpio interrupt callback
    microzig.interrupt.enable(.IO_IRQ_BANK0);
    // Enable timer interrupt callback
    microzig.cpu.interrupt.enable(.TIMER0_IRQ_0);
    microzig.cpu.interrupt.enable(.TIMER0_IRQ_1);
    timer.set_interrupt_enabled(.alarm0, true);
    timer.set_interrupt_enabled(.alarm1, true);

    log.debug("wifi init", .{});
    // init cyw43
    var wifi = try wifi_driver.init(.{
        .handle_irq = true,
        .chip = .{
            .firmware = pfs.fileFromBlob(blob_addr, 0),
            .clm = pfs.fileFromBlob(blob_addr, 2),
        },
    });
    //try wifi.set_power_mode(.none);
    var led = wifi.gpio(0);
    log.debug("mac address: {x}", .{wifi.mac});

    // join network
    try wifi.join_wait(secrets.ssid, secrets.pwd, secrets.join_opt);
    log.debug("wifi joined", .{});

    // init lwip network interface
    var nic: net.Interface = .{ .link = wifi.link() };
    try nic.init(wifi.mac, .{
        .hostname = "pico",
        .sntp_server = "pool.ntp.org",
        .status_callback = onNetStatus,
    });

    // init server
    var srv: net.tcp.Server = .{
        .nic = &nic,
        .on_accept = on_accept,
    };
    try srv.bind(80);

    var udp = try net.Udp.init(&nic);
    const sink: net.Endpoint = try .parse("192.168.207.181", 4242);

    const ts: TempSensor = .init(pins.temp);

    //var sntp_ts = net.sntp.time.ts;
    //
    while (true) {
        while (events.pop()) |event| switch (event) {
            .net_irq, .net_timeout => {
                timer.stop_alarm(.alarm0);
                while (true) {
                    const next_timeout = try nic.poll();
                    if (next_timeout > 0) {
                        timer.schedule_alarm(.alarm0, timer.read_low() +% next_timeout * 1000);
                        break;
                    }
                }
            },
            .temp_converted => {
                _ = events.push(.temp_read);
                const temp, const f = ts.read() catch |err| {
                    log.err("temperature sensor read {}", .{err});
                    continue;
                };
                add_reading(temp >> 2, pins.rel1.read());
                _ = events.push(.reading_added);
                log.debug("external temp: {} {} {} {} {}", .{ f, temp, readings.last().?, readings.count, reading_ts });
                pins.led.toggle();
            },
            .time_synced => {
                session_id = net.sntp.unix();
                add_reading(0, 0);
                _ = events.push(.temp_read);
            },
            .temp_read => {
                ts.convert() catch |err| {
                    log.err("temperature sensor convert {}", .{err});
                };
                timer.schedule_alarm(.alarm1, timer.read_low() +% std.time.us_per_s);
            },
            .reading_added => {
                var buf: [1472]u8 = undefined;
                var w = std.io.Writer.fixed(&buf);

                var iter = readings.iterator();
                while (iter.next()) |r| {
                    w.writeStruct(r, .little) catch break;
                }
                udp.send(buf[0..w.end], sink) catch |err| {
                    log.err("udp send {}", .{err});
                };
            },
            .toggle => {
                pins.rel1.toggle();
            },
        };

        cpu.wfi();
        led.toggle();
    }
}

fn gpio_interrupt() linksection(".ram_text") callconv(.c) void {
    _ = events.push(.net_irq);
    wifi_driver.disable_irq();
}

fn uart_interrupt() linksection(".ram_text") callconv(.c) void {
    // clear interrupt
    uart.get_regs().UARTICR.write(.{ .RXIC = 1, .RTIC = 1 });
    loop.check_reset(uart);
    //log.debug("check_reset", .{});
}

fn net_timer_interrupt() linksection(".ram_text") callconv(.c) void {
    _ = events.push(.net_timeout);
    timer.clear_interrupt(.alarm0);
}

fn sensor_timer_interrupt() linksection(".ram_text") callconv(.c) void {
    _ = events.push(.temp_converted);
    timer.clear_interrupt(.alarm1);
}

var pool: [2]Session = @splat(.{});

fn on_accept() ?*net.tcp.Connection {
    for (pool[0..]) |*handler| {
        if (handler.conn.state != .closed) continue;
        handler.* = .{
            .recv_bytes = 0,
            .conn = .{
                .on_recv = Session.on_recv,
                .on_connect = Session.on_connect,
                .on_close = Session.on_close,
            },
        };
        return &handler.conn;
    }
    return null;
}

const Session = struct {
    const Self = @This();

    conn: net.tcp.Connection = .{},
    recv_bytes: usize = 0,

    fn on_recv(conn: *net.tcp.Connection, bytes: []u8) void {
        onRecv(conn, bytes) catch |err| {
            log.err("http request {}", .{err});
        };
    }

    fn onRecv(conn: *net.tcp.Connection, bytes: []u8) !void {
        const Head = @import("Head.zig");
        const head: Head = try .parse(bytes);
        if (head.target.len <= 1) {
            // server root
        }
        log.debug("{x} request {s}", .{ @intFromPtr(conn), head.target });
        if (readings.count >= 1) {
            if (std.mem.startsWith(u8, head.target, "/last")) {
                return try last(conn);
            }
            if (std.mem.startsWith(u8, head.target, "/all")) {
                return try all(conn);
            }
            if (std.mem.startsWith(u8, head.target, "/toggle")) {
                _ = events.push(.toggle);
            }
        }
        try conn.send(http_ok);
    }

    fn last(conn: *net.tcp.Connection) !void {
        const reading = readings.last() orelse return;

        var http_buf: [1460]u8 = undefined;
        var w = std.Io.Writer.fixed(&http_buf);
        try w.print(http_header, .{
            1 * reading_byte_size,
            reading.ts,
        });
        try w.writeStruct(reading, .little);
        try conn.send(http_buf[0..w.end]);
    }

    fn all(conn: *net.tcp.Connection) !void {
        if (readings.count <= 1) return;
        var http_buf: [1460]u8 = undefined;

        var readings_count = @min(
            (http_buf.len - http_header.len - 8 - 8) / reading_byte_size,
            readings.count,
        );
        var w = std.Io.Writer.fixed(&http_buf);
        try w.print(http_header, .{
            readings_count * reading_byte_size,
            readings.last().?.ts,
        });
        var iter = readings.iterator();
        while (iter.next()) |r| {
            try w.writeStruct(r, .little);
            readings_count -= 1;
            if (readings_count == 0) break;
        }

        try conn.send(http_buf[0..w.end]);
    }

    fn on_connect(conn: *net.tcp.Connection) void {
        _ = conn;
        //log.debug("{x} connected", .{@intFromPtr(conn)});
    }

    fn on_close(conn: *net.tcp.Connection, err: net.Error) void {
        switch (err) {
            error.EndOfStream => {},
            else => {
                log.debug("{x} closed {}", .{ @intFromPtr(conn), err });
            },
        }
    }
};

const http_header =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: application/octet-stream\r\n" ++
    "Content-Length: {d}\r\n" ++
    "ETag: \"{x}\"\r\n" ++
    "Access-Control-Allow-Origin: *\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

const http_ok = "HTTP/1.1 200 OK\r\n" ++
    "Content-Length: 0\r\n" ++
    "Access-Control-Allow-Origin: *\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

var events: @import("atomic_ring_buffer.zig").AtomicRingBuffer(Event, 64) = .{};

const Event = enum(u8) {
    net_irq,
    net_timeout,
    temp_read,
    temp_converted,
    time_synced,
    reading_added,
    toggle,
};

fn onNetStatus(nic: *net.Interface, status: net.Interface.Status) void {
    _ = nic;
    log.debug("onNetStatus: {}", .{status});
    if (session_id == 0 and status.unix_time > 0) {
        _ = events.push(.time_synced);
    }
}
