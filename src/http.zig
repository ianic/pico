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
const uart_tx_pin = gpio.num(0);
pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
    .interrupts = .{
        .IO_IRQ_BANK0 = .{ .c = gpio_interrupt },
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

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

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
    });

    // init server
    var srv: net.tcp.Server = .{
        .nic = &nic,
        .on_accept = on_accept,
    };
    try srv.bind(80);

    const ts: TempSensor = .init(pins.temp);
    ts.convert() catch |err| {
        log.err("temperature sensor convert {}", .{err});
    };
    timer.schedule_alarm(.alarm1, timer.read_low() +% std.time.us_per_s);

    var sntp_ts = net.sntp.time.ts;
    //pins.rel1.toggle();
    while (true) {
        while (events.get()) |pending| {
            if (pending.isSet(.net_irq) or pending.isSet(.net_timeout)) {
                timer.stop_alarm(.alarm0);
                while (true) {
                    const next_timeout = try nic.poll();
                    if (next_timeout > 0) {
                        timer.schedule_alarm(.alarm0, timer.read_low() +% next_timeout * 1000);
                        break;
                    }
                }
            }
            if (pending.isSet(.sensor_timeout)) {
                const external = ts.read() catch |err| brk: {
                    log.err("temperature sensor read {}", .{err});
                    break :brk 0;
                };
                log.debug("external temp: {}", .{external});

                ts.convert() catch |err| {
                    log.err("temperature sensor convert {}", .{err});
                };
                timer.schedule_alarm(.alarm1, timer.read_low() +% std.time.us_per_s);
                //pins.rel1.toggle();
                //pins.rel2.toggle();
                pins.led.toggle();
            }
        }
        cpu.wfi();
        led.toggle();

        if (sntp_ts != net.sntp.time.ts) {
            log.debug("sntp {}", .{net.sntp.time});
            sntp_ts = net.sntp.time.ts;
        }
        // if (net.sntp.date_time(std.time.s_per_hour)) |dt| {re
        //     log.debug("date: {}", .{dt});
        // }

        loop.check_reset(uart);
    }
}

fn gpio_interrupt() linksection(".ram_text") callconv(.c) void {
    events.set(.net_irq);
    wifi_driver.disable_irq();
}

fn net_timer_interrupt() linksection(".ram_text") callconv(.c) void {
    events.set(.net_timeout);
    timer.clear_interrupt(.alarm0);
}

fn sensor_timer_interrupt() linksection(".ram_text") callconv(.c) void {
    events.set(.sensor_timeout);
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
        const self: *Self = @fieldParentPtr("conn", conn);
        self.recv_bytes += bytes.len;
        log.debug("{x} recv {s}", .{ @intFromPtr(conn), bytes });
        conn.send(http_ok) catch |err| {
            log.debug("send {}", .{err});
        };
    }

    fn on_connect(conn: *net.tcp.Connection) void {
        log.debug("{x} connected", .{@intFromPtr(conn)});
    }

    fn on_close(conn: *net.tcp.Connection, err: net.Error) void {
        log.debug("{x} closed {}", .{ @intFromPtr(conn), err });
    }
};

const http_ok = "HTTP/1.1 200 OK\r\n" ++
    "Content-Length: 0\r\n" ++
    "Access-Control-Allow-Origin: *\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

var events: Events = .{};

const Events = struct {
    // Each bit represents an event type
    pending: Atomic(u32) = Atomic(u32).init(0),

    const Event = enum(u5) {
        net_irq = 0,
        net_timeout = 1,
        sensor_timeout = 2,
    };

    pub fn set(self: *Events, event: Event) void {
        const bit = @as(u32, 1) << @intFromEnum(event);
        _ = self.pending.fetchOr(bit, .release);
    }

    pub fn get(self: *Events) ?Pending {
        const p = Pending{ .value = self.pending.swap(0, .acquire) };
        if (p.empty()) return null;
        return p;
    }

    const Pending = struct {
        value: u32,

        fn isSet(self: Pending, event: Event) bool {
            const bit = @as(u32, 1) << @intFromEnum(event);
            return self.value & bit > 0;
        }

        fn empty(self: Pending) bool {
            return self.value == 0;
        }
    };
};
