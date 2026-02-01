const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;
const time = hal.time;
const gpio = hal.gpio;
const pio = hal.pio;
const drivers = hal.drivers;
const loop = @import("loop.zig");

const uart = hal.uart.instance.num(0);
const uart_tx_pin = gpio.num(0);
pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
};
const log = std.log.scoped(.main);

const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    // external led connected to the gpio 15 pin
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};

comptime {
    _ = @import("lwip_exports.zig");
}
const net = @import("net");
const secrets = @import("secrets.zig");

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // init cyw43
    var wifi_driver: drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{
        .chip = .{
            .firmware = fileFromAddr(0x103b_0000), // 7_95_61
            //.firmware = fileFromAddr(0x1036_0000), // 7_95_88
            .clm = fileFromAddr(0x1035_f000),
        },
    });
    var led = wifi.gpio(0);
    log.debug("mac address: {x}", .{wifi.mac});

    // join network
    try wifi.join_wait(secrets.ssid, secrets.pwd, secrets.join_opt);
    log.debug("wifi joined", .{});

    // init lwip network interface
    var nic: net.Interface = .{ .link = wifi.link() };
    try nic.init(wifi.mac, .{});

    var ts = time.get_time_since_boot();
    while (true) {
        // run lwip poller
        try nic.poll();

        // blink
        const now = time.get_time_since_boot();
        if (now.diff(ts).to_us() > 500_000) {
            ts = now;
            led.toggle();
            pins.led.toggle();
        }
        loop.check_reset(uart);
    }
}

fn bytesFromAddr(addr: usize, len: usize) []const u8 {
    return @as([*]const u8, @ptrFromInt(addr))[0..len];
}

fn fileFromAddr(addr: usize) []const u8 {
    const len: u32 = std.mem.readInt(u32, bytesFromAddr(addr, 4)[0..4], .little);
    log.debug("loading file of {} bytes from {x}", .{ len, addr });
    return bytesFromAddr(addr + 4, len);
}
