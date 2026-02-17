const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;
const time = hal.time;
const gpio = hal.gpio;
const pio = hal.pio;
const drivers = hal.drivers;
const loop = @import("loop.zig");
const pfs = @import("pfs.zig");

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

const blob_addr = 0x1030_0000;

pub fn main() !void {
    const pins = pin_config.apply();
    // init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // init cyw43
    var wifi_driver: drivers.WiFi = .{};
    var wifi = try wifi_driver.init(.{
        .chip = .{
            .firmware = pfs.fileFromBlob(blob_addr, 0),
            .clm = pfs.fileFromBlob(blob_addr, 2),
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
        _ = try nic.poll();

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
