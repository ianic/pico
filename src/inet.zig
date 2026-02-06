const std = @import("std");
const microzig = @import("microzig");
const cpu = microzig.cpu;
const hal = microzig.hal;
const time = hal.time;
const gpio = hal.gpio;
const pio = hal.pio;
const drivers = hal.drivers;
const loop = @import("loop.zig");
const pfs = @import("pfs.zig");
const Net = @import("net.zig").Net;

const uart = hal.uart.instance.num(0);
const uart_tx_pin = gpio.num(0);
pub const microzig_options = microzig.Options{
    .log_level = .debug,
    .logFn = hal.uart.log,
    .interrupts = .{
        .IO_IRQ_BANK0 = .{ .c = gpio_interrupt },
        .TIMER0_IRQ_0 = .{ .c = timer_interrupt },
    },
};
const log = std.log.scoped(.main);

const pin_config = hal.pins.GlobalConfiguration{
    .GPIO0 = .{ .function = .UART0_TX },
    .GPIO1 = .{ .function = .UART0_RX },
    // external led connected to the gpio 15 pin
    .GPIO15 = .{ .name = "led", .direction = .out, .function = .SIO },
};

const secrets = @import("secrets.zig");

const blob_addr = 0x1030_0000;

const timer = hal.system_timer.num(0);

var wifi_driver: drivers.WiFi = .{};
var rx_buffer: [1540]u8 align(4) = undefined;
var tx_buffer: [1540]u8 align(4) = undefined;

pub fn main() !void {
    const pins = pin_config.apply();
    _ = pins;

    // Init uart logging
    uart.apply(.{ .clock_config = hal.clock_config });
    hal.uart.init_logger(uart);

    // Enable gpio interrupt callback
    microzig.interrupt.enable(.IO_IRQ_BANK0);
    // Enable timer interrupt callback
    microzig.cpu.interrupt.enable(.TIMER0_IRQ_0);
    timer.set_interrupt_enabled(.alarm0, true);

    // Init cyw43
    var wifi = try wifi_driver.init(.{
        .handle_irq = true,
        .chip = .{
            .firmware = pfs.fileFromBlob(blob_addr, 0),
            .clm = pfs.fileFromBlob(blob_addr, 2),
        },
    });
    var led = wifi.gpio(0);
    log.debug("mac address: {x}", .{wifi.mac});

    var net = Net{
        .dhcp = .init(wifi.mac),
        .driver = wifi.link(),
        .tx_buffer = &tx_buffer,
        .rx_buffer = &rx_buffer,
    };

    // Join network
    _ = try wifi.join(secrets.ssid, secrets.pwd, secrets.join_opt);

    // timer.schedule_alarm(.alarm0, timer.read_low() +% tick_interval_ms * 1000);
    while (true) {
        const now: u32 = @truncate(time.get_time_since_boot().to_us() / 1000);
        net.poll(now) catch |err| {
            log.err("net poll {}", .{err});
            // there can be more waiting packets
            // log error and poll again
            // TODO: fatal join error is also reported here and leads to infinite loop
            continue;
        };
        led.toggle();

        cpu.wfe();
    }
}

const tick_interval_ms = 250;

var wakeup_source: packed struct {
    wifi: bool = false,
    tick: bool = false,
} = .{};

fn gpio_interrupt() linksection(".ram_text") callconv(.c) void {
    // Disable interrupts storm, store source and wake up main loop.
    wifi_driver.disable_irq();
    wakeup_source.wifi = true;
    cpu.sev();
}

fn timer_interrupt() linksection(".ram_text") callconv(.c) void {
    wakeup_source.tick = true;
    cpu.sev();
    timer.clear_interrupt(.alarm0);
    timer.schedule_alarm(.alarm0, timer.read_low() +% tick_interval_ms * 1000);
}
