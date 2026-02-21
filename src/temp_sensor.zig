const std = @import("std");
const microzig = @import("microzig");
const hal = microzig.hal;
const time = hal.time;
const gpio = hal.gpio;

const OneWire = struct {
    pin: gpio.Pin,

    pub fn init(pin: gpio.Pin) OneWire {
        return .{ .pin = pin };
    }

    // Raises error if no devices are present on the data bus
    pub fn reset(self: OneWire) !void {
        self.pin.set_direction(.out);

        // bring low for 480us
        self.pin.put(0);
        time.sleep_us(480);

        self.pin.set_direction(.in); // let the data line float high
        time.sleep_us(70);
        const presence = self.pin.read() == 0; // see if any devices are pulling the data line low
        time.sleep_us(410);

        if (!presence) return error.NoDevices;
    }

    fn putBit(self: OneWire, bit: bool) void {
        self.pin.set_direction(.out);
        self.pin.put(0);
        time.sleep_us(3);
        if (bit) {
            self.pin.put(1);
            time.sleep_us(55);
        } else {
            time.sleep_us(60);
            self.pin.put(1);
            time.sleep_us(5);
        }
    }

    fn getBit(self: OneWire) bool {
        self.pin.set_direction(.out);
        self.pin.put(0);
        time.sleep_us(3);

        self.pin.set_direction(.in);
        time.sleep_us(3);
        const res = self.pin.read() == 1;
        time.sleep_us(45);

        return res;
    }

    fn putByte(self: OneWire, b: u8) void {
        var byte = b;
        for (0..8) |_| {
            self.putBit(byte & 0x01 > 0);
            byte = byte >> 1;
        }
    }

    fn getByte(self: OneWire) u8 {
        var byte: u8 = 0;
        for (0..8) |_| {
            byte = byte >> 1;
            if (self.getBit()) {
                byte = byte | 0x80;
            }
        }
        return byte;
    }
};

// DS18B20
pub const TempSensor = struct {
    ow: OneWire,

    pub fn init(pin: gpio.Pin) TempSensor {
        return .{ .ow = .init(pin) };
    }

    // Initiates a single temperature conversion
    // Leave 750ms before reading
    pub fn convert(self: TempSensor) !void {
        try self.ow.reset();
        self.ow.putByte(0xcc);
        self.ow.putByte(0x44);
    }

    pub fn read(self: TempSensor) !f32 {
        // read the contents of the scratchpad
        try self.ow.reset();
        self.ow.putByte(0xcc);
        self.ow.putByte(0xbe);
        var res: [9]u8 = @splat(0);
        for (&res) |*r| {
            const b = self.ow.getByte();
            r.* = b;
        }
        // check crc
        if (crc(res[0..8]) != res[8]) return error.CrcFail;
        // temperature bytes
        const lsb = res[0];
        const msb = res[1];
        const temp: u16 = (@as(u16, @intCast(msb)) << 8 | lsb);
        return @as(f32, @floatFromInt(temp)) / 16;
    }

    fn crc(bytes: []const u8) u8 {
        var res: u8 = 0;
        for (bytes) |byte| {
            var b = byte;
            for (0..8) |_| {
                const mix = ((res ^ b) & 0x01) > 0;
                res >>= 1;
                if (mix) res ^= 0x8C;
                b >>= 1;
            }
        }
        return res;
    }

    test crc {
        const data: [8]u8 = .{ 112, 1, 0, 0, 127, 225, 60, 170 };
        try std.testing.expectEqual(103, crc(&data));
    }
};

test {
    _ = TempSensor;
}
