const std = @import("std");
const Atomic = std.atomic.Value;
const testing = std.testing;

pub fn AtomicRingBuffer(comptime T: type, comptime size: usize) type {
    comptime {
        if (!std.math.isPowerOfTwo(size)) @compileError("Size must be a power of two");
    }

    return struct {
        buffer: [size]T = undefined,
        // Use atomics for indices to ensure cross-core visibility
        head: Atomic(usize) = Atomic(usize).init(0),
        tail: Atomic(usize) = Atomic(usize).init(0),
        mask: usize = size - 1,

        const Self = @This();

        /// Producer: Called by one thread/core only
        pub fn push(self: *Self, item: T) bool {
            const h = self.head.load(.unordered);
            const t = self.tail.load(.acquire); // Ensure we see latest tail from consumer

            if (h -% t == size) return false; // Buffer full

            self.buffer[h & self.mask] = item;
            // Store-release: makes the written data visible to the consumer
            self.head.store(h +% 1, .release);
            return true;
        }

        /// Consumer: Called by a different thread/core only
        pub fn pop(self: *Self) ?T {
            const t = self.tail.load(.unordered);
            const h = self.head.load(.acquire); // Ensure we see latest head from producer

            if (h == t) return null; // Buffer empty

            const item = self.buffer[t & self.mask];
            // Store-release: signals to producer that space is now free
            self.tail.store(t +% 1, .release);
            return item;
        }
    };
}

test AtomicRingBuffer {
    var rb: AtomicRingBuffer(u32, 4) = .{};
    try testing.expectEqual(null, rb.pop());
    try testing.expect(rb.push(1));
    try testing.expect(rb.push(2));
    try testing.expect(rb.push(3));
    try testing.expect(rb.push(4));
    try testing.expect(!rb.push(5));
    try testing.expectEqual(1, rb.pop());
    try testing.expect(rb.push(5));
}
