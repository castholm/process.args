const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;
const os = std.os;

/// Allocates a slice containing the current process's command line arguments.
/// Caller must call `free` when done.
pub fn alloc(allocator: Allocator) Allocator.Error![][:0]const u8 {
    return (switch (builtin.os.tag) {
        .windows => allocSliceWindows,
        .wasi => if (builtin.link_libc) allocSlicePosix else allocSliceWasi,
        else => allocSlicePosix,
    })(allocator);
}

/// Frees a slice of command line arguments previously allocated with `alloc`.
pub fn free(allocator: Allocator, args: []const [:0]const u8) void {
    (switch (builtin.os.tag) {
        .windows => freeSliceWindows,
        .wasi => if (builtin.link_libc) freeSlicePosix else freeSliceWasi,
        else => freeSlicePosix,
    })(allocator, args);
}

/// Only the outermost slice is dynamically allocated.
fn allocSlicePosix(allocator: Allocator) Allocator.Error![][:0]const u8 {
    if (os.argv.len == 0) return &.{};
    const args = try allocator.alloc([:0]const u8, os.argv.len);
    for (args, os.argv) |*dst, src| {
        dst.* = mem.span(src);
    }
    return args;
}

/// Only the outermost slice is dynamically allocated.
fn freeSlicePosix(allocator: Allocator, args: []const [:0]const u8) void {
    if (args.len == 0) return;
    allocator.free(args);
}

fn allocSliceWindows(allocator: Allocator) Allocator.Error![][:0]const u8 {
    _ = allocator;
}

fn freeSliceWindows(allocator: Allocator, args: []const [:0]const u8) void {
    _ = allocator;
    _ = args;
}

fn allocSliceWasi(allocator: Allocator) Allocator.Error![][:0]const u8 {
    _ = allocator;
}

fn freeSliceWasi(allocator: Allocator, args: []const [:0]const u8) void {
    _ = allocator;
    _ = args;
}
