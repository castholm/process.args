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

/// Memory layout: `args.*, args[0].*, args[1].*, ..., args[args.len - 1].*`
fn allocSliceWasi(allocator: Allocator) Allocator.Error![][:0]u8 {
    return allocSliceWasiInner(allocator) catch |err| switch (err) {
        error.Unexpected => &.{},
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn allocSliceWasiInner(allocator: Allocator) (Allocator.Error || os.UnexpectedError)![][:0]u8 {
    var args_len: usize = undefined;
    var buf_len: usize = undefined;
    switch (os.wasi.args_sizes_get(&args_len, &buf_len)) {
        .SUCCESS => {},
        else => |err| return os.unexpectedErrno(err),
    }
    if (args_len == 0) return &.{};
    const args_slice_bytes_len = @sizeOf([:0]u8) * args_len;
    const args_many_bytes_len = @sizeOf([*:0]u8) * args_len;
    const raw_len = args_slice_bytes_len + buf_len;

    const raw = try allocator.alignedAlloc(u8, @alignOf([:0]u8), raw_len);
    errdefer allocator.free(raw);

    const args_slice_bytes_start = 0;
    const args_slice = @as([*][:0]u8, @ptrCast(@alignCast(raw.ptr + args_slice_bytes_start)))[0..args_len];
    const args_many_bytes_start = args_slice_bytes_len - args_many_bytes_len;
    const args_many = @as([*][*:0]u8, @ptrCast(@alignCast(raw.ptr + args_many_bytes_start)))[0..args_len];
    const buf_start = args_slice_bytes_len;
    const buf = raw[buf_start..];
    switch (os.wasi.args_get(args_many.ptr, buf.ptr)) {
        .SUCCESS => {},
        else => |err| return os.unexpectedErrno(err),
    }
    for (args_slice, args_many) |*dst, src| {
        dst.* = mem.span(src);
    }
    return args_slice;
}

/// Memory layout: `args.*, args[0].*, args[1].*, ..., args[args.len - 1].*`
fn freeSliceWasi(allocator: Allocator, args: []const [:0]const u8) void {
    if (args.len == 0) return;
    var raw_len: usize = @sizeOf([:0]u8) * args.len;
    for (args) |arg| {
        raw_len += arg.len + 1;
    }
    const raw = @as([*]align(@alignOf([:0]u8)) const u8, @ptrCast(args.ptr))[0..raw_len];
    allocator.free(raw);
}
