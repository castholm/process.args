const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = mem.Allocator;
const os = std.os;
const unicode = std.unicode;

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
        .windows => freeSliceWindowsWasi,
        .wasi => if (builtin.link_libc) freeSlicePosix else freeSliceWindowsWasi,
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

/// Memory layout: `args.*, args[0].*, args[1].*, ..., args[args.len - 1].*`
fn allocSliceWindows(allocator: Allocator) Allocator.Error![][:0]const u8 {
    const command_line_w = mem.span(os.windows.kernel32.GetCommandLineW());
    var command_line_it = unicode.Wtf16LeIterator.init(command_line_w);
    const lengths = Iterator.Windows.getLengths(&command_line_it, true);

    const args_byte_len = @sizeOf([:0]u8) * lengths.args;
    const raw_len = args_byte_len + lengths.buf;

    const raw = try allocator.alignedAlloc(u8, @alignOf([:0]u8), raw_len);

    const args_byte_start = 0;
    const args = @as([*][:0]u8, @ptrCast(raw.ptr + args_byte_start))[0..lengths.args];
    const buf_start = args_byte_len;
    var buf = raw[buf_start..];
    assert(buf.len == lengths.buf);

    command_line_it = unicode.Wtf16LeIterator.init(command_line_w);
    var index: usize = 0;
    while (Iterator.Windows.encodeNext(&command_line_it, index == 0, buf)) |arg| {
        args[index] = arg;
        index += 1;
        buf = buf[(arg.len + 1)..];
    }
    assert(index == args.len);
    assert(buf.len == 0);
    return args;
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

    comptime assert(@sizeOf([:0]u8) >= @sizeOf([*:0]u8));
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
    assert(buf.len == buf_len);

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
fn freeSliceWindowsWasi(allocator: Allocator, args: []const [:0]const u8) void {
    if (args.len == 0) return;
    var raw_len: usize = @sizeOf([:0]u8) * args.len;
    for (args) |arg| {
        raw_len += arg.len + 1;
    }
    const raw = @as([*]align(@alignOf([:0]u8)) const u8, @ptrCast(args.ptr))[0..raw_len];
    allocator.free(raw);
}

/// Initializes an iterator over the current process's command line arguments.
/// On Windows and WASI, an internal buffer may be allocated.
/// On other platforms, no memory will be allocated.
/// Caller must call `Iterator.deinit` to free the iterator's internal buffer when done.
pub fn iterator(allocator: Allocator) Allocator.Error!Iterator {
    return Iterator.initFromCurrentProcess(allocator);
}

pub const Iterator = struct {
    underlying_iterator: Native,

    pub fn initFromCurrentProcess(allocator: Allocator) Allocator.Error!Iterator {
        return .{
            .underlying_iterator = switch (@typeInfo(@TypeOf(Native.initFromCurrentProcess)).Fn.params.len) {
                0 => Native.initFromCurrentProcess(),
                1 => try Native.initFromCurrentProcess(allocator),
                else => comptime unreachable,
            },
        };
    }

    pub fn next(it: *Iterator) ?[:0]const u8 {
        return it.underlying_iterator.next();
    }

    pub fn skip(it: *Iterator) bool {
        return it.underlying_iterator.skip();
    }

    pub fn deinit(it: *Iterator) void {
        if (!@hasDecl(@TypeOf(it.underlying_iterator), "deinit")) return;
        it.underlying_iterator.deinit();
    }

    pub const Native = switch (builtin.os.tag) {
        .windows => Windows,
        .wasi => if (builtin.link_libc) Posix else Wasi,
        else => Posix,
    };

    pub const Posix = struct {
        args: []const [*:0]const u8,
        index: usize = 0,

        pub fn init(args: []const [*:0]const u8) Posix {
            return .{ .args = args };
        }

        pub fn initFromCurrentProcess() Posix {
            return Posix.init(os.argv);
        }

        pub fn next(it: *Posix) ?[:0]const u8 {
            if (it.index == it.args.len) return null;
            const arg = mem.span(it.args[it.index]);
            it.index += 1;
            return arg;
        }

        pub fn skip(it: *Posix) bool {
            if (it.index == it.args.len) return false;
            it.index += 1;
            return true;
        }
    };

    pub const Windows = struct {
        /// The essential parts of the algorithm are described in Microsoft's documentation:
        ///
        /// - <https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170#parsing-c-command-line-arguments>
        /// - <https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw>
        ///
        /// David Deley explains some additional undocumented quirks in great detail:
        ///
        /// - <https://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES>
        ///
        /// Code points `<= U+0020` terminating an unquoted first argument was discovered
        /// independently by testing and observing the behavior of `CommandLineToArgvW` on
        /// Windows 10.
        ///
        fn parseCommandLine(context: anytype, first: bool) @TypeOf(context.eof()) {
            var c: u21 = undefined;

            // The first argument (the executable name) uses different parsing rules.
            if (first) {
                c = context.nextCodePoint();
                switch (c) {
                    0 => {
                        // Immediately complete the iterator without yielding any arguments.
                        // 'CommandLineToArgvW' would return the name of the current executable.
                        return context.eof();
                    },
                    '"' => {
                        // If the first character is a quote, read everything until the next quote
                        // (then skip that quote), or until the end of the string.
                        while (true) {
                            c = context.nextCodePoint();
                            switch (c) {
                                '"', 0 => return context.yield(),
                                else => context.emitCodePoint(c),
                            }
                        }
                    },
                    else => {
                        // Otherwise, read everything until the next space or non-DEL ASCII control
                        // character (then skip that character), or until the end of the string.
                        // This means that if the command-line string starts with one of these
                        // characters, the first yielded argument will be the empty string.
                        context.emitCodePoint(c);
                        while (true) {
                            c = context.nextCodePoint();
                            switch (c) {
                                0...' ' => return context.yield(),
                                else => context.emitCodePoint(c),
                            }
                        }
                    },
                }
            }

            // Skip spaces and tabs.
            // The iterator completes if we reach the end of the string here.
            while (true) {
                c = context.nextCodePoint();
                switch (c) {
                    0 => return context.eof(),
                    ' ', '\t' => continue,
                    else => break,
                }
            }

            // Parsing rules for subsequent arguments:
            //
            // - The end of the string always terminates the current argument.
            // - When not in 'inside_quotes' mode, a space or tab terminates the current argument.
            // - 2n backslashes followed by a quote emit n backslashes. If in 'inside_quotes' and
            //   the quote is immediately followed by a second quote, one quote is emitted and the
            //   other is skipped, otherwise, the one quote is skipped. Finally, 'inside_quotes'
            //   is toggled.
            // - 2n + 1 backslashes followed by a quote emit n backslashes followed by a quote.
            // - n backslashes not followed by a quote emit n backslashes.
            //
            var backslash_count: usize = 0;
            var inside_quotes = false;
            var after_unquote = false;
            while (true) {
                switch (c) {
                    0 => {
                        context.emitBackslashes(backslash_count);
                        return context.yield();
                    },
                    ' ', '\t' => {
                        context.emitBackslashes(backslash_count);
                        backslash_count = 0;
                        after_unquote = false;
                        if (inside_quotes) {
                            context.emitCodePoint(c);
                        } else {
                            return context.yield();
                        }
                    },
                    '"' => {
                        if (after_unquote) {
                            after_unquote = false;
                            context.emitCodePoint('"');
                        } else {
                            const c_is_escaped_quote = backslash_count % 2 != 0;
                            context.emitBackslashes(backslash_count / 2);
                            backslash_count = 0;
                            if (c_is_escaped_quote) {
                                context.emitCodePoint('"');
                            } else {
                                if (inside_quotes) {
                                    after_unquote = true;
                                }
                                inside_quotes = !inside_quotes;
                            }
                        }
                    },
                    '\\' => {
                        backslash_count += 1;
                        after_unquote = false;
                    },
                    else => {
                        context.emitBackslashes(backslash_count);
                        backslash_count = 0;
                        after_unquote = false;
                        context.emitCodePoint(c);
                    },
                }
                c = context.nextCodePoint();
            }
        }

        fn getLengths(command_line: *unicode.Wtf16LeIterator, first: bool) struct { args: usize, buf: usize } {
            const Counter = struct {
                command_line: *unicode.Wtf16LeIterator,
                args: usize = 0,
                buf: usize = 0,
                fn nextCodePoint(counter: *@This()) u21 {
                    return counter.command_line.nextCodepoint() orelse 0;
                }
                fn emitCodePoint(counter: *@This(), c: u21) void {
                    counter.buf += unicode.utf8CodepointSequenceLength(c) catch unreachable;
                }
                fn emitBackslashes(counter: *@This(), n: usize) void {
                    counter.buf += n;
                }
                fn yield(counter: *@This()) bool {
                    counter.buf += 1;
                    counter.args += 1;
                    return true;
                }
                fn eof(_: *@This()) bool {
                    return false;
                }
            };
            var counter: Counter = .{ .command_line = command_line };
            if (parseCommandLine(&counter, first)) {
                while (parseCommandLine(&counter, false)) {}
            }
            return .{ .args = counter.args, .buf = counter.buf };
        }

        /// Assumes `buf` is large enough to hold the next argument.
        fn encodeNext(command_line: *unicode.Wtf16LeIterator, first: bool, buf: []u8) ?[:0]u8 {
            const Encoder = struct {
                command_line: *unicode.Wtf16LeIterator,
                buf: []u8,
                end: usize = 0,
                fn nextCodePoint(encoder: *@This()) u21 {
                    return encoder.command_line.nextCodepoint() orelse 0;
                }
                fn emitCodePoint(encoder: *@This(), c: u21) void {
                    encoder.end += unicode.wtf8Encode(c, encoder.buf[encoder.end..]) catch unreachable;
                }
                fn emitBackslashes(encoder: *@This(), n: usize) void {
                    @memset(encoder.buf[encoder.end..][0..n], '\\');
                    encoder.end += n;
                }
                fn yield(encoder: *@This()) [:0]u8 {
                    encoder.buf[encoder.end] = 0;
                    return encoder.buf[0..encoder.end :0];
                }
                fn eof(_: *@This()) ?[:0]u8 {
                    return null;
                }
            };
            var encoder: Encoder = .{ .command_line = command_line, .buf = buf };
            return parseCommandLine(&encoder, first);
        }
    };

    pub const Wasi = struct {};
};
