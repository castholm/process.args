const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = mem.Allocator;
const os = std.os;
const unicode = std.unicode;

pub const AllocSliceError = if (builtin.os.tag == .windows)
    Allocator.Error
else if (builtin.os.tag == .wasi and !builtin.link_libc)
    Allocator.Error || os.UnexpectedError
else
    Allocator.Error;

pub fn allocSlice(allocator: Allocator) AllocSliceError![][:0]u8 {
    return if (builtin.os.tag == .windows)
        allocSliceWindows(allocator, os.windows.kernel32.GetCommandLineW())
    else if (builtin.os.tag == .wasi and !builtin.link_libc)
        allocSliceWasi(allocator, os.wasi.args_sizes_get, os.wasi.args_get)
    else
        allocSlicePosix(allocator, os.argv);
}

pub fn allocSlicePosix(
    allocator: Allocator,
    argv: []const [*:0]const u8,
) Allocator.Error![][:0]u8 {
    var buf_len: usize = 0;
    for (argv) |arg| {
        buf_len += mem.len(arg) + 1;
    }
    const raw = try allocSliceRaw(allocator, argv.len, buf_len);

    var end: usize = 0;
    for (raw.args, argv) |*dest_arg, src_arg| {
        const arg_len = mem.len(src_arg);
        const arg_len_sentinel = arg_len + 1;
        const dest_buf_sentinel = raw.buf[end..][0..arg_len_sentinel];
        @memcpy(dest_buf_sentinel, src_arg);
        end += arg_len_sentinel;
        dest_arg.* = dest_buf_sentinel[0..arg_len :0];
    }
    return raw.args;
}

pub fn allocSliceWindows(
    allocator: Allocator,
    command_line_w: [*:0]const u16,
) Allocator.Error![][:0]u8 {
    const command_line_w_slice = mem.span(command_line_w);
    var command_line_it = unicode.Wtf16LeIterator.init(command_line_w_slice);
    const lengths = IteratorWindows.countLengths(&command_line_it);
    const raw = try allocSliceRaw(allocator, lengths.args, lengths.buf_total);

    command_line_it.i = 0;
    var index: usize = 0;
    var end: usize = 0;
    while (IteratorWindows.encodeNext(&command_line_it, raw.buf[end..])) |arg| {
        raw.args[index] = arg;
        end += arg.len + 1;
        index += 1;
    }
    assert(index == raw.args.len);
    assert(end == raw.buf.len);
    return raw.args;
}

pub fn allocSliceWasi(
    allocator: Allocator,
    comptime args_sizes_get: @TypeOf(os.wasi.args_sizes_get),
    comptime args_get: @TypeOf(os.wasi.args_get),
) (Allocator.Error || os.UnexpectedError)![][:0]u8 {
    var args_len: usize = undefined;
    var buf_len: usize = undefined;
    switch (args_sizes_get(&args_len, &buf_len)) {
        .SUCCESS => {},
        else => |err| return os.unexpectedErrno(err),
    }
    const raw = try allocSliceRaw(allocator, args_len, buf_len);

    switch (args_get(raw.temp.ptr, raw.buf.ptr)) {
        .SUCCESS => {},
        else => |err| return os.unexpectedErrno(err),
    }
    for (raw.args, raw.temp) |*dest, src| {
        dest.* = mem.span(src);
    }
    return raw.args;
}

pub fn allocSliceResponseFile(
    comptime options: ResponseFileOptions,
    allocator: Allocator,
    rsp: []const u8,
) Allocator.Error![][:0]u8 {
    var rsp_i: usize = 0;
    const lengths = IteratorResponseFile(options).countLengths(rsp, &rsp_i);
    const raw = try allocSliceRaw(allocator, lengths.args, lengths.buf_total);

    rsp_i = 0;
    var index: usize = 0;
    var end: usize = 0;
    while (IteratorResponseFile(options).encodeNext(rsp, &rsp_i, raw.buf[end..])) |arg| {
        raw.args[index] = arg;
        end += arg.len + 1;
        index += 1;
    }
    assert(index == raw.args.len);
    assert(end == raw.buf.len);
    return raw.args;
}

fn allocSliceRaw(
    allocator: Allocator,
    args_len: usize,
    buf_len: usize,
) Allocator.Error!struct { args: [][:0]u8, temp: [][*:0]u8, buf: []u8 } {
    comptime assert(@sizeOf([:0]u8) >= @sizeOf([*:0]u8));
    comptime assert(@alignOf([:0]u8) % @alignOf([*:0]u8) == 0);

    const raw_len_bytelen = @sizeOf(usize);
    const args_bytelen = @sizeOf([:0]u8) * args_len;
    const args_bytestart = mem.alignForward(usize, raw_len_bytelen, @alignOf([:0]u8));
    const buf_start = args_bytestart + args_bytelen;
    const temp_bytelen = @sizeOf([*:0]u8) * args_len;
    const temp_bytestart = buf_start - temp_bytelen;
    const raw_len_value = buf_start + buf_len;

    const alignment = @max(@alignOf(usize), @alignOf([:0]u8), @alignOf([*:0]u8));
    const raw = try allocator.alignedAlloc(u8, alignment, raw_len_value);
    errdefer allocator.free(raw);

    const raw_len: *usize = @ptrCast(raw.ptr);
    raw_len.* = raw_len_value;

    const args = @as([*][:0]u8, @ptrCast(@alignCast(raw.ptr + args_bytestart)))[0..args_len];
    const temp = @as([*][*:0]u8, @ptrCast(@alignCast(raw.ptr + temp_bytestart)))[0..args_len];
    const buf = raw[buf_start..];
    assert(buf.len == buf_len);
    return .{ .args = args, .temp = temp, .buf = buf };
}

pub fn freeSlice(allocator: Allocator, args: []const [:0]const u8) void {
    const raw_len_addr = mem.alignBackward(usize, @intFromPtr(args.ptr) - 1, @alignOf(usize));
    const raw_len: *usize = @ptrFromInt(raw_len_addr);
    const alignment = @max(@alignOf(usize), @alignOf([:0]u8), @alignOf([*:0]u8));
    const raw = @as([*]align(alignment) const u8, @ptrCast(args.ptr))[0..raw_len.*];
    allocator.free(raw);
}

pub const IteratorOptions = struct {
    stable: bool = true,
};

/// Initializes an iterator over the current process's command-line arguments.
/// Caller must call `Iterator.deinit` to free the iterator's internal buffer when done.
pub fn iterator(allocator: Allocator, options: IteratorOptions) Iterator.InitError!Iterator {
    return if (builtin.os.tag == .windows)
        try IteratorWindows.init(allocator, os.windows.kernel32.GetCommandLineW(), options)
    else if (builtin.os.tag == .wasi and !builtin.link_libc)
        try IteratorWasi.init(allocator, os.wasi.args_sizes_get, os.wasi.args_get)
    else
        IteratorPosix.init(os.argv);
}

const Iterator = if (builtin.os.tag == .windows)
    IteratorWindows
else if (builtin.os.tag == .wasi and !builtin.link_libc)
    IteratorWasi
else
    IteratorPosix;

pub const IteratorPosix = struct {
    argv: []const [*:0]const u8,
    index: usize = 0,

    pub const InitError = error{};

    pub fn init(argv: []const [*:0]const u8) IteratorPosix {
        return .{ .argv = argv };
    }

    pub fn next(it: *IteratorPosix) ?[:0]const u8 {
        if (it.index == it.argv.len) return null;
        const arg = mem.span(it.argv[it.index]);
        it.index += 1;
        return arg;
    }

    pub fn skip(it: *IteratorPosix) bool {
        if (it.index == it.argv.len) return false;
        it.index += 1;
        return true;
    }

    pub fn reset(it: *IteratorPosix) void {
        it.index = 0;
    }

    pub fn deinit(it: *IteratorPosix) void {
        _ = it;
    }
};

pub const IteratorWindows = struct {
    command_line: unicode.Wtf16LeIterator,
    buf: []u8,
    buf_i: usize = 0,
    allocator: Allocator,
    stable: bool,

    pub const InitError = Allocator.Error;

    pub fn init(
        allocator: Allocator,
        command_line_w: [*:0]const u16,
        options: IteratorOptions,
    ) InitError!IteratorWindows {
        const command_line_w_slice = mem.span(command_line_w);
        var command_line_it = unicode.Wtf16LeIterator.init(command_line_w_slice);
        const lengths = countLengths(&command_line_it);
        const buf_len = if (options.stable) lengths.buf_total else lengths.buf_max;
        const buf = try allocator.alloc(u8, buf_len);

        return .{
            .command_line = unicode.Wtf16LeIterator.init(command_line_w_slice),
            .buf = buf,
            .allocator = allocator,
            .stable = options.stable,
        };
    }

    pub fn next(it: *IteratorWindows) ?[:0]const u8 {
        if (encodeNext(&it.command_line, it.buf[it.buf_i..])) |arg| {
            if (it.stable) {
                it.buf_i += arg.len + 1;
            }
            return arg;
        } else {
            return null;
        }
    }

    pub fn skip(it: *IteratorWindows) bool {
        return if (it.stable)
            it.next() != null
        else
            skipNext(&it.command_line);
    }

    pub fn reset(it: *IteratorWindows) void {
        it.command_line.i = 0;
        it.buf_i = 0;
    }

    pub fn deinit(it: *IteratorWindows) void {
        it.allocator.free(it.buf);
    }

    fn countLengths(command_line: *unicode.Wtf16LeIterator) struct {
        args: usize,
        buf_total: usize,
        buf_max: usize,
    } {
        const Counter = struct {
            command_line: *unicode.Wtf16LeIterator,
            args: usize = 0,
            buf_current: usize = 0,
            buf_total: usize = 0,
            buf_max: usize = 0,
            fn readNextCharacter(counter: *@This()) u21 {
                return counter.command_line.nextCodepoint() orelse 0;
            }
            fn writeCharacter(counter: *@This(), c: u21) void {
                counter.buf_current += unicode.utf8CodepointSequenceLength(c) catch unreachable;
            }
            fn writeBackslashes(counter: *@This(), n: usize) void {
                counter.buf_current += n;
            }
            fn yield(counter: *@This()) bool {
                counter.buf_current += 1;
                counter.buf_total += counter.buf_current;
                counter.buf_max = @max(counter.buf_max, counter.buf_current);
                counter.buf_current = 0;
                counter.args += 1;
                return true;
            }
            fn eof(_: *@This()) bool {
                return false;
            }
        };
        var counter: Counter = .{ .command_line = command_line };
        while (parseCommandLineString(&counter, .windows, command_line.i == 0)) {}
        return .{
            .args = counter.args,
            .buf_total = counter.buf_total,
            .buf_max = counter.buf_max,
        };
    }

    fn encodeNext(command_line: *unicode.Wtf16LeIterator, buf: []u8) ?[:0]u8 {
        const Encoder = struct {
            command_line: *unicode.Wtf16LeIterator,
            buf: []u8,
            end: usize = 0,
            fn readNextCharacter(encoder: *@This()) u21 {
                return encoder.command_line.nextCodepoint() orelse 0;
            }
            fn writeCharacter(encoder: *@This(), c: u21) void {
                encoder.end += unicode.wtf8Encode(c, encoder.buf[encoder.end..]) catch unreachable;
            }
            fn writeBackslashes(encoder: *@This(), n: usize) void {
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
        return parseCommandLineString(&encoder, .windows, command_line.i == 0);
    }

    fn skipNext(command_line: *unicode.Wtf16LeIterator) bool {
        const Skipper = struct {
            command_line: *unicode.Wtf16LeIterator,
            fn readNextCharacter(skipper: *@This()) u21 {
                return skipper.command_line.nextCodepoint() orelse 0;
            }
            fn writeCharacter(_: *@This(), _: u21) void {}
            fn writeBackslashes(_: *@This(), _: usize) void {}
            fn yield(_: *@This()) bool {
                return true;
            }
            fn eof(_: *@This()) bool {
                return false;
            }
        };
        var skipper: Skipper = .{ .command_line = command_line };
        return parseCommandLineString(&skipper, .windows, command_line.i == 0);
    }
};

pub const IteratorWasi = struct {
    args: [][*:0]u8,
    index: usize = 0,
    allocator: Allocator,

    pub const InitError = Allocator.Error || os.UnexpectedError;

    pub fn init(
        allocator: Allocator,
        comptime args_sizes_get: @TypeOf(os.wasi.args_sizes_get),
        comptime args_get: @TypeOf(os.wasi.args_get),
    ) InitError!IteratorWasi {
        const args: [][*:0]u8 = alloc_args: {
            var args_len: usize = undefined;
            var buf_len: usize = undefined;
            switch (args_sizes_get(&args_len, &buf_len)) {
                .SUCCESS => {},
                else => |err| return os.unexpectedErrno(err),
            }
            if (args_len == 0) break :alloc_args &.{};

            const raw_len_bytelen = @sizeOf(usize);
            const args_bytelen = @sizeOf([*:0]u8) * args_len;
            const args_bytestart = mem.alignForward(usize, raw_len_bytelen, @alignOf([*:0]u8));
            const buf_start = args_bytestart + args_bytelen;
            const raw_len_value = buf_start + buf_len;

            const alignment = @max(@alignOf(usize), @alignOf([*:0]u8));
            const raw = try allocator.alignedAlloc(u8, alignment, raw_len_value);
            errdefer allocator.free(raw);

            const raw_len: *usize = @ptrCast(raw.ptr);
            raw_len.* = raw_len_value;

            const args = @as([*][*:0]u8, @ptrCast(@alignCast(raw.ptr + args_bytestart)))[0..args_len];
            const buf = raw[buf_start..];
            assert(buf.len == buf_len);

            switch (args_get(args.ptr, buf.ptr)) {
                .SUCCESS => {},
                else => |err| return os.unexpectedErrno(err),
            }
            break :alloc_args args;
        };
        return .{ .args = args, .allocator = allocator };
    }

    pub fn next(it: *IteratorWasi) ?[:0]const u8 {
        if (it.index == it.args.len) return null;
        const arg = mem.span(it.args[it.index]);
        it.index += 1;
        return arg;
    }

    pub fn skip(it: *IteratorWasi) bool {
        if (it.index == it.args.len) return false;
        it.index += 1;
        return true;
    }

    pub fn reset(it: *IteratorWasi) void {
        it.index = 0;
    }

    pub fn deinit(it: *IteratorWasi) void {
        const raw_len_addr = mem.alignBackward(usize, @intFromPtr(it.args.ptr) - 1, @alignOf(usize));
        const raw_len: *usize = @ptrFromInt(raw_len_addr);
        const alignment = @max(@alignOf(usize), @alignOf([*:0]u8));
        const raw = @as([*]align(alignment) const u8, @ptrCast(it.args.ptr))[0..raw_len.*];
        it.allocator.free(raw);
    }
};

pub const ResponseFileOptions = struct {
    comments: bool = false,
    single_quotes: bool = false,
};

pub fn IteratorResponseFile(comptime rsp_options: ResponseFileOptions) type {
    return struct {
        const Self = @This();

        rsp: []const u8,
        rsp_i: usize = 0,
        buf: []u8,
        buf_i: usize = 0,
        allocator: Allocator,
        stable: bool,

        pub const InitError = Allocator.Error;

        pub fn init(allocator: Allocator, rsp: []const u8, it_options: IteratorOptions) InitError!Self {
            var rsp_i: usize = 0;
            const lengths = countLengths(rsp, &rsp_i);
            const buf_len = if (it_options.stable) lengths.buf_total else lengths.buf_max;
            const buf = try allocator.alloc(u8, buf_len);

            return .{
                .rsp = rsp,
                .buf = buf,
                .allocator = allocator,
                .stable = it_options.stable,
            };
        }

        pub fn next(it: *Self) ?[:0]const u8 {
            if (encodeNext(it.rsp, &it.rsp_i, it.buf[it.buf_i..])) |arg| {
                if (it.stable) {
                    it.buf_i += arg.len + 1;
                }
                return arg;
            } else {
                return null;
            }
        }

        pub fn skip(it: *Self) bool {
            return if (it.stable)
                it.next() != null
            else
                skipNext(it.rsp, &it.rsp_i);
        }

        pub fn reset(it: *Self) void {
            it.rsp_i = 0;
            it.buf_i = 0;
        }

        pub fn deinit(it: *Self) void {
            it.allocator.free(it.buf);
        }

        fn countLengths(rsp: []const u8, rsp_i: *usize) struct {
            args: usize,
            buf_total: usize,
            buf_max: usize,
        } {
            const Counter = struct {
                rsp: []const u8,
                rsp_i: *usize,
                args: usize = 0,
                buf_current: usize = 0,
                buf_total: usize = 0,
                buf_max: usize = 0,
                fn readNextCharacter(counter: *@This()) u8 {
                    if (counter.rsp_i.* != counter.rsp.len) {
                        const c = counter.rsp[counter.rsp_i.*];
                        counter.rsp_i.* += 1;
                        return c;
                    } else {
                        return 0;
                    }
                }
                fn writeCharacter(counter: *@This(), _: u8) void {
                    counter.buf_current += 1;
                }
                fn writeBackslashes(counter: *@This(), n: usize) void {
                    counter.buf_current += n;
                }
                fn yield(counter: *@This()) bool {
                    counter.buf_current += 1;
                    counter.buf_total += counter.buf_current;
                    counter.buf_max = @max(counter.buf_max, counter.buf_current);
                    counter.buf_current = 0;
                    counter.args += 1;
                    return true;
                }
                fn eof(_: *@This()) bool {
                    return false;
                }
            };
            var counter: Counter = .{ .rsp = rsp, .rsp_i = rsp_i };
            while (parseCommandLineString(&counter, .{ .response_file = rsp_options }, rsp_i.* == 0)) {}
            return .{
                .args = counter.args,
                .buf_total = counter.buf_total,
                .buf_max = counter.buf_max,
            };
        }

        fn encodeNext(rsp: []const u8, rsp_i: *usize, buf: []u8) ?[:0]u8 {
            const Encoder = struct {
                rsp: []const u8,
                rsp_i: *usize,
                buf: []u8,
                end: usize = 0,
                fn readNextCharacter(encoder: *@This()) u8 {
                    if (encoder.rsp_i.* != encoder.rsp.len) {
                        const c = encoder.rsp[encoder.rsp_i.*];
                        encoder.rsp_i.* += 1;
                        return c;
                    } else {
                        return 0;
                    }
                }
                fn writeCharacter(encoder: *@This(), c: u8) void {
                    encoder.buf[encoder.end] = c;
                    encoder.end += 1;
                }
                fn writeBackslashes(encoder: *@This(), n: usize) void {
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
            var encoder: Encoder = .{ .rsp = rsp, .rsp_i = rsp_i, .buf = buf };
            return parseCommandLineString(&encoder, .{ .response_file = rsp_options }, rsp_i.* == 0);
        }

        fn skipNext(rsp: []const u8, rsp_i: *usize) bool {
            const Skipper = struct {
                rsp: []const u8,
                rsp_i: *usize,
                fn readNextCharacter(skipper: *@This()) u8 {
                    if (skipper.rsp_i.* != skipper.rsp.len) {
                        const c = skipper.rsp[skipper.rsp_i.*];
                        skipper.rsp_i.* += 1;
                        return c;
                    } else {
                        return 0;
                    }
                }
                fn writeCharacter(_: *@This(), _: u21) void {}
                fn writeBackslashes(_: *@This(), _: usize) void {}
                fn yield(_: *@This()) bool {
                    return true;
                }
                fn eof(_: *@This()) bool {
                    return false;
                }
            };
            var skipper: Skipper = .{ .rsp = rsp, .rsp_i = rsp_i };
            return parseCommandLineString(&skipper, .{ .response_file = rsp_options }, rsp_i.* == 0);
        }
    };
}

/// Common command-line string parsing logic shared by `Windows` and `ResponseFile`.
///
/// For `Windows`, this function faithfully replicates the parsing behavior observed in
/// `CommandLineToArgvW` with one exception: if the command-line string is empty, the iterator
/// will immediately complete without returning any arguments (whereas `CommandLineArgvW` will
/// return a single argument representing the name of the current executable).
///
/// The essential parts of the algorithm are described in Microsoft's documentation:
///
/// - <https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170#parsing-c-command-line-arguments>
/// - <https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw>
///
/// David Deley explains some additional undocumented quirks in great detail:
///
/// - <https://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES>
///
/// Non-DEL ASCII control characters terminating an unquoted first argument was discovered
/// independently by testing and observing the behavior of `CommandLineToArgvW` on Windows 10.
///
/// For `ResponseFile`, a simplified variation of the same base algorithm that also handles
/// newlines and (optionally) comments and single quotes is used.
///
fn parseCommandLineString(
    context: anytype,
    comptime mode: union(enum) {
        windows,
        response_file: ResponseFileOptions,
    },
    is_arg0: bool,
) @TypeOf(context.eof()) {
    const handle_newlines = mode != .windows;
    const handle_comments = switch (mode) {
        .windows => false,
        .response_file => |rsp| rsp.comments,
    };
    const handle_single_quotes = switch (mode) {
        .windows => false,
        .response_file => |rsp| rsp.single_quotes,
    };
    const arg0_quirks = mode == .windows;
    const unquote_quirks = mode == .windows;

    var c = context.readNextCharacter();

    if (arg0_quirks and is_arg0) {
        // The first argument (the executable name) uses different parsing rules.
        switch (c) {
            0 => {
                // Immediately complete the iterator without yielding any arguments.
                // 'CommandLineToArgvW' would return the name of the current executable here.
                return context.eof();
            },
            '"' => {
                // If the first character is a quote, read everything until the next quote
                // (then skip that quote), or until the end of the string.
                while (true) {
                    c = context.readNextCharacter();
                    switch (c) {
                        '"', 0 => return context.yield(),
                        else => context.writeCharacter(c),
                    }
                }
            },
            else => {
                // Otherwise, read everything until the next space or non-DEL ASCII control
                // character (then skip that character), or until the end of the string.
                // This means that if the command-line string starts with one of these
                // characters, the first yielded argument will be the empty string.
                while (true) : (c = context.readNextCharacter()) switch (c) {
                    0...' ' => return context.yield(),
                    else => context.writeCharacter(c),
                };
            },
        }
    }

    // Skip whitespace and comments.
    // The iterator completes if we reach the end of the string here.
    while (true) : (c = context.readNextCharacter()) switch (c) {
        0 => {
            return context.eof();
        },
        ' ', '\t', '\r', '\n' => {
            if (!handle_newlines and (c == '\r' or c == '\n')) {
                break;
            }
        },
        '#' => {
            if (!handle_comments) {
                break;
            }
            while (true) {
                c = context.readNextCharacter();
                switch (c) {
                    0 => return context.eof(),
                    '\r', '\n' => break,
                    else => {},
                }
            }
        },
        else => {
            break;
        },
    };

    // Parsing rules:
    //
    // - The end of the string always terminates the current argument.
    // - When not in 'inside_quotes' mode, whitespace terminates the current argument.
    // - 2n backslashes followed by an opening quote or matching closing quote produce
    //   n backslashes and toggle 'inside_quotes'.
    // - 2n + 1 backslashes followed by an opening quote or matching closing quote produce
    //   n backslashes followed by that quote.
    // - n backslashes not followed by a quote produce n backslashes.
    // - If 'unquote_quirks' is in effect, a quote immediately following a closing quote of the
    //   same kind is interpreted literally.
    //
    var backslashes: usize = 0;
    var inside_quotes = false;
    var quote_c: if (handle_single_quotes) @TypeOf(c) else void = if (handle_single_quotes) 0 else {};
    var after_unquote: if (unquote_quirks) bool else void = if (unquote_quirks) false else {};
    while (true) : (c = context.readNextCharacter()) switch (c) {
        0 => {
            context.writeBackslashes(backslashes);
            return context.yield();
        },
        ' ', '\t', '\r', '\n' => {
            context.writeBackslashes(backslashes);
            backslashes = 0;
            if (unquote_quirks) {
                after_unquote = false;
            }
            if (!handle_newlines and (c == '\r' or c == '\n')) {
                context.writeCharacter(c);
            } else {
                if (inside_quotes) {
                    context.writeCharacter(c);
                } else {
                    return context.yield();
                }
            }
        },
        '"', '\'' => {
            if (!handle_single_quotes and c == '\'' or
                inside_quotes and handle_single_quotes and c != quote_c or
                unquote_quirks and after_unquote and (!handle_single_quotes or c == quote_c))
            {
                context.writeBackslashes(backslashes);
                backslashes = 0;
                if (unquote_quirks) {
                    after_unquote = false;
                }
                context.writeCharacter(c);
            } else {
                const c_is_escaped_quote = backslashes % 2 != 0;
                context.writeBackslashes(backslashes / 2);
                backslashes = 0;
                if (c_is_escaped_quote) {
                    context.writeCharacter(c);
                } else {
                    if (inside_quotes) {
                        if (unquote_quirks) {
                            after_unquote = true;
                        }
                    } else {
                        if (handle_single_quotes) {
                            quote_c = c;
                        }
                    }
                    inside_quotes = !inside_quotes;
                }
            }
        },
        '\\' => {
            backslashes += 1;
            if (unquote_quirks) {
                after_unquote = false;
            }
        },
        else => {
            context.writeBackslashes(backslashes);
            backslashes = 0;
            if (unquote_quirks) {
                after_unquote = false;
            }
            context.writeCharacter(c);
        },
    };
}

pub const SerializeOptions = struct {
    sentinel: ?u0 = 0,
    allow_embedded_sentinels: bool = false,
};

pub fn serializeWindows(
    allocator: Allocator,
    args: anytype,
    comptime options: SerializeOptions,
) Allocator.Error!(if (options.sentinel) |z| [:z]u16 else []u16) {
    _ = allocator;
    _ = args;
}

pub fn serializeResponseFile(
    allocator: Allocator,
    args: anytype,
    comptime options: SerializeOptions,
) Allocator.Error!(if (options.sentinel) |z| [:z]u8 else []u8) {
    _ = allocator;
    _ = args;
}
