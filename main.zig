const std = @import("std");
const builtin = @import("builtin");

const process = struct {
    const args = @import("args.zig");
};

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{ .verbose_log = true }) = .{};
    defer std.debug.assert(gpa_state.deinit() == .ok);

    const gpa = gpa_state.allocator();

    if (builtin.os.tag == .windows) {
        std.debug.print("{}\n", .{std.unicode.fmtUtf16Le(std.mem.span(std.os.windows.kernel32.GetCommandLineW()))});
    }

    //std.debug.print("process.args.alloc\n", .{});
    //{
    //    const args = try process.args.alloc(gpa);
    //    defer process.args.free(gpa, args);

    //    for (args[@min(args.len, 1)..], 1..) |arg, i| {
    //        std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
    //    }
    //}

    std.debug.print("process.args.iterator\n", .{});
    {
        var args = try process.args.iterator(gpa);
        defer args.deinit();

        while (args.skip()) {}
        args.reset();

        var i: usize = 0;
        while (args.next()) |arg| : (i += 1) {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }

    std.debug.print("process.args.Iterator.ResponseFile\n", .{});
    {
        const rsp =
            \\hello world #yolo
            \\# this is a comment
            \\  # this is also a comment
            \\abc # this is now also a comment
            \\"new
            \\line"
            \\'new
            \\line'
            \\"a b\" c\\" 'a b\' c\\'
        ;
        var args = try process.args.Iterator.ResponseFile(.{
            .comments = true,
            .single_quotes = true,
        }).init(gpa, rsp);
        defer args.deinit();

        while (args.skip()) {}
        args.reset();

        var i: usize = 0;
        while (args.next()) |arg| : (i += 1) {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }
}
