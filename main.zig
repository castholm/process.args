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

    std.debug.print("process.args.alloc\n", .{});
    {
        const args = try process.args.allocSlice(gpa);
        defer process.args.freeSlice(gpa, args);

        for (args, 0..) |arg, i| {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }

    std.debug.print("process.args.iterator\n", .{});
    {
        var args = try process.args.iterator(gpa, .{ .stable = false });
        defer args.deinit();

        while (args.skip()) {}
        args.reset();

        var i: usize = 0;
        while (args.next()) |arg| : (i += 1) {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }

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

    std.debug.print("process.args.allocSliceResponseFile\n", .{});
    {
        const args = try process.args.allocSliceResponseFile(.{
            .comments = true,
            .single_quotes = true,
        }, gpa, rsp);
        defer process.args.freeSlice(gpa, args);

        for (args, 0..) |arg, i| {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }

    std.debug.print("process.args.Iterator.ResponseFile\n", .{});
    {
        var args = try process.args.IteratorResponseFile(.{
            .comments = true,
            .single_quotes = true,
        }).init(gpa, rsp, .{ .stable = false });
        defer args.deinit();

        while (args.skip()) {}
        args.reset();

        var i: usize = 0;
        while (args.next()) |arg| : (i += 1) {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }
}
