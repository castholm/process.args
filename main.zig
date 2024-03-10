const std = @import("std");

const process = struct {
    const args = @import("args.zig");
};

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{ .verbose_log = true }) = .{};
    defer std.debug.assert(gpa_state.deinit() == .ok);

    const gpa = gpa_state.allocator();
    {
        const args = try process.args.alloc(gpa);
        defer process.args.free(gpa, args);

        for (args[@min(args.len, 1)..], 1..) |arg, i| {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
        }
    }

    {
        var args = try process.args.iterator(gpa);
        defer args.deinit();

        _ = args.skip();
        var i: usize = 1;
        while (args.next()) |arg| {
            std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
            i += 1;
        }
    }
}
