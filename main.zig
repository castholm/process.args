const std = @import("std");

const process = struct {
    const args = @import("args.zig");
};

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{ .verbose_log = true }) = .{};
    defer std.debug.assert(gpa_state.deinit() == .ok);

    const gpa = gpa_state.allocator();

    const args = try process.args.alloc(gpa);
    defer process.args.free(gpa, args);

    for (args, 0..) |arg, i| {
        std.debug.print("args[{}]: \"{}\"\n", .{ i, std.zig.fmtEscapes(arg) });
    }
}
