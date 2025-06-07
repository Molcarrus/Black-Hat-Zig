const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

// Windows API functions
extern "kernel32" fn LoadLibraryA([*:0]const u8) callconv(.C) ?windows.HMODULE;
extern "kernel32" fn GetCurrentProcessId() callconv(.C) windows.DWORD;
extern "kernel32" fn GetLastError() callconv(.C) windows.DWORD;
extern "kernel32" fn FreeLibrary(hLibModule: windows.HMODULE) callconv(.C) windows.BOOL;
extern "kernel32" fn GetModuleFileNameA(hModule: ?windows.HMODULE, lpFilename: [*]u8, nSize: windows.DWORD) callconv(.C) windows.DWORD;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        print("[!] Missing Argument; Dll Payload To Run \n", .{});
        print("Usage: {s} <dll_path>\n", .{args[0]});
        std.process.exit(1);
    }

    const dll_path = args[1];
    const current_pid = GetCurrentProcessId();

    print("[i] Injecting \"{s}\" To The Local Process Of Pid: {d} \n", .{ dll_path, current_pid });

    // Check if DLL file exists and get full path
    var full_path_buf: [windows.PATH_MAX_WIDE]u8 = undefined;
    const full_path = std.fs.cwd().realpath(dll_path, &full_path_buf) catch |err| {
        print("[!] Cannot access DLL file \"{s}\": {}\n", .{ dll_path, err });
        print("[!] Make sure the file exists and is in the current directory\n", .{});
        std.process.exit(1);
    };

    print("[+] Full DLL path: {s}\n", .{full_path});
    print("[+] Loading Dll... ", .{});

    // Convert to null-terminated string for Windows API
    const dll_path_z = try allocator.dupeZ(u8, full_path);
    defer allocator.free(dll_path_z);

    if (LoadLibraryA(dll_path_z.ptr)) |handle| {
        print("SUCCESS!\n", .{});
        print("[+] DLL Handle: 0x{x}\n", .{@intFromPtr(handle)});

        // Verify the loaded module
        var module_name: [windows.MAX_PATH]u8 = undefined;
        const name_len = GetModuleFileNameA(handle, &module_name, windows.MAX_PATH);
        if (name_len > 0) {
            print("[+] Loaded module: {s}\n", .{module_name[0..name_len]});
        }

        print("[+] DLL loaded successfully! Waiting for payload execution...\n", .{});

        // Give the DLL time to execute
        std.time.sleep(2 * std.time.ns_per_s); // Wait 2 seconds

        // Keep the DLL loaded for a bit longer
        print("[+] Press <Enter> to unload DLL and exit... ", .{});
        _ = std.io.getStdIn().reader().readByte() catch {};

        // Unload the DLL
        if (FreeLibrary(handle) != 0) {
            print("[+] DLL unloaded successfully\n", .{});
        } else {
            print("[!] Failed to unload DLL\n", .{});
        }

        print("[+] DONE!\n", .{});
    } else {
        const error_code = GetLastError();
        print("FAILED!\n", .{});
        print("[!] LoadLibraryA Failed With Error: {d}\n", .{error_code});

        // Print common error meanings
        switch (error_code) {
            2 => print("    → The system cannot find the file specified\n", .{}),
            3 => print("    → The system cannot find the path specified\n", .{}),
            126 => print("    → The specified module could not be found\n", .{}),
            193 => print("    → Not a valid Win32 application\n", .{}),
            else => print("    → Unknown error\n", .{}),
        }
        std.process.exit(1);
    }
}
