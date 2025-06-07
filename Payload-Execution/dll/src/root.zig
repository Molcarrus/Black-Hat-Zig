const std = @import("std");
const windows = std.os.windows;

// Windows API constants
const MB_OK = 0x00000000;
const MB_ICONINFORMATION = 0x00000040;

// DLL reasons
const DLL_PROCESS_ATTACH: windows.DWORD = 1;
const DLL_THREAD_ATTACH: windows.DWORD = 2;
const DLL_THREAD_DETACH: windows.DWORD = 3;
const DLL_PROCESS_DETACH: windows.DWORD = 0;

// External Windows API functions
extern "user32" fn MessageBoxA(
    hWnd: ?windows.HWND,
    lpText: [*:0]const u8,
    lpCaption: [*:0]const u8,
    uType: windows.UINT,
) callconv(.C) i32;

fn msgBoxPayload() void {
    _ = MessageBoxA(
        null,
        "Please give Black-Hat-Zig a star!",
        "Zig!",
        MB_OK | MB_ICONINFORMATION,
    );
}

export fn DllMain(
    hModule: windows.HMODULE,
    dwReason: windows.DWORD,
    lpReserved: windows.LPVOID,
) callconv(.C) windows.BOOL {
    _ = hModule; // Unused parameter
    _ = lpReserved; // Unused parameter

    switch (dwReason) {
        DLL_PROCESS_ATTACH => {
            msgBoxPayload();
        },
        DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH => {
            // Do nothing
        },
        else => {},
    }

    return 1; // TRUE
}
