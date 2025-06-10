# DLL Loader

Loads a DLL into the current process using `LoadLibraryA`. Provide the DLL path as a command line argument and compile with `zig build`.

To test the DLL injection, change directory to `zig-out/bin` and run the following command.

```ps1
.\dll.exe .\payload_dll.dll
```

> [!IMPORTANT]
> This includes Windows API so it should be run on Windows
