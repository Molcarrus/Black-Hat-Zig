# XOR Encryption

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Basic-Payload-Management/Payload-Encryption/XOR)

Exclusive OR (XOR) encryption is one of the simplest ways to obfuscate data.
Each byte of the payload is XORed with a key value. Applying the same operation
again restores the original bytes. While trivial to reverse if the key is known,
XOR still hides clear text strings and shellcode from basic scans. The chapter
shows two XOR routines—one that incorporates the byte index and another that
uses a multi-byte key—to demonstrate how attackers might protect their payloads
without resorting to heavy cryptography.

## Using Standard Library

```zig title="main.zig"
const std = @import("std");

/// This is the first approach to encrypt the payload.
/// We add the index "i" to each iteration to make the encryption
/// more complicated.
fn xorWithKeyAndIndex(payload: []u8, key: u8) void {
    for (payload, 0..) |*byte, i| {
        // Truncate i to u8 (i mod 256), then do wrapping add with key (overflow in the sum),
        // finally XOR the result with the payload byte.
        byte.* = byte.* ^ (key +% @as(u8, @truncate(i)));
    }
}

/// This is the second approach to encrypt the payload.
/// We use a multi-bytes key and iterate each byte as different
/// key in each iteration.
fn xorWithMultiBytesKey(payload: []u8, key: []const u8) void {
    const key_len = key.len;
    if (key_len == 0) @panic("Key length must be greater than 0"); // Division by zero

    var j: usize = 0;
    for (payload) |*byte| {
        byte.* = byte.* ^ key[j];
        j += 1;
        if (j >= key_len) {
            j = 0;
        }
    }
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var payload1 = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50 };
    const key1: u8 = 0xAA;
    try stdout.print("[+] Original payload1: {any}\n", .{payload1});
    // Encrypt
    xorWithKeyAndIndex(payload1[0..], key1);
    try stdout.print("[+] After xorByIKeys with key {X}: {any}\n", .{ key1, payload1 });
    // Decrypt
    xorWithKeyAndIndex(payload1[0..], key1);
    try stdout.print("[+] Restored payload1: {any}\n\n", .{payload1});

    var payload2 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const key2 = [_]u8{ 0x10, 0x20, 0x30 };
    try stdout.print("[+] Original payload2: {any}\n", .{payload2});
    // Encrypt
    xorWithMultiBytesKey(payload2[0..], key2[0..]);
    try stdout.print("[+] After xorByInputKey with key {any}: {any}\n", .{ key2, payload2 });
    // Decrypt
    xorWithMultiBytesKey(payload2[0..], key2[0..]);
    try stdout.print("[+] Restored payload2: {any}\n", .{payload2});
}
```
