# Black-Hat-Zig

Hello hackers. Hello maldevs. Hello reversers.

This project provides many malware techniques implementation using Zig since I'm a huge fan of it. But I'm still leaning, so please tell me if there's something wrong or can be optimized. It will be perfect if you want to create a PR for this project.

Okay, let's hack the planet!

## Table of content

1. [Payload Placement](./Payload-Placement/)
    - [.data section](./Payload-Placement/dot_data_section/)
    - [.rdata section](./Payload-Placement/dot_rdata_section/)
    - [.text section](./Payload-Placement/dot_text_section/)
    - .rsrc section
2. [Payload Obfuscation](./Payload-Obfuscation/)
    - [IP Address Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/)
        - [IPv4 Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv4Fuscation/)
        - [IPv4 Deobfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv4Fuscation/)
        - [IPv6 Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv6Fuscation/)
        - [IPv6 Deobfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv6Deobfuscation/)
3. Payload Encryption
    - XOR Encryption
    - RC4 Encryption
    - AES Encryption

## Usage

You can check the codes inside each directory. Also, if the code uses Windows API, remember to compile it with `-Dtarget=x86_64-windows` flag. So following are commands to copy and paste.

**Normal binary**

```
zig build
```

**Binaries contain Window API**

```
zig build -Dtarget=x86_64-windows
```

## Contribution

This project is currently maintained by [@CX330Blake](https://github.com/CX330Blake). PRs are welcomed. Hope there's more people use Zig for malware developing so the ecosystem will be more mature.
