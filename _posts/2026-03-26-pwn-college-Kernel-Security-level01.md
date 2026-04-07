---
layout: post
title: (Kernel Security) level 1
categories: pwn.college Kernel-Security
date: 2026-03-26 07:02:17 +0300
tags: pwn.college Device-Driver-CHAR simple-driver
---
## Information

- category: pwn

## Description
>
> Ease into kernel exploitation with this simple crackme level!

## Explit

Just We need to look at module challenge using ghidra then find the correct pass O_o. No good write-ups am busy !

```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
  printf("FIRST OPEN DRIVER:\n");
  int fd = open("/proc/pwncollege", O_RDWR);
  printf("SEND CORRECT PASS:\n");
  char flag[16] = "snceewqvyntlwfha";
  write(fd, flag, 16);
  printf("TRY GET FLAG:\n");
  read(fd, flag, 15);

  puts(flag);
}
```
