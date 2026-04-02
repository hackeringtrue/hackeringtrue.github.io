---
layout: post
title: (Kernel Security) level 2
categories: pwn.college Kernel-Security
date: 2026-04-01 07:02:17 +0300
tags: pwn.college Device-Driver-CHAR simple-driver
---
## Information

- category: pwn

## Description
>
> Ease into kernel exploitation with another crackme level.

## Explit

Another copy-paste scheme level U_u.

```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main() {
  int fd = open("/proc/pwncollege", O_RDWR);
  printf("Driver opened.\n");
  char pass[16] = "zcexibhdcclcottw";
  write(fd, pass, 16);
  printf("Password sent.\n");
  return 0;
}
```
