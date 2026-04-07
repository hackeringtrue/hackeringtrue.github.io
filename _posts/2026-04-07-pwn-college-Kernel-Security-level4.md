---
layout: post
title: (Kernel Security) level 4
categories: pwn.college Kernel-Security
date: 2026-04-07 11:02:17 +0300
tags: pwn.college Device-Driver-CHAR simple-driver kernel-privilage-ring0
---
## Information

- category: pwn

## Description
>
> Ease into kernel exploitation with another crackme level and learn how kernel devices communicate.

## Explit

~~I think I should try to get ```Hacker``` rank on HTB U_U.~~
When I finish this module I'll try why not O_O.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main() {
  int fd = open("/proc/pwncollege", O_RDWR);
  printf("UID BEFORE: %d\n", getuid());
  ioctl(fd, 1337, "jwerkvvpqgkxvazf");
  printf("UID AFTER: %d", getuid());
  system("cat /flag");
}
```
