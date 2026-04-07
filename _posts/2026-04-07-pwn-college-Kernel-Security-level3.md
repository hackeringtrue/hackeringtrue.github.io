---
layout: post
title: (Kernel Security) level 3
categories: pwn.college Kernel-Security
date: 2026-04-07 10:02:17 +0300
tags: pwn.college Device-Driver-CHAR simple-driver kernel-privilage-ring0
---
## Information

- category: pwn

## Description
>
> Ease into kernel exploitation with another crackme level, this time with some privilege escalation (whoami?).

## Explit

Call win function by send correct password, then spawn ```"/bin/sh"```.

```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
  int fd = open("/proc/pwncollege", O_RDWR);
  printf("UID BEFORE:%d", getuid());
  write(fd, "dylgcsgflojsupql", 16);
  printf("\nUID AFTER:%d", getuid());
  execl("/bin/sh", "/bin/sh", 0);
}
```
