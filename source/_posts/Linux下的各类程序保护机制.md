---
title: Linux下的各类程序保护机制
date: 2020-03-06 18:59:35
tags: [ctf, pwn]
---

之前一直在做逆向，快一年没碰 PWN 了，接下来有一堆比赛，赶紧重新 PWN 起来。这里先整理一下 Linux 下的程序保护机制。

<!-- more -->

# Environment

Linux 版本：

```bash
$ uname -a
Linux ubuntu 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

GCC 版本：

```bash
$ gcc --version
gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

# Checksec

[Checksec](https://github.com/slimm609/checksec.sh/) 是用 Shell 编写的一个脚本，它可以用来检查可执行文件属性，例如 PIE, RELRO, PaX, Canaries, ASLR, Fortify Source 等等属性。

![](/pics/Linux下的各类程序保护机制/1.png)

# Cannary

Canary 表示栈保护功能是否开启。栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让 Shellcode 能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈里插入 Cookie 信息，当函数真正返回的时候会验证 Cookie 信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将 Cookie 信息给覆盖掉，导致栈保护检查失败而阻止 Shellcode 的执行。在 Linux 中将 Cookie 信息称为 Canary。

gcc 在 4.2 版本中添加了 `-fstack-protector` 和 `-fstack-protector-all` 编译参数以支持栈保护功能，4.9 新增了 `-fstack-protector-strong` 编译参数让保护的范围更广。故在编译时可以控制是否开启栈保护以及程度。

测试代码：

```cpp
#include <stdio.h>

int main() {
	char buf[20];
	gets(buf);
	return 0;
}
```

## Default（`-fstack-protector`）

默认情况下，开启了 Cannary 保护（即 `-fstack-protector` 参数），一开始会在栈上存储 Cannary（`QWORD PTR fs:0x28`），在程序结束时通过异或检查栈上的值是否正确来检查 Cannary 是否被篡改，如果不正确则调用 `__stack_chk_fail()` 产生报错：

```asm
0000000000400596 <main>:
  400596:	55                   	push   rbp
  400597:	48 89 e5             	mov    rbp,rsp
  40059a:	48 83 ec 20          	sub    rsp,0x20
  40059e:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4005a5:	00 00
  4005a7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4005ab:	31 c0                	xor    eax,eax
  4005ad:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  4005b1:	48 89 c7             	mov    rdi,rax
  4005b4:	b8 00 00 00 00       	mov    eax,0x0
  4005b9:	e8 c2 fe ff ff       	call   400480 <gets@plt>
  4005be:	b8 00 00 00 00       	mov    eax,0x0
  4005c3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  4005c7:	64 48 33 14 25 28 00 	xor    rdx,QWORD PTR fs:0x28
  4005ce:	00 00
  4005d0:	74 05                	je     4005d7 <main+0x41>
  4005d2:	e8 89 fe ff ff       	call   400460 <__stack_chk_fail@plt>
  4005d7:	c9                   	leave
  4005d8:	c3                   	ret
```

## `-fno-stack-protector`

`-fstack-protector` 参数取消对栈的保护，直接编译成程序所对应的汇编：

```asm
0000000000400526 <main>:
  400526:	55                   	push   rbp
  400527:	48 89 e5             	mov    rbp,rsp
  40052a:	48 83 ec 20          	sub    rsp,0x20
  40052e:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  400532:	48 89 c7             	mov    rdi,rax
  400535:	b8 00 00 00 00       	mov    eax,0x0
  40053a:	e8 d1 fe ff ff       	call   400410 <gets@plt>
  40053f:	b8 00 00 00 00       	mov    eax,0x0
  400544:	c9                   	leave
  400545:	c3                   	ret
```

# NX（DEP）

NX 即 No-eXecute（不可执行）的意思，NX（即 Windows 下的 DEP，数据执行保护）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入 Shellcode 时，程序会尝试在数据页面上执行指令，此时 CPU 就会抛出异常，而不是去执行恶意指令。

## Default（`-z noexecstack`）

默认开始 NX，栈上的数据不可执行：

```gdb
assassinq$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/beale/Test_Dir/main
0x00600000         0x00601000         r--p	/home/beale/Test_Dir/main
0x00601000         0x00602000         rw-p	/home/beale/Test_Dir/main
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdd000 0x00007ffff7fe0000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

## `-z execstack`

开启栈可执行后，栈上的代码可被执行，同时其他处内存部分都是读写执行全开：

```gdb
assassinq$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/beale/Test_Dir/main
0x00600000         0x00601000         r-xp	/home/beale/Test_Dir/main
0x00601000         0x00602000         rwxp	/home/beale/Test_Dir/main
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rwxp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rwxp	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdd000 0x00007ffff7fe0000 rwxp	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

# PIE（ASLR）

一般情况下 NX 和地址空间分布随机化（ASLR）会同时工作。[ASLR 不负责代码段以及数据段的随机化工作，这项工作由 PIE 负责；但是只有在开启 ASLR 之后，PIE 才会生效。](https://blog.csdn.net/spenghui/article/details/79910884)内存地址随机化机制（Address Space Layout Randomization)，有以下三种情况（具体的 ASLR 和 PIE 的互相作用：https://www.cnblogs.com/rec0rd/p/7646857.html）：

1. 0 - 表示关闭进程地址空间随机化。
2. 1 - 表示将 mmap 的基址，stack 和 Vdso 页面随机化。
3. 2 - 表示在 1 的基础上增加 heap 的随机化。

可以防范基于 ret2libc 方式的针对 DEP 的攻击。ASLR 和 DEP 配合使用，能有效阻止攻击者在堆栈上运行恶意代码。位置独立的可执行区域（Position-Independent Executables）使得在利用缓冲溢出和移动操作系统中存在的其他内存崩溃缺陷时采用面向返回的编程（Return-Oriented Programming）方法变得难得多。

> Linux 关闭 PIE 的方法：
>
> ```bash
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
> ```

## Default（`-no-pie`）

默认不开启。静态分析程序时所得到的地址都是运行时的真实地址，基地址为 0x400000：

```asm
0000000000400526 <main>:
  400526:	55                   	push   rbp
  400527:	48 89 e5             	mov    rbp,rsp
  40052a:	bf c4 05 40 00       	mov    edi,0x4005c4
  40052f:	e8 cc fe ff ff       	call   400400 <puts@plt>
  400534:	b8 00 00 00 00       	mov    eax,0x0
  400539:	5d                   	pop    rbp
  40053a:	c3                   	ret
```

与 gdb 调试的时候相同：

```gdb
───────────────────────────────────── Code ─────────────────────────────────────
   0x400521 <frame_dummy+33>:	jmp    0x4004a0 <register_tm_clones>
   0x400526 <main>:	push   rbp
   0x400527 <main+1>:	mov    rbp,rsp
=> 0x40052a <main+4>:	mov    edi,0x4005c4
   0x40052f <main+9>:	call   0x400400 <puts@plt>
   0x400534 <main+14>:	mov    eax,0x0
   0x400539 <main+19>:	pop    rbp
   0x40053a <main+20>:	ret
```

## `-pie`

`-fpie` 与 `-fPIE` 效果一样，用于编译；`-pie` 用于链接。开启 PIE 后的静态反编译结果没有基地址，每次运行时的基地址不同：

```asm
0000000000000750 <main>:
 750:	55                   	push   rbp
 751:	48 89 e5             	mov    rbp,rsp
 754:	48 8d 3d 99 00 00 00 	lea    rdi,[rip+0x99]        # 7f4 <_IO_stdin_used+0x4>
 75b:	e8 90 fe ff ff       	call   5f0 <puts@plt>
 760:	b8 00 00 00 00       	mov    eax,0x0
 765:	5d                   	pop    rbp
 766:	c3                   	ret
```

gdb 调试时如下：

```gdb
───────────────────────────────────── Code ─────────────────────────────────────
   0x55555555474b <frame_dummy+43>:
    jmp    0x555555554690 <register_tm_clones>
   0x555555554750 <main>:	push   rbp
   0x555555554751 <main+1>:	mov    rbp,rsp
=> 0x555555554754 <main+4>:	lea    rdi,[rip+0x99]        # 0x5555555547f4
   0x55555555475b <main+11>:	call   0x5555555545f0 <puts@plt>
   0x555555554760 <main+16>:	mov    eax,0x0
   0x555555554765 <main+21>:	pop    rbp
   0x555555554766 <main+22>:	ret
[rip+0x99] : 0x5555555547f4 ("Hello World")
```

# RELRO

在 Linux 系统安全领域数据可以写的存储区就会是攻击的目标，尤其是存储函数指针的区域。所以在安全防护的角度来说尽量减少可写的存储区域对安全会有极大的好处。GCC、GNU linker 以及 Glibc-dynamic linker 一起配合实现了一种叫做 relro（Read Only Relocation）的技术。大概实现就是由 linker 指定程序的一块经过 dynamic linker 处理过 relocation 之后的区域为只读.

设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对 GOT 攻击。RELRO 为 Partial RELRO，说明对 GOT 表具有写权限。

## Default（`-z lazy`）

默认情况下对 GOT 表具有写权限。可以看到 `puts` 和 `_libc_start_main` 所在的内存部分是可写的：

```gdb
assassinq$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
assassinq$ got

/home/beale/Test_Dir/main:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000600ff8 R_X86_64_GLOB_DAT  __gmon_start__
0000000000601018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000601020 R_X86_64_JUMP_SLOT  __libc_start_main@GLIBC_2.2.5

assassinq$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/beale/Test_Dir/main
0x00600000         0x00601000         r--p	/home/beale/Test_Dir/main
0x00601000         0x00602000         rw-p	/home/beale/Test_Dir/main
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdd000 0x00007ffff7fe0000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

## `-z norelro`

没有开启 RELRO 的情况：

```gdb
assassinq$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled
assassinq$ got

/home/beale/Test_Dir/main:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
00000000006008a8 R_X86_64_GLOB_DAT  __gmon_start__
00000000006008c8 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
00000000006008d0 R_X86_64_JUMP_SLOT  __libc_start_main@GLIBC_2.2.5

assassinq$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/beale/Test_Dir/main
0x00600000         0x00601000         rw-p	/home/beale/Test_Dir/main
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdd000 0x00007ffff7fe0000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

## `-z now`

此时无法修改 GOT 表。`puts` 和 `_libc_start_main` 所在的内存部分只有读权限：

```gdb
assassinq$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
assassinq$ got

/home/beale/Test_Dir/main:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000600fe8 R_X86_64_GLOB_DAT  puts@GLIBC_2.2.5
0000000000600ff0 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
0000000000600ff8 R_X86_64_GLOB_DAT  __gmon_start__

assassinq$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/beale/Test_Dir/main
0x00600000         0x00601000         r--p	/home/beale/Test_Dir/main
0x00601000         0x00602000         rw-p	/home/beale/Test_Dir/main
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdd000 0x00007ffff7fe0000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

# Conclusion

各种安全选择的编译参数如下：

- NX：`-z execstack` / `-z noexecstack` (关闭 / 开启)
- Canary：`-fno-stack-protector` / `-fstack-protector` / `-fstack-protector-all` (关闭 / 开启 / 全开启)
- PIE：`-no-pie` / `-pie` (关闭 / 开启)
- RELRO：`-z norelro` / `-z lazy` / `-z now` (关闭 / 部分开启 / 完全开启)

![](/pics/Linux下的各类程序保护机制/2.png)

# References

http://www.gandalf.site/2019/03/linux-pwn.html
https://stackoverflow.com/questions/24465014/gcc-generate-canary-or-not
https://stackoverflow.com/questions/2463150/what-is-the-fpie-option-for-position-independent-executables-in-gcc-and-ld
https://richardustc.github.io/2013-05-21-2013-05-21-pie.html
http://liudonghua.com/archives/2014/10/26/gcc_g++%E4%B8%AD%E7%9A%84pic%E4%B8%8Epie/
https://paper.seebug.org/481/
