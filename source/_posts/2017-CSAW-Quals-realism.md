---
title: 2017-CSAW-Quals-realism
date: 2018-08-30 22:09:36
tags: [ctf, re, wp]
---

学习 z3 时复现的一道题，了解了 SSE 指令以及学习了 gdb 和 qemu 之间的调试。

<!-- more -->

# Analysis

```bash
$ file main.bin
main.bin: DOS/MBR boot sector
```

题目给的是一个 DOS 程序，直接拖进 IDA，以 16 位的模式打开。定位到一处检测字符串前缀的代码，基本可以判断出 1234h 即我们输入的字符串在内存中的地址。

```
seg000:006F                 cmp     dword ptr ds:1234h, 'galf'
seg000:0078                 jnz     loc_14D
seg000:007C                 movaps  xmm0, xmmword ptr ds:1238h
seg000:0081                 movaps  xmm5, xmmword ptr ds:7C00h
seg000:0086                 pshufd  xmm0, xmm0, 1Eh
```

因为 IDA 不能反编译，所以基本上是直接看汇编，那么需要稍微了解一下 [SSE 指令](https://www.jianshu.com/p/64ef4d304e17)。

|   指令   |                                                                                作用                                                                                 |
| :------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| `MOVAPS` |                                            把源存储器内容值送入目的寄存器。当有 m128 时, 内存地址必须是 16 字节对齐的。                                             |
| `PSHUFD` | 有三个操作数，从左往右，第一个操作数是目的操作数保存结果，第二个操作数是源操作数，第三个操作数是一个 8 位立即数，指定以怎样的顺序将源操作数中数据保存到目的操作数。 |
| `ANDPS`  |                                                                               按位与                                                                                |
| `PSADBW` |                                                                            绝对差值求和                                                                             |

接下来的汇编部分有一些小复杂，动态调试会比较清晰。先用 qemu 启动程序（-s 参数开启远程调试服务）：

```bash
qemu-system-i386 -drive format=raw,file=main.bin -s
```

gdb 进行远程连接，并设置指令架构，同时在比较完 flag 前缀后设下断点（MBR 的加载地址是 0x7C00）：

```bash
gdb -ex 'target remote localhost:1234' \
    -ex 'set architecture i8086' \
    -ex 'break *0x7c6f' \
    -ex 'continue'
```

然后在程序中输入字符串，以 flag 为前缀，后面的部分用 a 到 p 来填充：

![](/pics/2017-CSAW-Quals-realism/1.png)

输入完成后我们可以看到 gdb 断了下来，此时可以开始和 IDA 对照着调试。可能是因为指令的结构不一样，所以 gdb 中只有当前指向的指令是基本正确的（有时可能也不正确，还是要看 IDA 的汇编）。同时在每次对 xmm 寄存器操作后，可以使用 p 命令输出并查看寄存器中的值。

![](/pics/2017-CSAW-Quals-realism/2.png)

首先单步调一下，看看两条 movaps 指令：

```
seg000:007C                 movaps  xmm0, xmmword ptr ds:1238h
seg000:0081                 movaps  xmm5, xmmword ptr ds:7C00h
```

单步后可以看到 xmm0 中存放了我们输入的字符串中 flag 之后的部分（我是在 mac 下调试的，gdb 中可能有点 bug，寄存器存的值明显偏了 32 位）。接着执行下一条指令，可以看出 xmm5 中存放了内存中另一段的数据，可以打印出来看看：

```
gef> p $xmm5
$6 = {
  v4_float = {-2.50091934, -1.48039995e-36, 1.93815862e-18, 0},
  v2_double = {-1.787847107871084e-289, 2.8231360405480285e-315},
  v16_int8 = {0x10, 0xf, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x2, 0xf, 0x22, 0x0, 0x0, 0x0, 0x0},
  v8_int16 = {0xf10, 0xc020, 0xe083, 0x83fb, 0x2c8, 0x220f, 0x0, 0x0},
  v4_int32 = {0xc0200f10, 0x83fbe083, 0x220f02c8, 0x0},
  v2_int64 = {0x83fbe083c0200f10, 0x220f02c8},
  uint128 = 0x220f02c883fbe083c0200f10
}
gef> p $xmm4
$7 = {
  v4_float = {0, 0, 0, -134298496},
  v2_double = {0, -8.2671312985563202e+62},
  v16_int8 = {0x0 <repeats 12 times>, 0xb8, 0x13, 0x0, 0xcd},
  v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13b8, 0xcd00},
  v4_int32 = {0x0, 0x0, 0x0, 0xcd0013b8},
  v2_int64 = {0x0, 0xcd0013b800000000},
  uint128 = 0xcd0013b8000000000000000000000000
}
```

```
seg000:0086                 pshufd  xmm0, xmm0, 1Eh
seg000:008B                 mov     si, 8
```

接下来单步执行 pshufd 这条指令。不关注 pshufd 的具体作用的话，可以在调试中看到，运行过后发现 xmm0 中的值从 0x706f6e6d6c6b6a696867666564636261 变成了 0x6463626168676665706f6e6d6c6b6a69，数据的顺序变化了。然后将 si 置为 8，在后面的调试中可以判断出，si 中存放的为循环次数。

```
seg000:008E                 movaps  xmm2, xmm0
seg000:0091                 andps   xmm2, xmmword ptr [si+7D90h]
```

接下来两条指令分别将 xmm0 赋给 xmm2 以及将 xmm2 和内存中的一段数据按位与。看一看到 xmm2 中的值即为变化后的输入：

```
gef> p $xmm2
$2 = {
  v4_float = {2.96401656e+29, 4.37102201e+24, 1.67779994e+22, 0},
  v2_double = {8.5408834851248547e+194, 8.3212257841951935e-315},
  v16_int8 = {0x6d, 0x6e, 0x6f, 0x70, 0x65, 0x66, 0x67, 0x68, 0x61, 0x62, 0x63, 0x64, 0x0, 0x0, 0x0, 0x0},
  v8_int16 = {0x6e6d, 0x706f, 0x6665, 0x6867, 0x6261, 0x6463, 0x0, 0x0},
  v4_int32 = {0x706f6e6d, 0x68676665, 0x64636261, 0x0},
  v2_int64 = {0x68676665706f6e6d, 0x64636261},
  uint128 = 0x6463626168676665706f6e6d
}
gef> p $xmm1
$3 = {
  v4_float = {0, 0, 0, 1.1384003e+27},
  v2_double = {0, 1.8458895617341177e+214},
  v16_int8 = {0x0 <repeats 12 times>, 0x69, 0x6a, 0x6b, 0x6c},
  v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6a69, 0x6c6b},
  v4_int32 = {0x0, 0x0, 0x0, 0x6c6b6a69},
  v2_int64 = {0x0, 0x6c6b6a6900000000},
  uint128 = 0x6c6b6a69000000000000000000000000
}
```

查看内存中的数据，可以看到和输入按位与之后，会把对应为 0x00 两个字节给抹掉。并通过下面的分析可以知道总共会有 8 次循环，每次进行按位与的数据是不同的，即每次的数据会左移 4 位：

```
gef> x/2gx 0x7D98
0x7d98:	0xffffffffffffff00	0xffffffffffffff00
gef> x/2gx 0x7D97
0x7d97:	0xffffffffffff00ff	0xffffffffffff00ff
gef> x/2gx 0x7D96
0x7d96:	0xffffffffff00ffff	0xffffffffff00ffff
gef> x/2gx 0x7D95
0x7d95:	0xffffffff00ffffff	0xffffffff00ffffff
gef> x/2gx 0x7D94
0x7d94:	0xffffff00ffffffff	0xffffff00ffffffff
gef> x/2gx 0x7D93
0x7d93:	0xffff00ffffffffff	0xffff00ffffffffff
gef> x/2gx 0x7D92
0x7d92:	0xff00ffffffffffff	0xff00ffffffffffff
gef> x/2gx 0x7D91
0x7d91:	0x00ffffffffffffff	0x00ffffffffffffff
```

接着看 psadbw 这条指令，这里将 xmm5 和 xmm2 中的数据进行绝对差值求和（每 64 位的数据逐字节相减，将结果相加后存到前一个操作数中）。接着把高低 64 位经过绝对差值求和的结果（每个结果大小为 16 位，高低两个结果共 32 位）保存到 edi 中：

```
seg000:0096                 psadbw  xmm5, xmm2
seg000:009A                 movaps  xmmword ptr ds:1268h, xmm5
seg000:009F                 mov     di, ds:1268h
seg000:00A3                 shl     edi, 10h
seg000:00A7                 mov     di, ds:1270h
```

然后将 edi 中的结果和内存里的值比较，如果不相等，会有个大跳转，IDA 里大概判断一下应该是直接跳到失败处。

```
seg000:00AB                 mov     dx, si
seg000:00AD                 dec     dx
seg000:00AE                 add     dx, dx
seg000:00B0                 add     dx, dx
seg000:00B2                 cmp     edi, [edx+7DA8h]
seg000:00BA                 jnz     loc_14D
seg000:00BE                 dec     si
seg000:00BF                 test    si, si
seg000:00C1                 jnz     short sub_8E
```

查看内存中进行比较的值，正好 8 个值，每次都进行一次判断：

```
gef> x/8wx 0x7DA8
0x7da8:	0x02110270	0x02290255	0x025e0291	0x01f90233
0x7db8:	0x027b0278	0x02090221	0x0290025d	0x02df028f
```

基本上所有的线性关系都有了，接下来交给 z3 就行了。

# Script

```python
#!/usr/bin/env python
from z3 import *

def z3_abs(x):
    return If(x >= 0, x, -x)

def psadbw(xmm0, xmm1):
    a = Sum([z3_abs(b1 - b2) for b1, b2 in zip(xmm0[:8], xmm1[:8])])
    b = Sum([z3_abs(b1 - b2) for b1, b2 in zip(xmm0[8:], xmm1[8:])])
    return a + b * 0x10000

s = Solver()
ZERO = IntVal(0)
xmm5 = '220f02c883fbe083c0200f10cd0013b8'.decode('hex')
xmm5 = [ord(c) for c in xmm5]
xmm5s = [xmm5]

xmm0 = [Int('x%d' % i) for i in range(16)]
for c in xmm0:
    s.add(c >= 32, c <= 126)

check = [0x02df028f, 0x0290025d, 0x02090221, 0x027b0278, 0x01f90233, 0x025e0291, 0x02290255, 0x02110270]
xmm5s += map(lambda e: [0, 0, 0, 0, 0, 0, (e >> 8) & 0xFF, e & 0xFF, 0, 0, 0, 0, 0, 0, e >> 24, (e >> 16) & 0xFF], check)
print xmm5s

for i in range(8):
    xmm5 = xmm5s[i]
    xmm2 = list(xmm0)
    xmm2[7 - i] = ZERO
    xmm2[15 - i] = ZERO
    res = psadbw(xmm5, xmm2)
    s.add(res == check[i])

if s.check() == sat:
    print s.model()
    flag = ''.join(chr(eval(str(s.model()[c]))) for c in xmm0)
    # pshufd xmm0, xmm0, 1Eh
    flag = 'flag' + flag[:4][::-1] + flag[4:8][::-1] + flag[12:][::-1] + flag[8:12][::-1]
    print flag
    # flag{4r3alz_m0d3_y0}
```

# References

https://fortenf.org/e/ctfs/re/2017/09/18/csaw17-realism.html
