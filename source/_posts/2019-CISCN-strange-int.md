---
title: 2019-CISCN-strange_int
date: 2020-01-24 16:46:38
tags: [ctf, re]
---

一道 MBR 虚拟机的题目，同时也熟悉了使用 bochs 对 MBR 的调试。

<!-- more -->

# Analysis

```
$ file Image.bin
Image.bin: DOS/MBR boot sector
```

先在 IDA 中 16 位的模式打开。在 7C00~7C0E 的代码（MBR 的加载地址是 0x7C00 处）是对寄存器和栈指针进行初始化操作；在 7C0F~7C12 的代码是 x86 系统中的第 17 号调用，设置了显示模式；在 7C14~7C24 的代码是 x86 系统中的第 20 号调用，从软盘的第 0 个磁盘第 0 个柱面第 2 个扇区开始的共 28 个扇区读取数据到内存的 10000000 处；在 7C2B~7C3B 的代码将内存中 10000000~10002000 的数据赋值给内存 0~2000 处；在 7C3D~7C47 的代码初始化 IDT 和 GDT；在 7C4C~7C52 的代码处，启动保护模式，并跳转至 32 位代码段：

```asm
MBR16:0000 sub_0           proc near
MBR16:0000                 jmp     far ptr 7C0h:5
MBR16:0000 sub_0           endp
MBR16:0000
MBR16:0005
MBR16:0005 ; =============== S U B R O U T I N E =======================================
MBR16:0005
MBR16:0005
MBR16:0005 sub_5           proc near
MBR16:0005                 mov     ax, cs
MBR16:0007                 mov     ds, ax
MBR16:0009                 assume ds:MBR16
MBR16:0009                 mov     ss, ax
MBR16:000B                 assume ss:MBR16
MBR16:000B                 mov     sp, 400h
MBR16:000E                 cld
MBR16:000F                 mov     ax, 3
MBR16:0012                 int     10h             ; - VIDEO - SET VIDEO MODE
MBR16:0012                                         ; AL = mode
MBR16:0014                 mov     dx, 0
MBR16:0017                 mov     cx, 2
MBR16:001A                 mov     ax, 1000h
MBR16:001D                 mov     es, ax
MBR16:001F                 assume es:nothing
MBR16:001F                 xor     bx, bx
MBR16:0021                 mov     ax, 228h
MBR16:0024                 int     13h             ; DISK - READ SECTORS INTO MEMORY
MBR16:0024                                         ; AL = number of sectors to read, CH = track, CL = sector
MBR16:0024                                         ; DH = head, DL = drive, ES:BX -> buffer to fill
MBR16:0024                                         ; Return: CF set on error, AH = status, AL = number of sectors read
MBR16:0026                 jnb     short loc_2A
MBR16:0028
MBR16:0028 loc_28:                                 ; CODE XREF: sub_5:loc_28↓j
MBR16:0028                 jmp     short loc_28
MBR16:002A ; ---------------------------------------------------------------------------
MBR16:002A
MBR16:002A loc_2A:                                 ; CODE XREF: sub_5+21↑j
MBR16:002A                 cli
MBR16:002B                 mov     ax, 1000h
MBR16:002E                 mov     ds, ax
MBR16:0030                 assume ds:nothing
MBR16:0030                 xor     ax, ax
MBR16:0032                 mov     es, ax
MBR16:0034                 assume es:MBR16
MBR16:0034                 mov     cx, 2000h
MBR16:0037                 sub     si, si
MBR16:0039                 sub     di, di
MBR16:003B                 rep movsb
MBR16:003D                 mov     ax, 7C0h
MBR16:0040
MBR16:0040 loc_40:                                 ; DATA XREF: sub_5+D↑r
MBR16:0040                 mov     ds, ax
MBR16:0042                 assume ds:nothing
MBR16:0042                 lidt    fword ptr ds:6Fh ; Init IDT
MBR16:0047                 lgdt    fword ptr ds:75h ; Init GDT
MBR16:004C
MBR16:004C loc_4C:                                 ; DATA XREF: sub_5+1F↑r
MBR16:004C                 mov     ax, 1            ; Start Protected Mode
MBR16:004F                 lmsw    ax               ; Jump to 32-bit Code
MBR16:004F sub_5           endp
MBR16:004F
MBR16:004F MBR16           ends
```

> ## 何为 IDT 和 GDT？
>
> ### GDT
>
> 全局描述表（Global Descriptor Table）。在实时模式下，对一个内存地址的访问是通过段寄存器的方式来进行（一个段具备两个元素：[Base Address, Limit]），即段模式。而在保护模式下（保护模式运行在 32 位系统上），内存的管理模式分为两种，段模式和页模式，其中页模式也是基于段模式的（纯段模式和段页模式）。
>
> 在保护模式下，对一个段的描述则包括 3 方面因素：[Base Address, Limit, Access]，它们加在一起被放在一个 64-bit 长的数据结构中，被称为段描述符。而段寄存器仍然是 16-bit，无法通过 16-bit 长度的段寄存器来直接引用 64-bit 的段描述符。
>
> 解决方法就是把这些长度为 64-bit 的段描述符放入一个数组即 GDT 中。当程序员通过段寄存器来引用一个段描述符时，CPU 必须知道 GDT 的入口，也就是基地址放在哪里，所以 Intel 的设计者门提供了一个寄存器 GDTR 用来存放 GDT 的入口地址，程序员将 GDT 设定在内存中某个位置之后，可以通过 LGDT 指令将 GDT 的入口地址装入此寄存器，从此以后，CPU 就根据此寄存器中的内容作为 GDT 的入口来访问 GDT 了。
>
> ### IDT
>
> 中断描述符表（Interrupt Descriptor Table），和 GDT 类似，记录了 0~255 的中断号和调用函数之间的关系。
>
> 段描述符使用数组存储，使用 LIDT 指令将 IDT 的入口地址装入 IDTR 寄存器。

接下来在 IDA 中用 32 位模式打开。一开始的一段代码对 IDT 和 GDT 进行了初始化：

```asm
seg001:00000205 sub_205         proc near
seg001:00000205                 mov     ds, eax
seg001:00000207                 lss     esp, fword ptr ds:dword_B34+28h
seg001:0000020E                 call    IDT_Init
seg001:00000213                 call    GDT_Init
seg001:00000218                 mov     eax, 10h        ; DATA XREF: sub_28B+27↓r
seg001:0000021D                 mov     ds, eax
seg001:0000021F                 assume ds:nothing
seg001:0000021F                 mov     es, eax
seg001:00000221                 assume es:nothing
seg001:00000221                 mov     fs, eax         ; DATA XREF: sub_283↓r
seg001:00000223                 assume fs:nothing
seg001:00000223                 mov     gs, eax
seg001:00000225                 assume gs:nothing
seg001:00000225                 lss     esp, large ds:0B5Ch
seg001:00000225                                         ; DATA XREF: sub_28B+11↓o
seg001:0000022C                 xor     ebx, ebx
```

IDT_init 处，先将 000800FC 赋给了 EAX，将 8E00 赋给了 DX。然后进行了一个 256 次的循环，每次循环从 00080128 的地址开始，分别存入 EAX 和 EDX。最后加载 IDTR，地址为 11C。

```asm
seg001:0000028B IDT_Init        proc near               ; CODE XREF: sub_205+9↑p
seg001:0000028B                 mov     edx, 0FCh
seg001:00000290                 mov     eax, 80000h
seg001:00000295                 mov     ax, dx
seg001:00000298                 mov     dx, 8E00h
seg001:0000029C                 lea     edi, ds:128h
seg001:000002A2                 mov     ecx, 100h
seg001:000002A7
seg001:000002A7 loc_2A7:                                ; CODE XREF: IDT_Init+25↓j
seg001:000002A7                 mov     [edi], eax
seg001:000002A9                 mov     [edi+4], edx
seg001:000002AC                 add     edi, 8
seg001:000002AF                 dec     ecx
seg001:000002B0                 jnz     short loc_2A7
seg001:000002B2                 lidt    large fword ptr ds:11Ch
seg001:000002B9                 retn
seg001:000002B9 IDT_Init        endp
```

在 bogus 中调试得到 IDTR 中的值为 0x012807ff（可以使用 show mode 命令来判断实模式向保护模式的转换）。依据之前的知识，可以知道基址为 0x0128 以及长度为 0x07ff：

```bochs
<bochs:40> x 0x11c
[bochs]:
0x000000000000011c <bogus+       0>:	0x012807ff
```

中断门描述符被初始化为 `0000 8e00 0008 00fc`（偏移：0xfc；段选择符：0x8；P：1，即段是否在内存；DPL：0），如下：

```
<bochs:79> x/20 0x128
[bochs]:
0x0000000000000128 <bogus+       0>:	0x000800fc	0x00008e00	0x000800fc	0x00008e00
0x0000000000000138 <bogus+      16>:	0x000800fc	0x00008e00	0x000800fc	0x00008e00
0x0000000000000148 <bogus+      32>:	0x000800fc	0x00008e00	0x000800fc	0x00008e00
0x0000000000000158 <bogus+      48>:	0x000800fc	0x00008e00	0x000800fc	0x00008e00
0x0000000000000168 <bogus+      64>:	0x000800fc	0x00008e00	0x000800fc	0x00008e00
```

GDT_init 处，加载 GDTR 的地址为 122：

```asm
seg001:00000283 GDT_Init        proc near               ; CODE XREF: sub_205+E↑p
seg001:00000283                 lgdt    large fword ptr ds:122h
seg001:0000028A                 retn
seg001:0000028A GDT_Init        endp
```

同理，可以知道 GDT 基址为 0x0928 以及长度为 0x001f。不过这里没有对 GDT 进行初始化：

```bochs
<bochs:74> x 0x122
[bochs]:
0x0000000000000122 <bogus+       0>:	0x0928001f
```

在 22E~25F 的代码执行了一个 16 次的循环，其中 0x21~0x30 的中断向量描述符在内存的原始位置在 D08 处，循环中将每个中断向量存储到 128 处；然后调用了 NextHandler 函数，最后调用 `INT 21H`。

```asm
seg001:0000022E loc_22E:                                ; CODE XREF: sub_205+58↓j
seg001:0000022E                 nop
seg001:0000022F                 cmp     ebx, 10h
seg001:00000232                 jge     short loc_25F
seg001:00000234                 mov     eax, 80000h
seg001:00000239                 lea     edx, ds:0D08h[ebx*4]
seg001:00000240                 mov     edx, [edx]
seg001:00000242                 mov     ax, dx
seg001:00000245                 mov     dx, 8E00h
seg001:00000249                 mov     ecx, 21h ; '!'
seg001:0000024E                 add     ecx, ebx
seg001:00000250                 lea     esi, ds:128h[ecx*8]
seg001:00000257                 mov     [esi], eax
seg001:00000259                 mov     [esi+4], edx
seg001:0000025C                 inc     ebx
seg001:0000025D                 jmp     short loc_22E
seg001:0000025F ; ---------------------------------------------------------------------------
seg001:0000025F
seg001:0000025F loc_25F:                                ; CODE XREF: sub_205+2D↑j
seg001:0000025F                                         ; sub_205+61↓j
seg001:0000025F                 call    NextHandler
seg001:00000264                 int     21h             ; DOS -
seg001:00000266                 jmp     short loc_25F
seg001:00000266 sub_205         endp
```

获取得到所有中断向量的地址如下：

```
...
IDT[0x21]=32-Bit Interrupt Gate target=0x0008:0x00000b7c, DPL=0
IDT[0x22]=32-Bit Interrupt Gate target=0x0008:0x00000b8a, DPL=0
IDT[0x23]=32-Bit Interrupt Gate target=0x0008:0x00000ba1, DPL=0
IDT[0x24]=32-Bit Interrupt Gate target=0x0008:0x00000bc1, DPL=0
IDT[0x25]=32-Bit Interrupt Gate target=0x0008:0x00000be1, DPL=0
IDT[0x26]=32-Bit Interrupt Gate target=0x0008:0x00000bfc, DPL=0
IDT[0x27]=32-Bit Interrupt Gate target=0x0008:0x00000c17, DPL=0
IDT[0x28]=32-Bit Interrupt Gate target=0x0008:0x00000c32, DPL=0
IDT[0x29]=32-Bit Interrupt Gate target=0x0008:0x00000c4f, DPL=0
IDT[0x2a]=32-Bit Interrupt Gate target=0x0008:0x00000c6c, DPL=0
IDT[0x2b]=32-Bit Interrupt Gate target=0x0008:0x00000c84, DPL=0
IDT[0x2c]=32-Bit Interrupt Gate target=0x0008:0x00000c96, DPL=0
IDT[0x2d]=32-Bit Interrupt Gate target=0x0008:0x00000cb5, DPL=0
IDT[0x2e]=32-Bit Interrupt Gate target=0x0008:0x00000cf7, DPL=0
IDT[0x2f]=32-Bit Interrupt Gate target=0x0008:0x00000ce0, DPL=0
IDT[0x30]=32-Bit Interrupt Gate target=0x0008:0x00000cd4, DPL=0
...
```

在 IDA 中定位到所有中断向量的地址，分别对应着不同的函数，这一段代码后面会用到：

```asm
seg001:00000D7C                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000D83                 mov     [ecx], eax
seg001:00000D85                 jmp     loc_EF8
seg001:00000D8A ; ---------------------------------------------------------------------------
seg001:00000D8A                 lea     eax, ds:0B64h[eax*4]
seg001:00000D91                 mov     eax, [eax]
seg001:00000D93                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000D9A                 mov     [ecx], eax
seg001:00000D9C                 jmp     loc_EF8
seg001:00000DA1 ; ---------------------------------------------------------------------------
seg001:00000DA1                 lea     eax, ds:0B64h[eax*4]
seg001:00000DA8                 mov     eax, [eax]
seg001:00000DAA                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000DB1                 lea     eax, ds:0D48h[eax*4]
seg001:00000DB8                 mov     eax, [eax]
seg001:00000DBA                 mov     [ecx], eax
seg001:00000DBC                 jmp     loc_EF8
seg001:00000DC1 ; ---------------------------------------------------------------------------
seg001:00000DC1                 lea     eax, ds:0B64h[eax*4]
seg001:00000DC8                 mov     eax, [eax]
seg001:00000DCA                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000DD1                 mov     ecx, [ecx]
seg001:00000DD3                 lea     ecx, ds:0D48h[ecx*4]
seg001:00000DDA                 mov     [ecx], eax
seg001:00000DDC                 jmp     loc_EF8
seg001:00000DE1 ; ---------------------------------------------------------------------------
seg001:00000DE1                 lea     eax, ds:0B64h[eax*4]
seg001:00000DE8                 mov     edx, [eax]
seg001:00000DEA                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000DF1                 mov     eax, [ecx]
seg001:00000DF3                 add     eax, edx
seg001:00000DF5                 mov     [ecx], eax
seg001:00000DF7                 jmp     loc_EF8
seg001:00000DFC ; ---------------------------------------------------------------------------
seg001:00000DFC                 lea     eax, ds:0B64h[eax*4]
seg001:00000E03                 mov     edx, [eax]
seg001:00000E05                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000E0C                 mov     eax, [ecx]
seg001:00000E0E                 sub     eax, edx
seg001:00000E10                 mov     [ecx], eax
seg001:00000E12                 jmp     loc_EF8
seg001:00000E17 ; ---------------------------------------------------------------------------
seg001:00000E17                 lea     eax, ds:0B64h[eax*4]
seg001:00000E1E                 mov     edx, [eax]
seg001:00000E20                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000E27                 mov     eax, [ecx]
seg001:00000E29                 xor     eax, edx
seg001:00000E2B                 mov     [ecx], eax
seg001:00000E2D                 jmp     loc_EF8
seg001:00000E32 ; ---------------------------------------------------------------------------
seg001:00000E32                 lea     eax, ds:0B64h[eax*4]
seg001:00000E39                 mov     eax, [eax]
seg001:00000E3B                 lea     edx, ds:0B64h[ecx*4]
seg001:00000E42                 mov     cl, al
seg001:00000E44                 mov     eax, [edx]
seg001:00000E46                 shl     eax, cl
seg001:00000E48                 mov     [edx], eax
seg001:00000E4A                 jmp     loc_EF8
seg001:00000E4F ; ---------------------------------------------------------------------------
seg001:00000E4F                 lea     eax, ds:0B64h[eax*4]
seg001:00000E56                 mov     eax, [eax]
seg001:00000E58                 lea     edx, ds:0B64h[ecx*4]
seg001:00000E5F                 mov     cl, al
seg001:00000E61                 mov     eax, [edx]
seg001:00000E63                 shr     eax, cl
seg001:00000E65                 mov     [edx], eax
seg001:00000E67                 jmp     loc_EF8
seg001:00000E6C ; ---------------------------------------------------------------------------
seg001:00000E6C                 lea     eax, ds:0B64h[eax*4]
seg001:00000E73                 mov     eax, [eax]
seg001:00000E75                 lea     ecx, ds:0B64h[ecx*4]
seg001:00000E7C                 mov     edx, [ecx]
seg001:00000E7E                 and     eax, edx
seg001:00000E80                 mov     [ecx], eax
seg001:00000E82                 jmp     short loc_EF8
seg001:00000E84 ; ---------------------------------------------------------------------------
seg001:00000E84                 lea     eax, ds:0B64h[ecx*4]
seg001:00000E8B                 mov     eax, [eax]
seg001:00000E8D                 lea     ecx, dword_B34+44h
seg001:00000E93                 mov     [ecx], eax
seg001:00000E95                 iret
seg001:00000E96 ; ---------------------------------------------------------------------------
seg001:00000E96                 lea     eax, ds:0B64h[eax*4]
seg001:00000E9D                 mov     eax, [eax]
seg001:00000E9F                 test    eax, eax
seg001:00000EA1                 jnz     short loc_EF8
seg001:00000EA3                 lea     eax, ds:0B64h[ecx*4]
seg001:00000EAA                 mov     eax, [eax]
seg001:00000EAC                 lea     ecx, dword_B34+44h
seg001:00000EB2                 mov     [ecx], eax
seg001:00000EB4                 iret
seg001:00000EB5 ; ---------------------------------------------------------------------------
seg001:00000EB5                 lea     eax, ds:0B64h[eax*4]
seg001:00000EBC                 mov     eax, [eax]
seg001:00000EBE                 test    eax, eax
seg001:00000EC0                 jz      short loc_EF8
seg001:00000EC2                 lea     eax, ds:0B64h[ecx*4]
seg001:00000EC9                 mov     eax, [eax]
seg001:00000ECB                 lea     ecx, dword_B34+44h
seg001:00000ED1                 mov     [ecx], eax
seg001:00000ED3                 iret
seg001:00000ED4 ; ---------------------------------------------------------------------------
seg001:00000ED4                 lea     eax, unk_F94
seg001:00000EDA                 call    sub_2EA
seg001:00000EDF                 hlt
seg001:00000EE0 ; ---------------------------------------------------------------------------
seg001:00000EE0                 lea     eax, unk_FA0
seg001:00000EE6                 call    sub_2EA
seg001:00000EEB                 lea     eax, word_FAE
seg001:00000EF1                 call    sub_2EA
seg001:00000EF6                 hlt
```

接下来在 NextHandler 处，包括 `INT 21H` 的三条指令，类似于一个 switch 语句，根据以前的做题经验，基本可以判断出是个虚拟机。在 NextHandler 函数中，首先从 B78 处获取值作为 D48 的偏移，将 D48 处的值分别赋值给 给 065（操作符）、ecx（操作数 1）、eax（操作数 2），而 065 地址处的值为 21H，即指令 `INT 21H` 的操作数，故这里中断的调用是和 edi 的取值有关系的：

```asm
seg001:00000268 NextHandler     proc near               ; CODE XREF: sub_205:loc_25F↑p
seg001:00000268                 mov     edi, large ds:0B78h
seg001:0000026E                 lea     edi, ds:0D48h[edi*4]
seg001:00000275                 mov     eax, [edi]
seg001:00000277                 mov     large ds:65h, al
seg001:0000027C                 mov     ecx, [edi+4]
seg001:0000027F                 mov     eax, [edi+8]
seg001:00000282                 retn
seg001:00000282 NextHandler     endp
```

回过去看上面中断代码的最后一部分是将上面 edi 中的值加 3，即取下一组指令：

```asm
seg001:00000EF8 loc_EF8:                                ; CODE XREF: seg001:00000D85↑j
seg001:00000EF8                                         ; seg001:00000D9C↑j ...
seg001:00000EF8                 lea     ecx, dword_B34+44h
seg001:00000EFE                 mov     eax, [ecx]
seg001:00000F00                 add     eax, 3
seg001:00000F03                 mov     [ecx], eax
seg001:00000F05                 iret
```

那么之前的那段代码就是不同的操作符时进行的中断调用。这里就先把每个中断的部分的代码进行翻译（buf 的地址为 B64，code 的地址为 D48，pc 的地址为 B78）：

| 中断编号 |           功能描述            |
| :------: | :---------------------------: |
|   0x21   |         `buf[a] = b`          |
|   0x22   |       `buf[a] = buf[b]`       |
|   0x23   |    `buf[a] = code[buf[b]]`    |
|   0x24   |    `code[buf[a]] = buf[b]`    |
|   0x25   |      `buf[a] += buf[b]`       |
|   0x26   |      `buf[a] -= buf[b]`       |
|   0x27   |      `buf[a] ^= buf[b]`       |
|   0x28   |      `buf[a] <<= buf[b]`      |
|   0x29   |      `buf[a] >>= buf[b]`      |
|   0x2A   |      `buf[a] &= buf[b]`       |
|   0x2B   |           `pc = a`            |
|   0x2C   | `if(buf[b] == 0) pc = buf[a]` |
|   0x2D   | `if(buf[b] != 0) pc = buf[a]` |
|   0x2E   |  终止 CPU 运行，即 hlt 指令   |
|   0x2F   |      输出 flag 正确提示       |
|   0x30   |      输出 flag 错误提示       |

根据上面的分析，用 IDAPython 把虚拟机指令 dump 下来：

```python
code = []
for addr in range(0x0F48, 0x11E0, 12):
    ins = Dword(addr)
    op1 = Dword(addr + 4)
    op2 = Dword(addr + 8)
    code.append(ins)
    code.append(op1)
    code.append(op2)
print code
```

然后用脚本处理一下，得到伪代码：

```python
buf[0] = 129
buf[1] ^= buf[1]
code[buf[1]] = buf[1] # 0
buf[2] = code[buf[0]] # ('Read code, offset:', '129')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '129')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '130')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '130')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '131')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '131')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '132')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '132')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '133')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '133')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '134')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '134')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '135')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '135')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '136')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '136')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[2] = code[buf[0]] # ('Read code, offset:', '137')
buf[3] = buf[2]
buf[4] = 8
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] <<= (buf[4] & 0xFF)
buf[2] ^= buf[3]
buf[3] ^= buf[3]
buf[4] = code[buf[3]] # 0
code[buf[3]] = buf[2] # 0
buf[2] ^= buf[4]
code[buf[0]] = buf[2] # ('Write code, offset:', '137')
buf[1] = 1
buf[0] += buf[1]
buf[1] = buf[0]
buf[2] = 129
buf[1] -= buf[2]
buf[2] = 9
buf[1] -= buf[2]
buf[2] = 9
if buf[1] != 0:
	pc = buf[2] # jmp 9
buf[0] = 129
buf[1] = buf[0]
buf[2] = 9
buf[1] += buf[2]
buf[3] = code[buf[0]] # ('Read code, offset:', '129')
buf[4] = code[buf[1]] # ('Read code, offset:', '138')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
print 'wrong'
```

上面是在 `buf[3] != 0` 的时候，输出 wrong 的情况，如果在这个条件判断中都正确的话，会产生以下代码：

```python
buf[0] = 129
buf[1] = buf[0]
buf[2] = 9
buf[1] += buf[2]
buf[3] = code[buf[0]] # ('Read code, offset:', '129')
buf[4] = code[buf[1]] # ('Read code, offset:', '138')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '130')
buf[4] = code[buf[1]] # ('Read code, offset:', '139')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '131')
buf[4] = code[buf[1]] # ('Read code, offset:', '140')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '132')
buf[4] = code[buf[1]] # ('Read code, offset:', '141')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '133')
buf[4] = code[buf[1]] # ('Read code, offset:', '142')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '134')
buf[4] = code[buf[1]] # ('Read code, offset:', '143')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '135')
buf[4] = code[buf[1]] # ('Read code, offset:', '144')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '136')
buf[4] = code[buf[1]] # ('Read code, offset:', '145')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
buf[3] = code[buf[0]] # ('Read code, offset:', '137')
buf[4] = code[buf[1]] # ('Read code, offset:', '146')
buf[3] -= buf[4]
buf[4] = 126
if buf[3] != 0:
	pc = buf[4] # jmp 126
buf[3] = 1
buf[0] += buf[3]
buf[1] += buf[3]
buf[2] -= buf[3]
buf[4] = 90
if buf[2] != 0:
	pc = buf[4] # jmp 90
print 'right'
```

人脑逆向机简化一波代码，就是一个 9 次的循环异或，并在最后进行比较：

```python
i = 129
while True:
    code[i] = code[i] ^ (code[i] << 8) ^ (code[i] << 16) ^ (code[i] << 24) ^ code[i - 1] ^ (code[i - 1] << 8) ^ (code[i - 1] << 16) ^ (code[i - 1] << 24)
    i += 1
    if i - 138 == 0:
        break
for i in range(9):
    if code[138 + i] - code[129 + i] != 0:
	    print 'wrong'
        exit()
print 'right'
```

这里已知正确的数据在计算后的结果，可以通过爆破来得到（爆破范围比较大，Python 会消耗很多时间，这里用 C#）：

```c#
using System;

namespace Solve {
	class Program {
		public static byte[] intToBytes(uint value) {
			byte[] res = new byte[4];
			res[3] = (byte) ((value >> 24) & 0xFF);
			res[2] = (byte) ((value >> 16) & 0xFF);
			res[1] = (byte) ((value >> 8) & 0xFF);
			res[0] = (byte) (value & 0xFF);
			return res;
		}

		public static string asciiToString(byte[] array) {
			return Convert.ToString(System.Text.Encoding.ASCII.GetString(array));
		}

		static void Main(string[] args) {
			var data = new uint[] {
				0x61646238, 0x36353465, 0x6361352d, 0x31312d38, 0x612d3965, 0x2d316331, 0x39653838, 0x30386566, 0x66616566, 0x57635565, 0x06530401, 0x1f494949, 0x5157071f, 0x575f4357, 0x57435e57, 0x4357020a, 0x575e035e, 0x0f590000, 0x6e6f7277, 0x20202067, 0x00202020, 0x72726f63, 0x20746365, 0x20202020, 0x6c660020, 0x69206761, 0x6c662073, 0x597b6761, 0x5072756f, 0x68637461, 0x2020207d, 0x20202020, 0x20202020, 0x20202020, 0x20202020, 0x20202020, 0x20202020, 0xffffff00, 0xffffffff
			};
			var ans = new uint[data.Length];
			var patch = new byte[data.Length * 4];
			for(uint i = 0; i < 9; i++) {
				uint t = 0;
				for(uint j = 0; j <= 0x7FFFFFFF; j++) {
					t = j ^ (j << 8) ^ (j << 16) ^ (j << 24);
					if(i > 0) {
						t ^= ans[i - 1] ^ (ans[i - 1] << 8) ^ (ans[i - 1] << 16) ^ (ans[i - 1] << 24);
					}
					if(t == data[i + 9]) { // 0x57635565
						ans[i] = j;
						patch[4 * i] = intToBytes(j)[0];
						patch[4 * i + 1] = intToBytes(j)[1];
						patch[4 * i + 2] = intToBytes(j)[2];
						patch[4 * i + 3] = intToBytes(j)[3];
						Console.WriteLine("0x{0:X8}", j);
						break;
					}
				}
			}
			string flag = asciiToString(patch);
			Console.WriteLine(flag);
		}
	}
}
```

当然在已知数据的情况下也可以直接逆回来：

```python
#!/usr/bin/env python
data = [0x57635565, 0x06530401, 0x1F494949, 0x5157071F, 0x575F4357, 0x57435E57, 0x4357020A, 0x575E035E, 0x0F590000, 0x00000000]
flag = ''

for i in range(9):
    flag += libnum.n2s(data[i] ^ ((data[i] << 8) & 0xFFFFFFFF))[::-1]
    data[i + 1] = data[i] ^ data[i + 1]
print flag
```

# bochs 调试

这道题其实主要通过 bochs 进行动态调试来分析，下面附上动态调试的一些过程：

```
<bochs:1> b 0x7c00
<bochs:2> c
00000004662i[BIOS  ] $Revision: 13073 $ $Date: 2017-02-16 22:43:52 +0100 (Do, 16. Feb 2017) $
00000318050i[KBD   ] reset-disable command received
00000320819i[BIOS  ] Starting rombios32
00000321257i[BIOS  ] Shutdown flag 0
00000321840i[BIOS  ] ram_size=0x02000000
00000322261i[BIOS  ] ram_end=32MB
00000362829i[BIOS  ] Found 1 cpu(s)
00000376413i[BIOS  ] bios_table_addr: 0x000f9cd8 end=0x000fcc00
00000704208i[PCI   ] i440FX PMC write to PAM register 59 (TLB Flush)
00001032137i[P2ISA ] PCI IRQ routing: PIRQA# set to 0x0b
00001032156i[P2ISA ] PCI IRQ routing: PIRQB# set to 0x09
00001032175i[P2ISA ] PCI IRQ routing: PIRQC# set to 0x0b
00001032194i[P2ISA ] PCI IRQ routing: PIRQD# set to 0x09
00001032204i[P2ISA ] write: ELCR2 = 0x0a
00001032974i[BIOS  ] PIIX3/PIIX4 init: elcr=00 0a
00001040697i[BIOS  ] PCI: bus=0 devfn=0x00: vendor_id=0x8086 device_id=0x1237 class=0x0600
00001042976i[BIOS  ] PCI: bus=0 devfn=0x08: vendor_id=0x8086 device_id=0x7000 class=0x0601
00001045094i[BIOS  ] PCI: bus=0 devfn=0x09: vendor_id=0x8086 device_id=0x7010 class=0x0101
00001045323i[PIDE  ] new BM-DMA address: 0xc000
00001045939i[BIOS  ] region 4: 0x0000c000
00001047953i[BIOS  ] PCI: bus=0 devfn=0x0a: vendor_id=0x8086 device_id=0x7020 class=0x0c03
00001048157i[UHCI  ] new base address: 0xc020
00001048773i[BIOS  ] region 4: 0x0000c020
00001048901i[UHCI  ] new irq line = 9
00001050796i[BIOS  ] PCI: bus=0 devfn=0x0b: vendor_id=0x8086 device_id=0x7113 class=0x0680
00001051028i[ACPI  ] new irq line = 11
00001051040i[ACPI  ] new irq line = 9
00001051065i[ACPI  ] new PM base address: 0xb000
00001051079i[ACPI  ] new SM base address: 0xb100
00001051107i[PCI   ] setting SMRAM control register to 0x4a
00001215200i[CPU0  ] Enter to System Management Mode
00001215200i[CPU0  ] enter_system_management_mode: temporary disable VMX while in SMM mode
00001215210i[CPU0  ] RSM: Resuming from System Management Mode
00001379231i[PCI   ] setting SMRAM control register to 0x0a
00001394138i[BIOS  ] MP table addr=0x000f9db0 MPC table addr=0x000f9ce0 size=0xc8
00001395960i[BIOS  ] SMBIOS table addr=0x000f9dc0
00001398141i[BIOS  ] ACPI tables: RSDP addr=0x000f9ee0 ACPI DATA addr=0x01ff0000 size=0xf72
00001401353i[BIOS  ] Firmware waking vector 0x1ff00cc
00001403148i[PCI   ] i440FX PMC write to PAM register 59 (TLB Flush)
00001403871i[BIOS  ] bios_table_cur_addr: 0x000f9f04
00001531488i[VBIOS ] VGABios $Id: vgabios.c,v 1.76 2013/02/10 08:07:03 vruppert Exp $
00001531559i[BXVGA ] VBE known Display Interface b0c0
00001531591i[BXVGA ] VBE known Display Interface b0c5
00001534516i[VBIOS ] VBE Bios $Id: vbe.c,v 1.65 2014/07/08 18:02:25 vruppert Exp $
00014040189i[BIOS  ] Booting from 0000:7c00
(0) Breakpoint 1, 0x0000000000007c00 in ?? ()
Next at t=14040244
(0) [0x000000007c00] 0000:7c00 (unk. ctxt): jmpf 0x07c0:0005          ; ea0500c007
```

可以用 `show mode` 命令来显示实模式向保护模式的转换：

```
<bochs:3> show mode
show mode switch: ON
show mask is: mode
```

利用 `u` 命令来查看汇编代码，这里是实模式的部分：

```
<bochs:7> u/40 0x7c00
00007c00: (                    ): jmpf 0x07c0:0005          ; ea0500c007
00007c05: (                    ): mov ax, cs                ; 8cc8
00007c07: (                    ): mov ds, ax                ; 8ed8
00007c09: (                    ): mov ss, ax                ; 8ed0
00007c0b: (                    ): mov sp, 0x0400            ; bc0004
00007c0e: (                    ): cld                       ; fc
00007c0f: (                    ): mov ax, 0x0003            ; b80300
00007c12: (                    ): int 0x10                  ; cd10
00007c14: (                    ): mov dx, 0x0000            ; ba0000
00007c17: (                    ): mov cx, 0x0002            ; b90200
00007c1a: (                    ): mov ax, 0x1000            ; b80010
00007c1d: (                    ): mov es, ax                ; 8ec0
00007c1f: (                    ): xor bx, bx                ; 31db
00007c21: (                    ): mov ax, 0x0228            ; b82802
00007c24: (                    ): int 0x13                  ; cd13
00007c26: (                    ): jnb .+2                   ; 7302
00007c28: (                    ): jmp .-2                   ; ebfe
00007c2a: (                    ): cli                       ; fa
00007c2b: (                    ): mov ax, 0x1000            ; b80010
00007c2e: (                    ): mov ds, ax                ; 8ed8
00007c30: (                    ): xor ax, ax                ; 31c0
00007c32: (                    ): mov es, ax                ; 8ec0
00007c34: (                    ): mov cx, 0x2000            ; b90020
00007c37: (                    ): sub si, si                ; 29f6
00007c39: (                    ): sub di, di                ; 29ff
00007c3b: (                    ): rep movsb byte ptr es:[di], byte ptr ds:[si] ; f3a4
00007c3d: (                    ): mov ax, 0x07c0            ; b8c007
00007c40: (                    ): mov ds, ax                ; 8ed8
00007c42: (                    ): lidt ds:0x006f            ; 0f011e6f00
00007c47: (                    ): lgdt ds:0x0075            ; 0f01167500
00007c4c: (                    ): mov ax, 0x0001            ; b80100
00007c4f: (                    ): lmsw ax                   ; 0f01f0
00007c52: (                    ): jmpf 0x0008:0000          ; ea00000800
```

在指令 `lmsw ax` 处看到实模式向保护模式的转换：

```
<bochs:39> n
Next at t=15885325
(0) [0x000000007c4f] 07c0:004f (unk. ctxt): lmsw ax                   ; 0f01f0
<bochs:40>
00015885326: switched from 'real mode' to 'protected mode'
Next at t=15885326
(0) [0x000000007c52] 07c0:0000000000000052 (unk. ctxt): jmpf 0x0008:0000          ; ea00000800
```

保护模式的前一段部分：

```
<bochs:42> u/20 0x00
00000000: (                    ): mov eax, 0x00000010       ; b810000000
00000005: (                    ): mov ds, ax                ; 8ed8
00000007: (                    ): lss esp, ds:0x00000b5c    ; 0fb2255c0b0000
0000000e: (                    ): call .+120                ; e878000000
00000013: (                    ): call .+107                ; e86b000000
00000018: (                    ): mov eax, 0x00000010       ; b810000000
0000001d: (                    ): mov ds, ax                ; 8ed8
0000001f: (                    ): mov es, ax                ; 8ec0
00000021: (                    ): mov fs, ax                ; 8ee0
00000023: (                    ): mov gs, ax                ; 8ee8
00000025: (                    ): lss esp, ds:0x00000b5c    ; 0fb2255c0b0000
0000002c: (                    ): xor ebx, ebx              ; 31db
```

IDTR 的初始化：

```
<bochs:39> u/20 0x8b
0000008b: (                    ): mov edx, 0x000000fc       ; bafc000000
00000090: (                    ): mov eax, 0x00080000       ; b800000800
00000095: (                    ): mov ax, dx                ; 6689d0
00000098: (                    ): mov dx, 0x8e00            ; 66ba008e
0000009c: (                    ): lea edi, dword ptr ds:0x00000128 ; 8d3d28010000
000000a2: (                    ): mov ecx, 0x00000100       ; b900010000
000000a7: (                    ): mov dword ptr ds:[edi], eax ; 8907
000000a9: (                    ): mov dword ptr ds:[edi+4], edx ; 895704
000000ac: (                    ): add edi, 0x00000008       ; 83c708
000000af: (                    ): dec ecx                   ; 49
000000b0: (                    ): jnz .-11                  ; 75f5
000000b2: (                    ): lidt ds:0x0000011c        ; 0f011d1c010000
000000b9: (                    ): ret                       ; c3
```

GDTR 的初始化：

```
<bochs:68> u/10 0x83
00000083: (                    ): lgdt ds:0x00000122        ; 0f011522010000
0000008a: (                    ): ret                       ; c3
```

用 `sreg` 命令可以看到 GDTR 和 IDTR 寄存器被初始化了：

```
<bochs:75> sreg
es:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
cs:0x0008, dh=0x00c09b00, dl=0x000007ff, valid=1
	Code segment, base=0x00000000, limit=0x007fffff, Execute/Read, Non-Conforming, Accessed, 32-bit
ss:0x0010, dh=0x00c09300, dl=0x000007ff, valid=7
	Data segment, base=0x00000000, limit=0x007fffff, Read/Write, Accessed
ds:0x0010, dh=0x00c09300, dl=0x000007ff, valid=7
	Data segment, base=0x00000000, limit=0x007fffff, Read/Write, Accessed
fs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=1
	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
gs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=1
	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
ldtr:0x0000, dh=0x00008200, dl=0x0000ffff, valid=1
tr:0x0000, dh=0x00008b00, dl=0x0000ffff, valid=1
gdtr:base=0x0000000000000928, limit=0x1f
idtr:base=0x0000000000000128, limit=0x7ff
```

最后是虚拟机指令部分：

```
<bochs:43> u/110 0xb7c
00000b7c: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000b83: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000b85: (                    ): jmp .+366                 ; e96e010000
00000b8a: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000b91: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000b93: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000b9a: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000b9c: (                    ): jmp .+343                 ; e957010000
00000ba1: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000ba8: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000baa: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000bb1: (                    ): lea eax, dword ptr ds:[eax*4+3400] ; 8d0485480d0000
00000bb8: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000bba: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000bbc: (                    ): jmp .+311                 ; e937010000
00000bc1: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000bc8: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000bca: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000bd1: (                    ): mov ecx, dword ptr ds:[ecx] ; 8b09
00000bd3: (                    ): lea ecx, dword ptr ds:[ecx*4+3400] ; 8d0c8d480d0000
00000bda: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000bdc: (                    ): jmp .+279                 ; e917010000
00000be1: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000be8: (                    ): mov edx, dword ptr ds:[eax] ; 8b10
00000bea: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000bf1: (                    ): mov eax, dword ptr ds:[ecx] ; 8b01
00000bf3: (                    ): add eax, edx              ; 01d0
00000bf5: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000bf7: (                    ): jmp .+252                 ; e9fc000000
00000bfc: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c03: (                    ): mov edx, dword ptr ds:[eax] ; 8b10
00000c05: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000c0c: (                    ): mov eax, dword ptr ds:[ecx] ; 8b01
00000c0e: (                    ): sub eax, edx              ; 29d0
00000c10: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000c12: (                    ): jmp .+225                 ; e9e1000000
00000c17: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c1e: (                    ): mov edx, dword ptr ds:[eax] ; 8b10
00000c20: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000c27: (                    ): mov eax, dword ptr ds:[ecx] ; 8b01
00000c29: (                    ): xor eax, edx              ; 31d0
00000c2b: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000c2d: (                    ): jmp .+198                 ; e9c6000000
00000c32: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c39: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000c3b: (                    ): lea edx, dword ptr ds:[ecx*4+2916] ; 8d148d640b0000
00000c42: (                    ): mov cl, al                ; 88c1
00000c44: (                    ): mov eax, dword ptr ds:[edx] ; 8b02
00000c46: (                    ): shl eax, cl               ; d3e0
00000c48: (                    ): mov dword ptr ds:[edx], eax ; 8902
00000c4a: (                    ): jmp .+169                 ; e9a9000000
00000c4f: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c56: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000c58: (                    ): lea edx, dword ptr ds:[ecx*4+2916] ; 8d148d640b0000
00000c5f: (                    ): mov cl, al                ; 88c1
00000c61: (                    ): mov eax, dword ptr ds:[edx] ; 8b02
00000c63: (                    ): shr eax, cl               ; d3e8
00000c65: (                    ): mov dword ptr ds:[edx], eax ; 8902
00000c67: (                    ): jmp .+140                 ; e98c000000
00000c6c: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c73: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000c75: (                    ): lea ecx, dword ptr ds:[ecx*4+2916] ; 8d0c8d640b0000
00000c7c: (                    ): mov edx, dword ptr ds:[ecx] ; 8b11
00000c7e: (                    ): and eax, edx              ; 21d0
00000c80: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000c82: (                    ): jmp .+116                 ; eb74
00000c84: (                    ): lea eax, dword ptr ds:[ecx*4+2916] ; 8d048d640b0000
00000c8b: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000c8d: (                    ): lea ecx, dword ptr ds:0x00000b78 ; 8d0d780b0000
00000c93: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000c95: (                    ): iret                      ; cf
00000c96: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000c9d: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000c9f: (                    ): test eax, eax             ; 85c0
00000ca1: (                    ): jnz .+85                  ; 7555
00000ca3: (                    ): lea eax, dword ptr ds:[ecx*4+2916] ; 8d048d640b0000
00000caa: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000cac: (                    ): lea ecx, dword ptr ds:0x00000b78 ; 8d0d780b0000
00000cb2: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000cb4: (                    ): iret                      ; cf
00000cb5: (                    ): lea eax, dword ptr ds:[eax*4+2916] ; 8d0485640b0000
00000cbc: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000cbe: (                    ): test eax, eax             ; 85c0
00000cc0: (                    ): jz .+54                   ; 7436
00000cc2: (                    ): lea eax, dword ptr ds:[ecx*4+2916] ; 8d048d640b0000
00000cc9: (                    ): mov eax, dword ptr ds:[eax] ; 8b00
00000ccb: (                    ): lea ecx, dword ptr ds:0x00000b78 ; 8d0d780b0000
00000cd1: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000cd3: (                    ): iret                      ; cf
00000cd4: (                    ): lea eax, dword ptr ds:0x00000f94 ; 8d05940f0000
00000cda: (                    ): call .-3061               ; e80bf4ffff
00000cdf: (                    ): hlt                       ; f4
00000ce0: (                    ): lea eax, dword ptr ds:0x00000fa0 ; 8d05a00f0000
00000ce6: (                    ): call .-3073               ; e8fff3ffff
00000ceb: (                    ): lea eax, dword ptr ds:0x00000fae ; 8d05ae0f0000
00000cf1: (                    ): call .-3084               ; e8f4f3ffff
00000cf6: (                    ): hlt                       ; f4
00000cf7: (                    ): hlt                       ; f4
00000cf8: (                    ): lea ecx, dword ptr ds:0x00000b78 ; 8d0d780b0000
00000cfe: (                    ): mov eax, dword ptr ds:[ecx] ; 8b01
00000d00: (                    ): add eax, 0x00000003       ; 83c003
00000d03: (                    ): mov dword ptr ds:[ecx], eax ; 8901
00000d05: (                    ): iret                      ; cf
```

# References

https://www.52pojie.cn/thread-936377-1-1.html
https://blog.csdn.net/ice__snow/article/details/50654629
https://blog.51cto.com/4201689/1420063
https://www.cnblogs.com/playmak3r/p/12079833.html
https://blog.qrzbing.cn/2019/04/27/CISCN2019-strange-int/
http://imushan.com/2018/07/11/os/Bochs%E5%AD%A6%E4%B9%A0-%E5%AE%89%E8%A3%85%E9%85%8D%E7%BD%AE%E7%AF%87/
https://www.cnblogs.com/mlzrq/p/10223079.html#%E4%BD%BF%E7%94%A8bochs%E8%B0%83%E8%AF%95
https://mrh1s.top/posts/d2cf12e4/