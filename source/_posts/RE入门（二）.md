---
title: RE入门（二）
date: 2019-01-27 11:54:09
tags: re
---

了解一些 VB 的特性以及一些简单的的函数调用约定。

<!-- more -->

# Visual Basic

## VB 专用引擎

VB 文件使用名为 `MSVBVM60.dll`（Microsoft Visual Basic Machine 6.0）的 VB 专用引擎（也称为 The Thunder Runtime Engine）。

举个使用 VB 引擎的例子，显示消息框时，VB 代码中要调用 `MsgBox()` 函数。其实，VB 编辑器真正调用的是 `MSVBVM60.dll` 里的 `rtcMsgBox()` 函数，在该函数内部通过调用 `user32.dll` 里的 `MessageBoxW()` 函数（Win32 API）来工作（也可以在 VB 代码中直接调用 `user32.dll` 里的 `MessageBoxW()`）。

## 本地代码和伪代码

根据使用的编译选项的不同，VB 文件可以编译为本地代码（N code）与伪代码（P code）。本地代码一般使用易于调试器解析的 IA-32 指令；而伪代码是一种解释器（Interpreter）语言，它使用由 VB 引擎实现虚拟机并可自解析的指令（字节码）。因此，若想准确解析 VB 的伪代码，就需要分析 VB 引擎并实现模拟器。

伪代码具有与 Java（Java 虚拟机）、Python（Python 专用引擎）类似的形态结构。使用伪代码的好处是非常方便代码移植（编写/发布针对特定平台的引擎，用户代码借助它几乎可以不加任何修改地在制定平台上运行）。

## 事件处理程序

VB 主要来编写 GUI 程序，IDE 用户界面本身也最适合于 GUI 编程。由于 VB 程序采用 Windows 操作系统的事件驱动方式工作，所以在 `main()` 或 `WinMain()` 中并不存在用户代码（希望调试的代码），用户代码存在于各个事件处理程序（event handler）之中。

# 函数调用约定

## cdecl

`cdecl` 是主要在 C 语言中使用的方式，调用者负责处理栈。

```cpp
#include "stdio.h"

int add(int a, int b)
{
    return (a + b);
}

int main(int argc, char *argv[])
{
    return add(1, 2);
}
```

使用 VC++（关闭优化选项）编译代码生成 `cdecl.exe`，使用 OllyDbg 调试。

从 401000~401020 地址间的代码可以发现，`add()` 函数的参数 1、2 以逆序的方式入栈，调用 `add()` 函数（401000）后，使用 `ADD ESP,8` 命令整理栈。调用者 `main()` 函数直接清理其压入栈的函数参数，这样的方式是 `cdecl`。

```
00401000  /$  55            PUSH EBP                                 ;  # add
00401001  |.  8BEC          MOV EBP,ESP
00401003  |.  8B45 08       MOV EAX,[ARG.1]
00401006  |.  0345 0C       ADD EAX,[ARG.2]
00401009  |.  5D            POP EBP
0040100A  \.  C3            RETN
0040100B      CC            INT3
0040100C      CC            INT3
0040100D      CC            INT3
0040100E      CC            INT3
0040100F      CC            INT3
00401010  /$  55            PUSH EBP                                 ;  # main
00401011  |.  8BEC          MOV EBP,ESP
00401013  |.  6A 02         PUSH 0x2                                 ;  / Arg2 = 00000002
00401015  |.  6A 01         PUSH 0x1                                 ;  | Arg1 = 00000001
00401017  |.  E8 E4FFFFFF   CALL cdecl.00401000                      ;  \ cdecl.00401000
0040101C  |.  83C4 08       ADD ESP,0x8
0040101F  |.  5D            POP EBP
00401020  \.  C3            RETN
```

`cdecl` 方式的好处在于它可以像 C 语言的 `printf()` 函数一样，向被调用函数传递长度可变的参数。这种长度可变的参数在其他调用约定中很难实现。

# stdcall

`stdcall` 方式常用于 Win32 API，该方式由被调用者清理栈。C 语言默认的函数调用方式为 `cdecl`。若想使用 `stdcall` 方式编译源码，只要使用 `_stdcall` 关键字即可。

```cpp
#include "stdio.h"

int _stdcall add(int a, int b)
{
    return (a + b);
}

int main(int argc, char *argv[])
{
    return add(1, 2);
}
```

使用 VC++（关闭优化选项）编译代码生成 `stdcall.exe` 文件后，使用 OllyDbg 调试。从代码中可以看到，在 `main()` 函数中调用 `add()` 函数后，省略了清理栈的代码（`ADD ESP,8`）。

栈的清理工作由 `add()` 函数中最后（40100A）的 `RETN 8` 命令来执行。`RETN 8` 命令的含义为 RETN + POP 8 字节，即返回后使 ESP 增加到指定大小。

```
00401000  /$  55            PUSH EBP                                 ;  # add
00401001  |.  8BEC          MOV EBP,ESP
00401003  |.  8B45 08       MOV EAX,[ARG.1]
00401006  |.  0345 0C       ADD EAX,[ARG.2]
00401009  |.  5D            POP EBP
0040100A  \.  C2 0800       RETN 0x8
0040100D      CC            INT3
0040100E      CC            INT3
0040100F      CC            INT3
00401010  /$  55            PUSH EBP                                 ;  # main
00401011  |.  8BEC          MOV EBP,ESP
00401013  |.  6A 02         PUSH 0x2                                 ;  / Arg2 = 00000002
00401015  |.  6A 01         PUSH 0x1                                 ;  | Arg1 = 00000001
00401017  |.  E8 E4FFFFFF   CALL stdcall.00401000                    ;  \ stdcall.00401000
0040101C  |.  5D            POP EBP
0040101D  \.  C3            RETN
```

像这样在被调用者 `add()` 函数内部清理栈的方式即为 `stdcall` 方式。`stdcall` 方式的好处在于，被调用者函数内部存在着栈清理代码，与每次调用函数时都要用 `ADD ESP,XXX` 命令的 `cdecl` 方式相比，代码尺寸要小。虽然 Win32 API 是使用语言编写的库，但它使用的是 `stdcall` 方式，而不是 C 语言默认的 `cdecl` 方式。这是为了更好的兼容性，使 C 语言之外的其他语言（Delphi（Pascall）、Visual Basic 等）也能直接调用 API。

# fastcall

`fastcall` 方式与 `stdcall` 方式基本类似，但该方式通常会使用寄存器（而非栈内存）去传递那些需要传递给函数的部分参数（前 2 个）。若某函数有 4 个参数，则前 2 个参数分别使用 ECX、EDX 寄存器传递。

顾名思义，`fastcall` 方式的优势在于可以实现对函数的快速调用（从 CPU 的立场看，访问寄存器的速度要远比内存快得多）。单从函数调用本身来看，`fastcall` 方式非常快，但是有时需要额外的系统开销来管理 ECX、EDX 寄存器。倘若调用函数前 ECX 与 EDX 中存有重要数据，那么使用它们前必须先备份。此外，如果函数本身很复杂，需要 ECX、EDX 寄存器用作其他用途时，也需要将它们中的参数值存储到另外某个地方。

# References

[《逆向工程核心原理》](https://reversecore.com/)
https://www.jianshu.com/p/85a76f630c95
https://bbs.pediy.com/thread-224583.htm
