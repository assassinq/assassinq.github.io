---
title: 【译】Radare2之旅-Part1：Simple crackme
date: 2019-02-18 12:17:27
tags: [re, translation]
---

翻译自[Megabeets](https://www.megabeets.net/a-journey-into-radare-2-part-1/)。

<!-- more -->

# 序言

过去一年里的 CTF 比赛中，不论是逆向工程（RE）还是漏洞挖掘（PWN），我一直在用`radare2`。我发现`radare2`对于很多 CTF 的题目来说都很有用，极大地缩短了我的做题时间。遗憾的是熟悉 radare2 的人太少了。可能大家都习惯了使用`IDA Pro`、`OllyDBG`还有`gdb`，或者没有听说过它。不管怎么样，我都认为`radare2`应该成为你工具箱中的一部分。

因为我真的特别喜欢这个项目，而且我希望能有越来越多的人开始熟悉它、使用它，能对项目做出一些贡献。我计划写一系列的文章以及使用`r2`的例子。因为那些文章都涉及`radare2`的特点和功能，我会解释的更加详细。

![Welcome to IDA 10.0. （在 radare2/doc/fortunes.fun 查看更多）](https://www.megabeets.net/uploads/r2_part1_1.png)

# `radare2`

`radare2`是一个逆向工程和二进制分析的开源框架，它有很多命令行接口，包括反汇编、分析数据、打补丁、比较数据、查找、替换、可视化等等功能。同时它可以在几乎所有的主要操作系统（`GNU/Linux`、`.Windows`、`*BSD`、`iOS`、`OSX`、`Solaris`等等）上运行，并且支持许多 CPU 架构和文件格式。他所有的特点可以展现出一个思想——`radare2`是绝对自由的。

该框架是一个工具的集合，既可以在`r2`给出的 shell 下使用，又可以独立使用——比如我们将要了解的`rahash2`、`rabin2`、`ragg2`三个组件。所有的组件赋予了`radare2`强大的静态或动态分析、十六进制编辑以及漏洞挖掘能力（在接下来的文章中我会更深入地讲述）。

我们必须意识到学习`r2`是一个十分艰难的过程——虽然`r2`有 GUI 和 WebUI。在我看来，IDA 的 GUI 和方便性确实更佳。但是它的命令行接口，包括其可视化模式，仍然是`radare2`的核心以及魅力所在。因为它的复杂性，我会尽力讲得浅显易懂。

![这差不多是r2的学习曲线](https://www.megabeets.net/uploads/r2_learning_curve.png)

在开始之前，你可以看一看[“r2、IDA Pro 和 Hopper 等工具间的比较”](https://www.radare.org/r/cmp.html)来了解它。

# 获取`radare2`

## 下载

`radare2`的环境配置非常快——我们每天都会更新，所以更推荐你去使用 git 的版本，而不是稳定版本。有时候稳定版本可能没有 git 版本更稳定。

```shell
$ git clone https://github.com/radare/radare2.git
$ cd radare2
$ ./sys/install.sh
```

如果你不想下载 git 版本或者你想要不同操作系统（`Windows`、`OS X`、`iOS`等等）上的可执行文件，可以在[radare2 官网下载界面](https://www.radare.org/r/down.html)查看。

## 更新

正如我之前所说的，更推荐大家使用 git 仓库里最新版的`r2`。从 git 更新`r2`只需要执行：

```shell
$ ./sys/install.sh
```

然后你就能从 git 获得最新的版本。我通常每天早上会更新一下`radare2`，在这期间可以看看一会儿视频消遣。

## 卸载

我实在想不出什么理由会让你在看这篇文章时想要卸载`radare2`。如果要卸载的话只需要执行：

```shell
$ make uninstall
$ make purge
```

# 开始学习

你可以在[这里](https://github.com/ITAYC0HEN/A-journey-into-Radare2/blob/master/Part%201%20-%20Simple%20crackme/megabeets_0x1)下载 Crackme。

现在你已经在自己的系统上下载了`radare2`和文件，我们可以开始探索`radare2`的基础使用。我会在[REMunx](https://remnux.org/)上调试，大部分的命令和说明跟`Windows`或者其他系统上是一样的。

## 命令行参数

和大部分命令行工具一样，查看可选参数的方式是执行`-h`参数：

```shell
$ r2 -h
```

我不把完整的输出放上来，而是放一些我日常工作中常用的参数：

```shell
Usage: r2 [-ACdfLMnNqStuvwz] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]
          [-s addr] [-B baddr] [-M maddr] [-c cmd] [-e k=v] file|pid|-|--|=

-d: Debug the executable 'file' or running process 'pid'
-A: Analyze executable at load time (xrefs, etc)
-q: Quiet mode, exit after processing commands
-w: Write mode enabled
-L: List of supported IO plugins
-i [file]: Interprets a r2 script
-n: Bare load. Do not load executable info as the entrypoint
-c 'command; command; ...': Run r2 and execute commands (eg: r2 's main; px 60')
-p [prj]: Creates a project for the file being analyzed
-: Opens r2 with the malloc plugin that gives a 512 bytes memory area to play with
```

## 二进制信息

面对一个新的文件时，我第一件想做的事就是获取文件的信息。我们可以使用`r2`框架中最强大的工具之一——`rabin2`来获取信息。

> - `rabin2`可以从二进制文件中获取信息，包括区段、文件头、导入导出表、字符串、入口点等等。同时具有不同的格式的输出。`rabin2`支持`ELF`、`PE`、`Mach-O`、`Java CLASS`等文件。
>
> - 使用`man rabin2`查看更多的信息。

我们执行`rabin2`并使用参数`-I`输出二进制信息，例如操作系统、语言、字节序、框架以及保护技术（比如`Canary`、`PIC`、`NX`）等等。

```shell
$ rabin2 -I megabeets_0x1
havecode true
pic      false
canary   false
nx       false
crypto   false
va       true
intrp    /lib/ld-linux.so.2
bintype  elf
class    ELF32
lang     c
arch     x86
bits     32
machine  Intel 80386
os       linux
minopsz  1
maxopsz  16
pcalign  0
subsys   linux
endian   little
stripped false
static   false
linenum  true
lsyms    true
relocs   true
rpath    NONE
binsz    6220
```

你可以清楚地看到，这是一个 32 位 elf 文件，没有符号表并且是动态链接。它没有任何漏洞利用技术——下一篇文章我们讲学习使用`radare2`来对漏洞进行利用。
让我们跑一下程序，看看它做了什么。

> - 注意：虽然我可以向你保证这个程序是安全的，但是逆向一个未知的程序时，务必在一个虚拟环境下运行。
> - 不过你可以相信我，因为程序确实是安全的。😛

```shell
$ ./megabeets_0x1

  .:: Megabeets ::.
Think you can make it?
Nop, Wrong argument.

$ ./megabeets_0x1 abcdef

  .:: Megabeets ::.
Think you can make it?
Nop, Wrong argument.
```

第一次跑的时候，输出了`Nop, Wrong argument`。假设我们需要提供一个参数，第二次输入`abcdef`作为参数，依旧失败了。显然需要特定的字符串才能绕过。

让我们用`radare2`来测试程序：

```shell
$ r2 ./megabeets_0x1
 — Thank you for using radare2. Have a nice night!
[0x08048370]>
```

我们生成了一个`radare2`的 shell，还有一个欢迎界面。我们可以执行`fo`来输出一个新的句子，有些很搞笑同时有些也很有趣。现在`r2`的 shell 正在等着我们输入命令，并且展示给我们此刻所在的地址（0x08048370）。默认情况下我们自动在入口点处。让我们看看是否正确：

```shell
[0x08048370]> ie
[Entrypoints]
vaddr=0x08048370 paddr=0x00000370 baddr=0x08048000 laddr=0x00000000 haddr=0x00000018 type=program1 entrypoints
```

我们使用`ie`命令输出了文件的入口点地址。`r2`命令有一系列有意义的字母。在这个例子里，`ie`代表了`info >> entrypoint`。因此在你熟悉了`radare2`的能力之后，命令都是比较好记的。但是你不需要记住所有的命令——你可以仅仅需要在（几乎）每个字母后面加上`?`来获得命令的信息以及它的子命令。

```shell
[0x08048370]> i?
|Usage: i Get info from opened file (see rabin2’s manpage)
| Output mode:
| ‘*’                Output in radare commands
| ‘j’                Output in json
| ‘q’                Simple quiet output
| Actions:
| i|ij               Show info of current file (in JSON)
| iA                 List archs
| ia                 Show all info (imports, exports, sections..)
| ib                 Reload the current buffer for setting of the bin (use once only)
| ic                 List classes, methods and fields
| iC                 Show signature info (entitlements, …)
| id                 Debug information (source lines)
| iD lang sym        demangle symbolname for given language
| ie                 Entrypoint
| iE                 Exports (global symbols)
| ih                 Headers (alias for iH)
| iHH                Verbose Headers in raw text
| ii                 Imports
| iI                 Binary info
| ik [query]         Key-value database from RBinObject
| il                 Libraries
| iL                 List all RBin plugins loaded
| im                 Show info about predefined memory allocation
| iM                 Show main address
| io [file]          Load info from file (or last opened) use bin.baddr
| ir|iR              Relocs
| is                 Symbols
| iS [entropy,sha1]  Sections (choose which hash algorithm to use)
| iV                 Display file version info
| iz                 Strings in data sections
| izz                Search for Strings in the whole binary
| iZ                 Guess size of binary program
```

`i`命令目的是从打开的文件中获取信息，它就是集成到`radare2`的 shell 里的`rabin2`（之前提到的）。

## 分析

默认情况下`radare2`不会自动分析文件，因为分析文件是一个复杂的过程，尤其是比较大的文件。了解更多关于分析的内容，你可以看一看在`radare2`博客上的[这篇文章](http://radare.today/posts/analysis-by-default/)。

显然分析仍然是可能的，`r2`提供了许多种类的分析方式。正如我之前提到的，我们可以通过对`a`命令后面添加`?`来查找分析选项。

```shell

[0x08048370]> a?
|Usage: a[abdefFghoprxstc] […]
| ab [hexpairs]    analyze bytes
| abb [len]        analyze N basic blocks in [len] (section.size by default)
| aa[?]            analyze all (fcns + bbs) (aa0 to avoid sub renaming)
| ac[?] [cycles]   analyze which op could be executed in [cycles]
| ad[?]            analyze data trampoline (wip)
| ad [from] [to]   analyze data pointers to (from-to)
| ae[?] [expr]     analyze opcode eval expression (see ao)
| af[?]            analyze Functions
| aF               same as above, but using anal.depth=1
| ag[?] [options]  output Graphviz code
| ah[?]            analysis hints (force opcode size, …)
| ai [addr]        address information (show perms, stack, heap, …)
| ao[?] [len]      analyze Opcodes (or emulate it)
| aO               Analyze N instructions in M bytes
| ar[?]            like ‘dr’ but for the esil vm. (registers)
| ap               find prelude for current offset
| ax[?]            manage refs/xrefs (see also afx?)
| as[?] [num]      analyze syscall using dbg.reg
| at[?] [.]        analyze execution traces
Examples:
f ts @ S*~text:0[3]; f t @ section..text
f ds @ S*~data:0[3]; f d @ section..data
.ad t t+ts @ d:ds
```

我通常开始分析时会执行`aa`（`analyse all`）。这个名称有一点容易误解，因为除此之外还有很多可以分析的（执行`aa?`可以看到更多的用法），但对于这个程序来说已经足够了。这次我们直接执行`aaa`，更简单些。你也可以执行`radare2`用`-A`参数来分析文件，直接在开始就执行`aaa`（例如`r2 -A megabeets_0x1`）

```shell
[0x08048370]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
```

## 标志

在分析之后，`radare2`把一些特定的名字和偏移联系在一起，例如区段、函数、符号表、字符串等等。他们被称作为标志。标志被整合进标志空间，一个标志空间是所有类似特征的标志的集合。执行`fs`以查看所有的标志：

```shell
[0x08048370]> fs
0    4 . strings
1   35 . symbols
2   82 . sections
3    5 . relocs
4    5 . imports
5    1 . functions
```

我们可以使用`fs <flagspace>`来查看某个特定的标志空间，然后用`f`输出所有的标志。我们使用分号将一行中的多个命令分开（比如`命令一; 命令二; 命令三;...`）。

```shell
[0x08048370]> fs imports; f
0x08048320 6 sym.imp.strcmp
0x08048330 6 sym.imp.strcpy
0x08048340 6 sym.imp.puts
0xffffffff 16 loc.imp.__gmon_start__
0x08048350 6 sym.imp.__libc_start_main
```

正如我们所看到的，`radare2`将所有程序所使用的导入表输出——可以看到我们所熟悉的`strcmp`、`strcpy`、`puts`等，包括相关的地址。我们也可以列出字符串的标志空间。

```shell
[0x08048370]> fs strings; f
0x08048700 21 str._n__.::_Megabeets_::.
0x08048715 23 str.Think_you_can_make_it_
0x0804872c 10 str.Success__n
0x08048736 22 str.Nop__Wrong_argument._n
```

## 字符串

我们看到`r2`列出了一些字符串的偏移，还有一些变量名。让我们主要来看看字符串。有很多可以列出程序中字符串的方式，你可以选择你最需要的一种。
`iz` – 列出在数据短的字符串
`izz` – 在整个程序中查找字符串

```shell
[0x08048370]> iz
vaddr=0x08048700 paddr=0x00000700 ordinal=000 sz=21 len=20 section=.rodata type=ascii string=\n .:: Megabeets ::.
vaddr=0x08048715 paddr=0x00000715 ordinal=001 sz=23 len=22 section=.rodata type=ascii string=Think you can make it?
vaddr=0x0804872c paddr=0x0000072c ordinal=002 sz=10 len=9 section=.rodata type=ascii string=Success!\n
vaddr=0x08048736 paddr=0x00000736 ordinal=003 sz=22 len=21 section=.rodata type=ascii string=Nop, Wrong argument.\n
```

我们已经熟悉了大部分字符串——还记得我们一开始运行程序时的那几行字符串吧。但是我们没有看到`Success`，这应该是我们输入正确字符串后的提示。既然我们已经得到了字符串，让我们看看它们在程序的什么地方被使用了。

```shell
[0x08048370]> axt @@ str.*
data 0x8048609 push str._n__.::_Megabeets_::. in main
data 0x8048619 push str.Think_you_can_make_it_ in main
data 0x8048646 push str._n_tSuccess__n in main
data 0x8048658 push str._n_tNop__Wrong_argument._n in main
```

这个命令展示给我们`radare2`更多的特点。`axt`命令用来在数据段或程序段交叉查找某个地址（试试`ax?`）。`@@`是一个迭代器标志，用来在一段偏移上重复某个命令（试试`@@?`）。`str.*`是一个对所有开头为`str.`的标志的通配。这条命令能帮助我列出字符串标志以及对应所在的函数名。在这之前要确保选择了字符串的标志空间（默认时是`fs *`）。

## 定位

正如我之前所说的，之前我们一直在程序的入口点，现在应该去其他地方看看了。我们刚列出来的字符串都是在`main`函数中的。为了定位到字符串，我们需要使用`seek`命令，用`s`替代。正如大家所知道的，在（几乎）每个命令后加上`?`会解决你所有的问题。

```shell
[0x08048370]> s?
|Usage: s  # Seek commands
| s                 Print current address
| s addr            Seek to address
| s-                Undo seek
| s- n              Seek n bytes backward
| s–                Seek blocksize bytes backward
| s+                Redo seek
| s+ n              Seek n bytes forward
| s++               Seek blocksize bytes forward
| s[j*=]            List undo seek history (JSON, =list, *r2)
| s/ DATA           Search for next occurrence of ‘DATA’
| s/x 9091          Search for next occurrence of \x90\x91
| s.hexoff          Seek honoring a base from core->offset
| sa [[+-]a] [asz]  Seek asz (or bsize) aligned to addr
| sb                Seek aligned to bb start
| sC[?] string      Seek to comment matching given string
| sf                Seek to next function (f->addr+f->size)
| sf function       Seek to address of specified function
| sg/sG             Seek begin (sg) or end (sG) of section or file
| sl[?] [+-]line    Seek to line
| sn/sp             Seek next/prev scr.nkey
| so [N]            Seek to N next opcode(s)
| sr pc             Seek to register
```

`seek`命令是接收一个地址或是一个数学表达式作为参数。这个表达式可以是数学运算、标志或者内存访问操作。我们可以执行`s main`来定位到 main 函数。让我们先通过`afl`命令（Analyze Functions List）来查看`radare2`为我们列出了哪些函数。

```shell
[0x08048370]> afl
0x080482ec    3 35           sym._init
0x08048320    1 6            sym.imp.strcmp
0x08048330    1 6            sym.imp.strcpy
0x08048340    1 6            sym.imp.puts
0x08048350    1 6            sym.imp.__libc_start_main
0x08048360    1 6            sub.__gmon_start___252_360
0x08048370    1 33           entry0
0x080483a0    1 4            sym.__x86.get_pc_thunk.bx
0x080483b0    4 43           sym.deregister_tm_clones
0x080483e0    4 53           sym.register_tm_clones
0x08048420    3 30           sym.__do_global_dtors_aux
0x08048440    4 43   -> 40   sym.frame_dummy
0x0804846b   19 282          sym.rot13
0x08048585    1 112          sym.beet
0x080485f5    5 127          main
0x08048680    4 93           sym.__libc_csu_init
0x080486e0    1 2            sym.__libc_csu_fini
0x080486e4    1 20           sym._fini
```

这些导入函数正是我们之前所看到的，包括入口点、libc、main 函数和两个引人注意的函数分别叫做`sym.beet`和`sym.rot13`。

# 反汇编

## main 函数

是时候去看看汇编代码了。首先我们用`s main`来定位到 main 函数，然后用`pdf`命令（Print Disassemble Function）来反汇编。注意地址是怎么准确地变成 main 函数的地址的。

> - 注意：正如我之前所说的，这篇文章的目的是教大家学习和了解`radare2`，而不是教汇编语言的。因此我不会彻底地解释代码。实际上，这个程序也很简单，你只要有一点点基础的逆向工程知识就能掌握。

```shell
[0x08048370]> s main
[0x080485f5]> pdf
          ;– main:
/ (fcn) main 127
|   main ();
|           ; var int local_8h @ ebp-0x8
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048387 (entry0)
|           0x080485f5      8d4c2404       lea ecx, [esp + local_4h]   ; 0x4
|           0x080485f9      83e4f0         and esp, 0xfffffff0
|           0x080485fc      ff71fc         push dword [ecx – 4]
|           0x080485ff      55             push ebp
|           0x08048600      89e5           mov ebp, esp
|           0x08048602      53             push ebx
|           0x08048603      51             push ecx
|           0x08048604      89cb           mov ebx, ecx
|           0x08048606      83ec0c         sub esp, 0xc
|           0x08048609      6800870408     push str._n__.::_Megabeets_::. ; str._n__.::_Megabeets_::.
|           0x0804860e      e82dfdffff     call sym.imp.puts          ; int puts(const char *s)
|           0x08048613      83c410         add esp, 0x10
|           0x08048616      83ec0c         sub esp, 0xc
|           0x08048619      6815870408     push str.Think_you_can_make_it_ ; “Think you can make it?” @ 0x8048715
|           0x0804861e      e81dfdffff     call sym.imp.puts          ; int puts(const char *s)
|           0x08048623      83c410         add esp, 0x10
|           0x08048626      833b01         cmp dword [ebx], 1          ; [0x1:4]=0x1464c45
|       ,=< 0x08048629      7e2a           jle 0x8048655
|       |   0x0804862b      8b4304         mov eax, dword [ebx + 4]    ; [0x4:4]=0x10101
|       |   0x0804862e      83c004         add eax, 4
|       |   0x08048631      8b00           mov eax, dword [eax]
|       |   0x08048633      83ec0c         sub esp, 0xc
|       |   0x08048636      50             push eax
|       |   0x08048637      e849ffffff     call sym.beet
|       |   0x0804863c      83c410         add esp, 0x10
|       |   0x0804863f      85c0           test eax, eax
|      ,==< 0x08048641      7412           je 0x8048655
|      ||   0x08048643      83ec0c         sub esp, 0xc
|      ||   0x08048646      682c870408     push str.Success__n ; “Success!.” @ 0x804872c
|      ||   0x0804864b      e8f0fcffff     call sym.imp.puts          ; int puts(const char *s)
|      ||   0x08048650      83c410         add esp, 0x10
|     ,===< 0x08048653      eb10           jmp 0x8048665
|     |||      ; JMP XREF from 0x08048629 (main)
|     |||      ; JMP XREF from 0x08048641 (main)
|     |-> 0x08048655      83ec0c         sub esp, 0xc
|     |     0x08048658      6836870408     push str.Nop__Wrong_argument._n ; “Nop, Wrong argument..” @ 0x8048736
|     |     0x0804865d      e8defcffff     call sym.imp.puts          ; int puts(const char *s)
|     |     0x08048662      83c410         add esp, 0x10
|     |        ; JMP XREF from 0x08048653 (main)
|     `—> 0x08048665      b800000000     mov eax, 0
|           0x0804866a      8d65f8         lea esp, [ebp – local_8h]
|           0x0804866d      59             pop ecx
|           0x0804866e      5b             pop ebx
|           0x0804866f      5d             pop ebp
|           0x08048670      8d61fc         lea esp, [ecx – 4]
\           0x08048673      c3             ret
```

看过汇编代码后，我们可以写出一段简单的伪代码：

```cpp
if (argc > 1 && beet(argv[1]) == true)
# i.e - if any argument passed to the program AND the result of beet, given the passed argument, is true
# argc is the number of arguments passed to the program
# argc will be at least 1 becuase the first argument is the program name
# argv is the array of parameters passed to the program
{
    print "success"
}
else
{
     print "fail"
}
exit
```

## 可视化模式和图形模式

`radare2`有着一个非常强大、效率极高的可视化模式。可视化模式对用户非常友好并且将使用`r2`的逆向过程带到了一个新的高度。按下`V`键开启可视化模式。按下`p`/`P`键用来切换模式。在屏幕的最上方可以看到你输入的命令。这里按`p`可以切换回原来的反汇编模式。

![](https://www.megabeets.net/uploads/visualMode_1.png)

### 可视化模式基本命令

#### 移动

你可以通过`k`向上移动，通过`j`向下移动。回车键可以`jmp`或者`call`到目标地址。同时在每个`jmp`或`call`右侧注释的方括号中有数字，直接按相应的数字可跳转到对应地址。

#### 帮助

正如之前命令行下的`radare2`，按下`?`可以为你展现帮助窗口，你可以学习可视化模式下的各个命令。

#### 交叉引用

用`x`/`X`分别来列出当前函数的引用和调用的情况。按下对应数字来跳转。

#### `radare2`命令

使用：在可视化模式下输入`:command`来执行`r2`命令

#### 注释

你可以通过`;[-]comment`来添加或删去注释。

#### 标记

`m<key>`可以用来标记特定的偏移地址。`'<key>`来跳到指定地址。

#### 退出

按下`q`键返回到`r2`的 shell。

### 可视化图形模式

和其他的一些反汇编器一样，`radare2`也有图形视图。你可以输入`VV`从 shell 进入图形视图，通过`k`/`j`/`h`/`l`向上/下/左/右移动，按`g`键跳转到目标函数（例如`gd`）。

![](https://www.megabeets.net/uploads/visualGraph_1.png)

按`?`来列出所有的命令，其中`R`命令值得一学。

## 反汇编`beet`函数

接下来回到反汇编函数上，看看`beet`函数。正如我们之前所看到的，我们的程序检查了`beet`的返回结果，也就是我们输入的参数。我们可以通过一些方式输出`beet`的返回值，这里列出几种：

1. 在`r2`的 shell 中定位到`beet`函数，然后通过`s sym.beet`（`sym.beet`是`beet`函数的一个标志。你可以通过`f sym.<tab>`输出出`sym`的标志）输出函数，然后执行`pdf`（Print Disassemble Function）；
2. 在`r2`的 shell 下，通过`pdf @ sym.beet`输出`beet`函数。`@`是临时的定位（输出`sym.beet`地址处的函数）；
3. 可视化模式下在 main 函数下跳到`beet`函数；
4. 可视化图形界面下在 main 函数中使用`gd`（`d`是`call`边上的字母）

这是`beet`函数在图形视图下的样子：

![](https://www.megabeets.net/uploads/visualGraph_beet1.png)

我们可以看到输入的参数被复制给了一个缓冲空间。缓存区的位置在`ebp - local_88h`。`local_88h`其实是 0x88，也就是十进制的 136。在可视化模式下，我们可以用`:`执行`r2`的命令`? 0x88`查看。

```shell
:> ? 0x88
136 0x88 0210 136 0000:0088 136 “\x88” 10001000 136.0 136.000000f 136.000000
```

由于 4 个字节保存了前一个栈帧的 ebp 值，接下来的 4 个字节则是返回地址，因此在栈上的缓冲区大小为 128 个字节，总共为 136 个字节。

在缓冲区之后是我们输入的参数，它和函数`sym.rot13`的结果进行比较。[Rot-13](https://en.wikipedia.org/wiki/ROT13)是一个著名的置换加密，经常在 CTF 以及 Crackme 中使用。这个函数接收了 9 个十六进制数，看起来`radare2`没有把它们识别成一个字符串。我们可以在其地址上执行`ahi s`。

```shell
:> ahi s @@=0x080485a3 0x080485ad 0x080485b7
```

`ahi s`用来将将具体地址转换成字符串（试试`ahi?`）。`@@`是一个迭代器（试试`@@`），然后这些地址则是`sym.beet`函数中没被`radare2`识别成字符串的部分。执行完这条命令后，图形视图会自动刷新（如果没有自动刷新，执行`r`）成这样：

![](https://www.megabeets.net/uploads/visualGraph_beet2.png)

看起来没被识别出来的字符串是`Megabeets`（根据[字节序](https://en.wikipedia.org/wiki/Endianness)反向压栈得到）。

该程序通过`strcmp`将经过 rot13 处理后的`Megabeets`与我们输入的参数进行比较。幸运的是我们不需要辛苦地分析 rot13 的具体算法，因为`r2`框架中的`rahash2`工具已经包含了 rot13 加密。

`rahash2`通过不同的算法计算文件或是字符串的校验值。

使用`man rahash2`查看更多的用法。

```shell
:> !rahash2 -E rot -S s:13 -s ‘Megabeets\n’
Zrtnorrgf
```

`rahash2`执行了`rot13(“Megabeets”)`后得到了字符串`Zrtnorrgf`。输入`!`可以在`r2`的 shell 下执行系统命令。我们假设`Zrtnorrgf`就是要和我们的输入进行比较的字符串。让我们在调试模式下打开程序，使用`ood`（试试`ood?`）并将`Zrtnorrgf`作为参数，看看我们会得到什么。

```shell
[0xf7749be9]> ood?
| ood [args]    reopen in debugger mode (with args)
[0xf7749be9]> ood Zrtnorrgf
Wait event received by different pid 7415
Wait event received by different pid 7444
Process with PID 7575 started…
File dbg:///home/remnux/Desktop/tutorials/megabeets_0x1 Zrtnorrgf reopened in read-write mode
= attach 7575 7575
Assuming filepath /home/remnux/Desktop/tutorials/megabeets_0x1
[0xf7749be9]> dc
Selecting and continuing: 7575.:: Megabeets ::.
Think you can make it?
Success!PTRACE_EVENT_EXIT pid=7575, status=0x0
```

我们收到了成功的提示，破解了这个 Crackme。在成功破解之后，我们终于可以说这个程序就是将我们输入的第一个参数与`rot13(“Megabeets”)`进行了比较，也就是`Zrtnorrgf`。

你可以在[这里](https://github.com/ITAYC0HEN/A-journey-into-Radare2/blob/master/Part%201%20-%20Simple%20crackme/megabeets_0x1.c)查看 Crackme 的完整源码。

# 后记

`Radare2`之旅第一部分就告一段落了。我们只接触了`radare2`的表皮，仅仅了解了它最最基础的一些功能。在下一部分中，我们将会学习更多的关于`radare2`的功能，包括脚本处理、恶意软件分析和漏洞利用。我知道对于很多人来说一开始是很难的，不管是能否感受到`radare2`的强大之处，亦或是将你的以前的习惯放到一边而熟悉使用`radare2`。不管你是一个逆向工程师、一个 CTF 比赛选手或者只是一个安全爱好者，我敢保证将`radare2`收入你的工具箱绝对一个是明智的选择。
