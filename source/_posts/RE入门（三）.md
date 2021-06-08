---
title: RE入门（三）
date: 2019-01-28 13:03:31
tags: re
---

摘自[《逆向工程核心原理》](https://reversecore.com/)中关于 Windows 操作系统的 PE（Portable Executable）文件格式的部分，其中也有关于进程、内存、DLL 等的内容，它们是 Windows 操作系统中最核心的部分。

<!-- more -->

# PE 文件格式

## 介绍

PE 文件是 Windows 操作系统下使用的可执行文件格式。它是微软在 UNIX 平台的 COFF（Common Object File Format，通用对象文件格式）基础上制作而成的。最初（正如 Portable 这个单词所代表的那样）设计用来提高程序在不同操作系统上的移植性，但实际上这种文件格式仅用在 Windows 系列的操作系统下。

PE 文件是指 32 位的可执行文件，也称为 PE32。64 位的可执行文件成为 PE+ 或 PE32+，是 PE（PE32）文件的一种扩展形式（请注意不是 PE64）。

## PE 文件格式

PE 文件种类如表所示。

|     种类     |      主扩展名      |
| :----------: | :----------------: |
|  可执行系列  |      EXE、SCR      |
|    库系列    | DLL、OCX、CPL、DRV |
| 驱动程序系列 |      SYS、VXD      |
| 对象文件系列 |        OBJ         |

严格地说，OBJ（对象）文件之外的所有文件都是可执行的。DLL、SYS 文件等虽然不能直接在 Shell（`Explorer.exe`）中运行，但可以使用其他方式（调试器、服务等）执行。

> 根据 PE 正式规范，编译结果 OBJ 文件也视为 PE 文件。但是 OBJ 文件本身不能以任何形式执行，在代码逆向分析中几乎不需要关注它。

接下来以记事本（Windows XP SP3 的 `notepad.exe`，与其他版本 Windows 下的 `notepad.exe` 文件结构类似，但是地址不同）程序进行简单说明。

下面是 `notepad.exe` 文件的起始部分，也是 PE 文件的头部分（PE header）。`notepad.exe` 文件运行需要的所有信息就存储在这个 PE 头中。如果加载到内存、从何处开始运行、运行中需要的 DLL 有哪些、需要多大的栈/堆内存等，大量信息以结构体形式存储在 PE 头中。换言之，学习 PE 文件格式就是学习 PE 头中的结构体。

![](/pics/BIN集训/RE/三/1.png)

### 基本结构

`notepad.exe` 具有普通 PE 文件的基本结构。从 DOS 头（DOS header）到节区头（Section header）是 PE 头部分，其下的节区合称 PE 体。文件中使用偏移（offset），内存中使用 VA（Virtual Address，虚拟地址）来表示位置。文件加载到内存时，情况就会发生变化（节区的大小、位置等）。文件的内容一般可分为代码（`.text`）、数据（`.data`）、资源（`.rsrc`）节，分别保存。

> 根据所用的不同开发工具（VB/VC++/Delphi/etc）与编译选项，节区的名称、大小、个数、存储的内容等都是不同的。最重要的是它们按照不同的用途分类保存到不同的节中。

各节区头定义了各节区在文件或内存中的大小、位置、属性等。

PE 头与各节区的尾部存在一个区域，称为 NULL 填充（Null padding）。计算机中，为了提高处理文件、内存、网络包的效率，使用“最小基本单位”这一概念，PE 文件中也类似。文件/内存中节区的起始位置应该在各文件/内存最小单位的倍数位置上，空白区域将用 NULL 填充（可以看到各节区起始地址的截断都遵循一定的规则）。

![](/pics/BIN集训/RE/三/2.png)

### VA&RVA

VA 指的是进程虚拟内存的绝对地址，RVA（Relative Virtual Address，相对虚拟地址）指从某个基准位置（ImageBase）开始的相对地址。VA 和 RVA 满足下面的换算关系。

```
RVA+ImageBase=RA
```

PE 头内部信息大多以 RVA 形式存在。原因在于，PE 文件（主要是 DLL）加载到进程虚拟内存的特定位置时，该位置可能已经加载了其他 PE 文件（DLL）。此时必须通过重定位（Relocation）将其加载到其他空白的位置，若 PE 头信息使用的是 VA，则无法正常访问。因此使用 RVA 来定位信息，即使发生了重定位，只要相对于基准位置的相对地址没有变化，就能正常访问到指定信息，不会出现任何问题。

> 32 位 Windows OS 中，各进程分配有 4GB 的虚拟内存，因此进程中 VA 值的范围是 00000000~FFFFFFFF。

## PE 头

PE 头由许多结构体组成。

### DOS 头

微软创建 PE 文件格式时，人们正广泛使用 DOS 文件，所以微软充分考虑了 PE 文件对 DOS 文件的兼容性。其结果是在 PE 头的最前面添加了一个 `IMAGE_DOS_HEADER` 结构体，用来扩展已有的 DOS EXE 头。

```cpp
typedef struct _IMAGE_DOS_HEADER {
    WORD    e_magic;         // DOS signature : 4D5A ("MZ")
    WORD    e_cblp;
    WORD    e_cp;
    WORD    e_crlc;
    WORD    e_cparhdr;
    WORD    e_minalloc;
    WORD    e_maxalloc;
    WORD    e_ss;
    WORD    e_sp;
    WORD    e_csum;
    WORD    e_ip;
    WORD    e_cs;
    WORD    e_lfarlc;
    WORD    e_ovno;
    WORD    e_res[4];
    WORD    e_oemid;
    WORD    e_oeminfo;
    WORD    e_res2[10];
    LONG    e_lfanew;        // offset to NT header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

`IMAGE_DOS_HEADER` 结构体的大小为 40 个字节。在该结构中必须知道 2 个重要成员：`e_magic` 与 `e_lfanew`。

- `e_magic`：DOS 签名（signature，4D5A=>ASCII 值“MZ”）
- `e_lfanew`：指示 NT 头的偏移（根据不同文件拥有可变值）

所有 PE 文件在你开始部分（`e_magic`）都有 DOS 签名（“MZ”）。`e_lfanew` 值指向 NT 头所在位置（NT 头的名称为 `IMAGE_NT_HEADERS`，后面将会介绍）。

> 一个名叫 Mark Zbikowski 的开发人员在微软设计了 DOS 可执行文件，MZ 即取自其名字的首字母。

![](/pics/BIN集训/RE/三/3.png)

根据 PE 规范，文件开始的 2 个字节为 4D5A，`e_lfanew` 的值为 000000E0（不是 E0000000）

> Intel 系列的 CPU 以逆序存储数据，称为小端序标识法。

如果尝试修改这些值，会发现程序无法正常运行（因为根据 PE 规范，它已不再是 PE 文件了）。

### DOS 存根

DOS 存根（stub）在 DOS 头下方，是个可选项，且大小不固定（即使没有 DOS 存根，文件也能正常运行）。DOS 存根由代码与数据混合而成。

![](/pics/BIN集训/RE/三/4.png)

图中，文件偏移 40~4D 区域为 16 位的汇编指令。32 位的 Windos OS 中不会运行该命令（由于被识别为 PE 文件，所以完全忽视该代码）。在 DOS 环境中运行 `Notepad.exe` 文件，或者使用 DOS 调试器（`debug.exe`）运行它，可使其执行该代码（不认识 PE 文件格式，所以被识别为 DOS EXE 文件）。

在 Windows XP 下打开命令行窗口（`cmd.exe`），输入 `debug C:\Windows\notepad.exe`。输入 “u” 指令（Unassemble），将会出现 16 位的汇编指令。

```
-u
0B39:0000 0E            PUSH    CS
0B39:0001 1F            POP     DS
0B39:0002 BA0E00        MOV     DX,000E         ; DX = 0E : "This program cannot be run in DOS mode"
0B39:0005 B409          MOV     AH,09
0B39:0007 CD21          INT     21              ; AH = 09 : WriteString()
0B39:0009 B8014C        MOV     AX,4C01
0B39:000C CD21          INT     21              ; AX = 4C01 : Exit()
0B39:000E 54            PUSH    SP
0B39:000F 68            DB      68
0B39:0010 69            DB      69
0B39:0011 7320          JNB     0033
0B39:0013 7072          JO      0087
0B39:0015 6F            DB      6F
0B39:0016 67            DB      67
0B39:0017 7261          JB      007A
0B39:0019 6D            DB      6D
0B39:001A 206361        AND     [BP+DI+61],AH
0B39:001D 6E            DB      6E
0B39:001E 6E            DB      6E
0B39:001F 6F            DB      6F
```

代码非常简单，在画面中输出字符串 `"This program cannot be run in DOS mode"` 后就退出。换言之，`notepad.exe` 文件虽然是 32 位的 PE 文件，但是带有 MS-DOS 兼容模式，可以在 DOS 环境中运行，执行 DOS EXE 代码，输出 `"This program cannot be run in DOS mode"` 后终止。灵活使用该特性可以在一个可执行文件（EXE）中创建出另一个文件，它在 DOS 与 Windows 中都能运行（在 DOS 环境中运行 16 位 DOS 代码，在 Windows 环境中运行 32 位 Windows 代码）。

如前所述，DOS 存根是可选项，开发工具应该支它（VB、VC++、Delphi 等默认支持 DOS 存根）。

### NT 头

下面介绍 NT 头 `IMAGE_NT_HEADERS`。

```cpp
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                   // PE Signature : 50450000 ("PE"00)
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

`IMAGE_NT_HEADERS` 结构体由 3 个成员组成，第一个成员为签名（Signature）结构体，其值为 50450000h（"PE"00）。另外沥青个成员分别为文件头（File Header）与可选头（Optional Header）结构体。

![](/pics/BIN集训/RE/三/5.png)

`IMAGE_NT_HEADERS` 结构体的大小为 F8，相当大。

### NT 头：文件头

文件头是表现文件大致属性的 `IMAGE_FILE_HEADER` 结构体。

```cpp
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machinie;               // 运行平台
    WORD    NumberOfSections;       // 区块表的个数
    DWORD   TimeDateStamp;          // 文件创建时间，是从 1970 年至今的秒数
    DWORD   PointerToSymbolTable;   // 指向符号表的指针
    DWORD   NumberOfSymbols;        // 符号表的数目
    WORD    SizeOfOptionalHeader;   // IMAGE_NT_HEADERS 结构中 OptionHeader 成员的大小，对于 Win32 平台这个值通常是 0x00E0
    WORD    Characteriistics;       // 文件的属性值
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

`IMAGE_FILE_HEADERS` 结构体中有如下 4 中重要成员（若它们设置不正确，将导致文件无法正常运行）。

#### Machine

每个 CPU 都拥有唯一的 Machine 码，兼容 32 位 Intel x86 芯片的 Machine 码为 14C。以下是定义在 `winnt.h` 文件中的 Machine 码。

```cpp
#define IMAGE_FILE_MACHINE_UNKNOWN      0
#define IMAGE_FILE_MACHINE_I386         0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000        0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000        0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000       0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2    0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA        0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_POWERPC      0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_SH3          0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3E         0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4          0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_ARM          0x01c0  // ARM Little-endian
#define IMAGE_FILE_MACHINE_THUMB        0x01c2
#define IMAGE_FILE_MACHINE_IA64         0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16       0x0266  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU      0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16    0x0466  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64      0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_AXP64        IMAGE_FILE_MACHINE_ALPHA64
```

#### NumberOfSections

前面提到过，PE 文件把代码、数据、资源等依据属性分类到各节区中存储。

`NumberOfSections` 用来指出文件中存在的节区数量。该值一定要大于 0，且当定义的节区数量与实际节区不同时，将发生运行错误。

#### SizeOfOptionalHeader

`IMAGE_NT_HEADER` 结构体的最后一个成员为 `IMAGE_OPTIONAL_HEADER32` 结构体。`SizeOfOptionalHeader` 成员用来指出 `IMAGE_OPTIONAL_HEADER32` 结构体的长度。`IMAGE_OPTIONAL_HEADER32` 结构体由 C 语言编写而成，故其大小已经确定。但是 Windows 的 PE 装载器需要查看 `IMAGE_FILE_HEADER` 的 `SizeOfOptionalHeader` 值，从而识别出 `IMAGE_OPTIONAL_HEADER32` 结构体的大小。

PE32+ 格式的文件中使用的是 `IMAGE_OPTIONAL_HEADER64` 结构体，而不是 `IMAGE_OPTIONAL_HEADER32` 结构体。2 个结构体的尺寸是不同的，所以需要在 `SizeOfOptionalHeader` 成员中明确指出结构体的大小。

> 借助 `IMAGE_DOS_HEADER` 的 `e_lfanew` 成员与 `IMAGE_FILE_HEADER` 的 `SizeOfOptionalHeader` 成员，可以创建出一种脱离常规的 PE 文件（PE Patch）（也有人称之为 “麻花” PE 文件）

#### Characteristics

该字段用于标识文件的属性，文件是否可运行的形态、是否为 DLL 文件等信息，以 bit OR 形式组合起来。

以下是定义在 `winnt.h` 文件中的 `Characteristics` 值（请记住 0002h 与 2000h 这两个值）。

```cpp
#define IMAGE_FILE_RELOCS_STRIPPED          0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002  // File is executable
                                                    // (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED       0x0004  // Line numbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED      0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM        0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE      0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO        0x0080  // byte of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE            0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED           0x0200  // Debugging info stripped from
                                                    // file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400  // If Image is on removable media,
                                                    // copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP        0x0800  // If Image is on Net,
                                                    // copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                   0x1000  // System File.
#define IMAGE_FILE_DLL                      0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY           0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI        0x8000  // byte of machine word are reversed.
```

PE 中 `Characteristics` 的值有可能不是 0002h（不可执行），比如类似 `*.obj` 的 object 文件以及 resource DLL 文件等。

最后讲一下 `IMAGE_FILE_HEADER` 的 `TimeDateStamp` 成员。改成成员的值不影响文件运行，用来记录编译器创建此文件的时间。但是有些开发工具（VB、VC++）提供了设置该值的工具，而有些开发工具（Delphi）则未提供（且随所用选项的不同而不同）。

#### IMAGE_FILE_HEADER

`IMAGE_FILE_HEADER` 的结构体。

![](/pics/BIN集训/RE/三/6.png)

以结构体成员的形式表示如下。

```
[ IMAGE_FILE_HEADER ] - notepad.exe

 offset   value   description
--------------------------------------------------------------------------
000000E4     014C machine
000000E6     0003 number of sections
000000E8 48025287 time date stamp (Mon Apr 14 03:35:51 2008)
000000EC 00000000 offset to symble table
000000F0 00000000 number of symbols
000000F4     00E0 size of optional header
000000F6     010F characteristics
                      IMAGE_FILE_RELOCS_STRIPPED
                      IMAGE_FILE_EXECUTABLE_IMAGE
                      IMAGE_FILE_LINE_NUMS_STRIPPED
                      IMAGE_FILE_LOCAL_SYMS_STRIPPED
                      IMAGE_FILE_32BIT_MACHINE
```

### NT 头：可选头

`IMAGE_OPTIIONAL_HEADER32` 是 PE 头结构体中最大的。

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    // Standard fields.
    WORD    Magic;                          // 标志字, ROM 映像（0107h），普通可执行文件（010Bh）
    BYTE    MajorLinkerVersion;             // 链接程序的主版本号
    BYTE    MinorLinkerVersion;             // 链接程序的次版本号
    DWORD   SizeOfCode;                     // 所有含代码的节的总大小
    DWORD   SizeOfInitializedData;          // 所有含已初始化数据的节的总大小
    DWORD   SizeOfUninitializedData;        // 所有含未初始化数据的节的大小
    DWORD   AddressOfEntryPoint;            // 程序执行入口 RVA
    DWORD   BaseOfCode;                     // 代码的区块的起始 RVA
    DWORD   BaseOfData;                     // 数据的区块的起始 RVA
    // NT additional fields.
    DWORD   ImageBase;                      // 程序的首选装载地址
    DWORD   SectionAlignment;               // 内存中的区块的对齐大小，一般为 0x1000
    DWORD   FileAlignment;                  // 文件中的区块的对齐大小，一般为 0x200
    WORD    MajorOperatingSystemVersion;    // 要求操作系统最低版本号的主版本号
    WORD    MinorOperatingSystemVersion;    // 要求操作系统最低版本号的副版本号
    WORD    MajorImageVersion;              // 可运行于操作系统的主版本号
    WORD    MinorImageVersion;              // 可运行于操作系统的次版本号
    WORD    MajorSubsystemVersion;          // 要求最低子系统版本的主版本号
    WORD    MinorSubsystemVersion;          // 要求最低子系统版本的次版本号
    DWORD   Win32VersionValue;              // 莫须有字段，不被病毒利用的话一般为 0
    DWORD   SizeOfImage;                    // 映像装入内存后的总尺寸
    DWORD   SizeOfHeaders;                  // 所有头 + 区块表的尺寸大小
    DWORD   CheckSum;                       // 映像的校检和
    WORD    Subsystem;                      // 可执行文件期望的子系统
    WORD    DllCharacteristics;             // DllMain() 函数何时被调用，默认为 0
    DWORD   SizeOfStackReserve;             // 初始化时的栈大小
    DWORD   SizeOfStackCommit;              // 初始化时实际提交的栈大小
    DWORD   SizeOfHeapReserve;              // 初始化时保留的堆大小
    DWORD   SizeOfHeapCommit;               // 初始化时实际提交的堆大小
    DWORD   LoaderFlags;                    // 与调试有关，默认为 0
    DWORD   NumberOfRvaAndSizes;            // 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
    // 数据目录表，保存了各种表的RVA及大小
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

在 `IMAGE_OPTIONAL_HEADER32` 结构体中需要关注下列成员。这些值谁文件运行必需的，设置错误将导致文件无法正常运行。

#### Magic

为 `IMAGE_OPTIONAL_HEADER32` 结构体时，Magic 码为 10B；为 `IMAGE_OPTIONAL_HEADER64` 结构体时，Magic 码为 20B。

#### AddressOfEntryPoint

`AddressOfEntryPoint` 持有 EP 的 RVA 值。该值指出程序最先执行的代码起始地址，相当重要。

#### ImageBase

进程虚拟内存的范围时 0~FFFFFFFF（32 位系统）。PE 文件被加载到如此大的内存中时，`ImageBase` 指出文件的优先装入地址。

EXE、DLL 文件被装载到用户内存的 0~7FFFFFFF 中，SYS 文件被载入内核内存的 80000000~FFFFFFFF 中。一般而言，使用开发工具（VB/VC++/Delphi）创建好 EXE 文件后，其 `ImgaeBase` 的值为 00400000，DLL 文件的 `ImgaeBase` 值为 10000000（当然也可以指定为其他值）。执行 PE 文件时，PE 装载器先创建进程，再将文件载入内存，然后把 EIP 寄存器的值设置为 `ImageBase+AddressOfEntryPoint`。

#### SectiionAlignment，FileAlignment

PE 文件的 Body 部分划分为若干节区，这些节存储着不同类别的数据。`FileAlignment` 指定了节区在磁盘文件中的最小单位，而 `SectionAlignment` 则指定了节区在内存中的最小单位（一个文件中，`FileAlignment` 与 `SectionAlignment` 的值可能相同，也可能不同）。磁盘文件或内存的节区大小必定为 `FileAlignment` 或 `SectionAlignment` 值的整数倍。

#### SizeOfImage

加载 PE 文件到内存时，`SizeOfImage` 指定了 PE Image 在虚拟内存中所占的空间的大小。一般而言，文件的大小与加载到内存中的大小是不同的（节区头中定义了各节装载的位置与占有内存的大小）。

#### SizeOfHeader

`SizeOfHeader` 用来指出整个 PE 头的大小。该值也必须是 `FileAlignment` 的整数倍。第一节区所在位置与 `SizeOfHeader` 距文件开始偏移的量相同。

#### Subsystem

该 `Subsystem` 值用来区分系统驱动文件（`*.sys`）与普通的可执行文件（`*.exe`，`*.dll`）。`Subsystem` 成员可拥有的值如下。

| 值  |    含义     |               备注                |
| :-: | :---------: | :-------------------------------: |
|  1  | Driver 文件 |    系统驱动（如：`ntfs.sys`）     |
|  2  |  GUI 文件   | 窗口应用程序（如：`notepad.exe`） |
|  3  |  CUI 文件   |  控制台应用程序（如：`cmd.exe`）  |

#### NumberOfRvaAndSizes

`NumberOfRvaAndSizes` 用来指定 `DataDirectory`（`IMAGE_OPTIONAL_HEADER32` 结构体的最后一个成员）数组的个数。虽然结构体定义中明确指出了数组个数为 `IMAGE_NUMBEROF_DIRECTORY_ENTRIES(16)`，但是 PE 装载器通过查看 `NumberOfRvaAndSizes` 值来识别数组大小，换言之，数组大小也可能不是 16。

#### DataDirectory

`DataDirectory` 是由 `IMAGE_DATA_DIRECTORY` 结构体组成的数组，数组的每项都有被定义的值。

```cpp
DataDirectory[0] = EXPORT Directory
DataDirectory[1] = IMPORT Directory
DataDirectory[2] = RESOURCE Directory
DataDirectory[3] = EXCEPTION Directory
DataDirectory[4] = SECURITY Directory
DataDirectory[5] = BASERELOC Directory
DataDirectory[6] = DEBUG Directory
DataDirectory[7] = COPYRIGHT Directory
DataDirectory[8] = GLOBALPTR Directory
DataDirectory[9] = TLS Directory
DataDirectory[A] = LOAD_CONFIG Directory
DataDirectory[B] = BOUND_IMPORT Directory
DataDirectory[C] = IAT Directory
DataDirectory[D] = DELAY_IMPORT Directory
DataDirectory[E] = COM_DESCRIPTOR Directory
DataDirectory[F] = Reserved Directory
```

将此处所说的 `Directory` 想成某个结构体数组即可。比较重要的是`EXPORT/IMPORT/RESOURCE`、`TLS Direction`。

#### IMAGE_OPTIONAL_HEADER

`IMAGE_OPTIONAL_HEADER` 整个结构体。

![](/pics/BIN集训/RE/三/7.png)

结构体各成员的值及其说明如下。

```
[ IMAGE_OPTIONAL_HEADER ] - notepad.exe

 offset   value   description
--------------------------------------------------------------------------
000000F8     010B magic
000000FA       07 major liinker version
000000FB       0A minor liinker version
000000FC 00007800 size of code
00000100 00008C00 size of initialized data
00000104 00000000 size of uninitialized data
00000108 0000739D address of entry point
0000010C 00001000 base of code
00000110 00009000 base of data
00000114 01000000 image base
00000118 00001000 section alignment
0000011C 00000200 file alignment
00000120     0005 major OS version
00000122     0001 minor OS version
00000124     0005 major image version
00000126     0001 minor image version
00000128     0004 major subsystem version
0000012A     0000 minor subsystem version
0000012C 00000000 win32 version value
00000130 00014000 size of image
00000134 00000400 size of headers
00000138 000126CE Checksum
0000013C     0002 subsystem
0000013E     8000 DLL characteristics
00000140 00040000 size of stack reserve
00000144 00011000 size of stack commit
00000148 00100000 size of heap reserve
0000014C 00001000 size of heap commit
00000150 00000000 loader flags
00000154 00000010 number of directories
00000158 00000000 RVA  of EXPORT Directory
0000015C 00000000 size of EXPORT Directory
00000160 00007604 RVA  of IMPORT Directory
00000164 000000C8 size of IMPORT Directory
00000168 00000000 RVA  of RESOURCE Directory
0000016C 00008304 size of RESOURCE Directory
00000170 00000000 RVA  of EXCEPTION Directory
00000174 00000000 size of EXCEPTION Directory
00000178 00000000 RVA  of SECURITY Directory
0000017C 00000000 size of SECURITY Directory
00000180 00000000 RVA  of BASERELOC Directory
00000184 00000000 size of BASERELOC Directory
00000188 00001350 RVA  of DEBUG Directory
0000018C 0000001C size of DEBUG Directory
00000190 00000000 RVA  of COPYRIGHT Directory
00000194 00000000 size of COPYRIGHT Directory
00000198 00000000 RVA  of GLOBALPTR Directory
0000019C 00000000 size of GLOBALPTR Directory
000001A0 00000000 RVA  of TLS Directory
000001A4 00000000 size of TLS Directory
000001A8 000018A8 RVA  of LOAD_CONFIG Directory
000001AC 00000040 size of LOAD_CONFIG Directory
000001B0 00000250 RVA  of BOUND_IMPORT Directory
000001B4 000000D0 size of BOUND_IMPORT Directory
000001B8 00001000 RVA  of IAT Directory
000001BC 00000348 size of IAT Directory
000001C0 00000000 RVA  of DELAY_IMPORT Directory
000001C4 00000000 size of DELAY_IMPORT Directory
000001C8 00000000 RVA  of COM_DESCRIPTOR Directory
000001CC 00000000 size of COM_DESCRIPTOR Directory
000001D0 00000000 RVA  of Reserved Directory
000001D4 00000000 size of Reserved Directory
```

### 节区头

节区头中定义了各节区属性。前面提到过，PE 文件中的 code（代码）、data（数据）、resource（资源）等按照属性分类存储在不同节区。

把 PE 文件创建成多个节区结构的好处是可以保证程序的安全性。若把 code 与 data 放在一个节区中相互纠缠很容易引发安全问题，即使忽略过程的烦琐。

假如向字符串 data 写数据时，由于某个原因导致溢出（输入超过缓冲区大小时），那么其下的 code（指令）就会被覆盖，应用程序就会崩溃。因此，PE 文件格式的设计者们决定把具有相似属性的数据统一保存在一个被称为 “节区” 的地方，然后需要把各节区属性记录在节区头中（节区属性中有文件/内存的起始位置、大小、访问权限等）。

换言之，需要为每个 code/data/resource 分别设置不同的特性、访问权限等，如下表。

|   类别   |     访问权限     |
| :------: | :--------------: |
|   code   |  执行，读取权限  |
|   data   | 非执行，读写权限 |
| resource | 非执行，读取权限 |

#### IMAGE_SECTION_HEADER

节区头是由 `IMAGE_SECTION_HEADER` 结构体组成的数组，每个结构体对应一个节区。

```cpp
# define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];  // 区块的名称，如 “.text”
    union {
            DWORD   PhysicalAddress;        // 物理地址
            DWORD   VirtualSize;            // 真实长度，这两个值是一个联合结构，可以使用其中的任何一个，一般是取后一个
    } Misc;
    DWORD   VirtualAddress;                 // 节区的 RVA 地址
    DWORD   SizeOfRawData;                  // 在文件中对齐后的尺寸
    DWORD   PointerToRawData;               // 在文件中的偏移量
    DWORD   PointerToRelocations;           // 在 OBJ 文件中使用，重定位的偏移
    DWORD   PointerToLinenumbers;           // 行号表的偏移（供调试使用地)
    WORD    NumberOfRelocations;            // 在 OBJ 文件中使用，重定位项数目
    WORD    NumberOfLinenumbers;            // 行号表中行号的数目
    DWORD   Characteristics;                // 节属性如可读，可写，可执行等
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

下表中列出了 `IMAGE_SECTION_HEADER` 结构体中要了解的重要成员（不使用其他成员）。

|        项目        |           含义            |
| :----------------: | :-----------------------: |
|   `VirtualSize`    |    内存中节区所占大小     |
|  `VirtualAddress`  | 内存中节区起始地址（RVA） |
|  `SizeOfRawData`   |  磁盘文件中节区所占大小   |
| `PointerToRawData` |  磁盘文件中节区起始位置   |
| `Characteristics`  |    节区属性（bit OR）     |

`VirtualAddress` 与 `PointerToRawData` 不带有任何值，分别由（定义在 `IMAGE_OPTIONAL_HEADER32` 中的）`SectionAlignment` 与 `FileAlignment` 确定。

`VirutalSize` 与 `SizeOfRawData` 一般具有不同的值，即磁盘文件中节区的大小与加载到内存中的节区大小是不同的。

`Characteristics` 由以下代码中现实的值组合（bit OR）而成。

```cpp
#define IMAGE_SCN_CNT_CODE                0x00000020 // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040 // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080 // Section contains uninitialized data.
#define IMAGE_SCN_MEM_EXECUTE             0x20000000 // Section is executable.
#define IMAGE_SCN_MEM_READ                0x40000000 // Section is readable.
#define IMAGE_SCN_MEM_WRITE               0x80000000 // Section is writable.
```

最后讲一下 Name 字段。Name 成员不像 C 语言中的字符串一样以 NULL 结束，并且没有 “必须使用 ASCII 值” 的限制。PE 规范未明确规定节区的 Name，所以可以向其中仿佛任何值，甚至可以填充 NULL 值。所以节区的 Name 仅供参考，不能保证其百分之百地被用作某种信息（数据节区的名称也可叫做 `.code`）。

![](/pics/BIN集训/RE/三/8.png)

各结构体成员如下。

```
[ IMAGE_SECTION_HEADER ]

 offset   value   description
--------------------------------------------------------------------------
000001D8 2E746578 Name (.text)
000001DC 74000000
000001E0 00007748 virtual size
000001E4 00001000 RVA
000001E8 00007800 size of raw data
000001EC 00000400 offset to raw data
000001F0 00000000 offset to relocations
000001F4 00000000 offset to line numbers
000001F8     0000 number of relocations
000001FA     0000 number of line numbers
000001FC 60000020 characteristics
                    IMAGE_SCN_CNT_CODE
                    IMAGE_SCN_MEM_EXECUTE
                    IMAGE_SCN_MEM_READ

00000200 2E646174 Name (.data)
00000204 61000000
00000208 00001BA8 virtual size
0000020C 00009000 RVA
00000210 00000800 size of raw data
00000214 00007C00 offset to raw data
00000218 00000000 offset to relocations
0000021C 00000000 offset to line numbers
00000220     0000 number of relocations
00000222     0000 number of line numbers
00000224 C0000040 characteristics
                    IMAGE_SCN_CNT_INITIALIZED_DATA
                    IMAGE_SCN_MEM_READ
                    IMAGE_SCN_MEM_WRITE

00000228 2E727372 Name (.rsrc)
0000022C 63000000
00000230 00008304 virtual size
00000234 0000B000 RVA
00000238 00008400 size of raw data
0000023C 00008400 offset to raw data
00000240 00000000 offset to relocations
00000244 00000000 offset to line numbers
00000248     0000 number of relocations
0000024A     0000 number of line numbers
0000024C 40000040 characteristics
                    IMAGE_SCN_CNT_INITIALIZED_DATA
                    IMAGE_SCN_MEM_READ
```

> 讲解 PE 文件时经常出现 “映像” （Image）这一术语。PE 文件加载到内存时，文件不会原封不动地加载，而要根据节区头中定义的节区起始地址、节区大小等加载。因此，磁盘文件中的 PE 与内存中的 PE 具有不同形态。将装载到内存中的形态称为 “映像” 以示区别。

## RVA to RAW

PE 文件加载到内存时，每个节区都要能准确完成内存骶椎与文件偏移间的映射。这种映射一般称为 RVA to RAW，方法如下。

1. 查找 RVA 所在节区。
2. 使用简单的公式计算文件偏移（RAW）。

根据 `IMAGE_SECTION_HEADER` 结构体，换算公式如下：

```
RAW - PointerToRawData = RVA - VirtualAddress
                   RAW = RVA - VirtualAddress + PointerToRawData
```

## IAT

IAT（Import Address Table，导入地址表）保存的内容与 Windows 操作系统的核心进程、内存、DLL 结构等有关。换句话说，只要理解了 IAT，就掌握了 Windows 操作系统的根基。简言之 IAT 是一种表格，用来记录程序正在使用哪些库中的哪些函数。

> RVA 与 RAW（文件偏移）间的相互变换是 PE 头的最基本的内容。

### DLL

DLL（Dynamic Linked Library）撑起了整座 Windows OS 大厦，它被翻译成 “动态链接库”。

16 位的 DOS 时代不存在 DLL 这一概念，只有 “库”（Library）一说。比如在 C 语言中使用 `printf()` 函数时，编译器会先从 C 库中读取相应函数的二进制代码，然后插入（包含到）应用程序。也就是说，可执行文件中包含着 `printf()` 函数的二进制代码。Windows OS 支持多任务，若仍采用这种包含库的方式，会非常没有效率。Windows 操作系统使用了数量庞大的库函数（进程、内存、窗口、消息等）来支持 32 位的 Windows 环境。同时运行多个程序时，若仍像以前一样每个程序运行时都包含相同的库，将造成严重的内存浪费（当然磁盘空间的浪费也不容小嘘）。因此，Windows OS 设计者们根据需要引入了 DLL 这一概念，描述如下。

- 不要把库包含到程序中，单独组成 DLL 文件，需要时调用即可。
- 内存映射技术使加载后的 DLL 代码、资源在多个进程中实现共享。
- 更新库时只要替换相关 DLL 文件即可，简便易行。

加载 DLL 的方式实际有两种：一种是 “显式链接”（Explicit Linking），程序使用 DLL 时加载，使用完毕后释放内存；另一种是 “隐式链接”（Implicit Linking），程序开始时即一同加载 DLL，程序终止时再释放占用的内存。IAT 提供的机制即与隐式链接有关。接下来用 OllyDbg 打开 `notepad.exe` 来查看 IAT，下图是 `CreateFileW()` 函数的代码，该函数位于 kernel32.dll 中。

![](/pics/BIN集训/RE/三/9.png)

调用 `CreateFileW()` 函数时并非直接调用，而是通过获取 01001104 地址处的值来实现（所有 API 调用均采用这种方式）。

地址 01001104 是 `notepad.exe` 中 `.text` 节区的内存区域（更确切地说是 IAT 内存区域）。01001104 地址的值为 7C8107F0，而 7C8107F0 地址即是加载到 `notepad.exe` 进程内存中的 `CreateFileW()` 函数（位于 kernel32.dll 库中）的地址。

那么为什么不直接 `CALL 7C8107F0` 呢？事实上，`notepad.exe` 程序的制作者编译（生成）程序时，并不知道该 `notepad.exe` 程序运行在哪种 Windows（9X、2K、XP、Vista、7 等）、哪种语言（ENG、JPN、KOR 等）、哪种服务包（Service Pack）下。上面列举出的所有环境中，kernel32.dll 的版本各不相同，`CreateFileW()` 函数的位置（地址）也不相同。为了确保在所有环境中都能正常地调用 `CreateFileW()` 函数，编译器准备了要保存 `CreateFileW()` 函数实际地址的位置（01001104），并记下 `CALL DWORD PTR DS:[01001104]` 形式的指令。执行文件时，PE 装载器将 `CreateFileW()` 函数的地址写到 01001104 位置。

编译器不使用 `CALL 7C8107F0` 语句的另一个原因在于 DLL 重定位。DLL 文件的 ImageBase 值一般为 10000000。比如某个程序使用 a.dll 与 b.dll 时，PE 装载器先把 a.dll 装载到内存的 10000000（ImageBase）处，然后尝试把 b.dll 也装载到该处。但是由于该地址处已经装载了 a.dll，所以 PE 装载器查找其他空白的内存空间（ex：3E000000），然后将 b.dll 装载进去。

这就是所谓的 DLL 重定位，它使我们无法对实际地址硬编码。另一个原因在于，PE 头中表示地址时不使用 VA，而是 RVA。

> 实际操作中无法保证 DLL 一定会被加载到 PE 头内指定的 ImageBase 处。但是 EXE 文件（生成进程的主体）却能准确加载到自身的 ImageBase 中，因为它拥有自己的虚拟空间。

PE 头的 IAT 是代码逆向分析的核心内容。

### IMAGE_IMPORT_DESCRIPTOR

`IMAGE_IMPORT_DESCRIPTOR` 结构体中记录着 PE 文件要导入哪些库文件。

> Import：导入，向库提供服务（函数）。
> Export：导出，从库向其他 PE 文件提供服务（函数）。

`IMAGE_IMPORT_DESCRIPTOR` 结构体如下所示。

```cpp
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristiics;
        DWORD   OriginalFirstThunk;     // INT(Import Name Table) address (RVA)
    }
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;                       // library name string address (RVA)
    DWORD   FirstThunk;                 // IAT(Import Address Table) address (RVA)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORTBY_NAME {
    WORD    Hint;                       // ordinal
    BYTE    Name[1];                    // function name string
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

执行一个普通程序时往往需要导入多个库，导入多少库就存在多少个 `IMAGE_IMPORT_DESCRIPTOR` 结构体，这些结构体形成了数组，且结构体数组最后以 NULL 结构体结束。`IMAGE_IMPORT_DESCRIPTOR` 中重要的成员如下表所示（拥有全部 RVA 值）。

|        项目        |           含义            |
| :----------------: | :-----------------------: |
| OriginalFirstThunk |     INT 的地址（RVA）     |
|        Name        | 库名称字符串的地址（RVA） |
|     FirstThunk     |     IAT 的地址（RVA）     |

> PE 头中提到的 “Table” 即指数组。
> INT 与 IAT 是长整型（4 个字节数据类型）数组，以 NULL 结束（未另外明确指出大小）。
> INT 中各元素的值为 IMAGE_IMPORT_BY_NAME 结构体指针（有时 IAT 也拥有相同的值）。
> INT 与 IAT 的大小应相同。

下图为 `notepad.exe` 之 kernel32.dll 的 `IMAGE_IMPORT_DESCRIPTOR` 结构。

![](/pics/BIN集训/RE/三/10.png)

INT 与 IAT 的各元素同时指向相同地址，但也有很多情况下它们是不一致的。

下面为 PE 装载器把导入函数输入之 IAT 的顺序。

1. 读取 IID 的 Name 成员，获取库名称字符串（“kernel32.dll”）。
2. 装载相应库。-> `LoadLibrary("kernel32.dll")`
3. 读取 IID 的 OriginialFirstThunk 成员，获取 INT 地址。
4. 逐一读取 INT 中数组的值，获取相应 IMAGE_IMPORT_BY_NAME 地址（RVA）。
5. 使用 IMAGE_IMPORT_BY_NAME 的 Hint（ordinal）或 Name 项，获取相应函数的起始地址。-> `GetProcAddress("GetCurrentThreadld")`
6. 读取 IID 的 FirstThunk（IAT）成员，获得 IAT 地址。
7. 将上面获得的函数地址输入相应 IAT 数组值。
8. 重复以上步骤 4~7，直到 INT 结束（遇到 NULL 时）。

## EAT

Windows 操作系统中，“库” 是为了方便其他程序调用而集中包含相关函数的文件（DLL/SYS）。Win32 API 是最具代表性的库，其中的 kernel32.dll 文件被称为最核心的库文件。

EAT 是一种核心机制，它使不同应用程序可以调用库文件中提供的函数。也就是说，只有通过 EAT 才能准确求得从相应库中导出函数的起始地址。与 IAT 一样，PE 文件内的特定结构体（`IMAGE_EXPORT_DIRECTORY`）保存着导出信息，且 PE 文件中仅有一个用来说明库 EAT 的 `IMAGE_EXPORT_DIRECTORY` 结构体。

> 用来说明 IAT 的 IMAGE_IMPORT_DESCRIPTOR 结构体以数组形式存在，且拥有多个成员。这样是因为 PE 文件可以同时导入多个库。

可以在 PE 文件的 PE 头查找到 `IMAGE_EXPORT_DIRECTORY` 结构体的位置。`IMAGE_OPTIONAL_HEADER32.DataDirectory[0].VirtualAddress` 值即是 `IMAGE_EXPORT_DIRECTORY` 的起始地址（也是 RVA 的值）。

下图显示的是 kernel32.dll 文件的 `IMAGE_OPTIONAL_HEADER32.DataDirectory[0]`（第一个 4 字节为 VirtualAddress，第二个 4 字节为 Size 成员）。

![](/pics/BIN集训/RE/三/11.png)

`IMAGE_OPTIONAL_HEADER32.DataDirectory` 结构体数组信息整理如下表。

|   偏移   |    值    |           说明           |
| :------: | :------: | :----------------------: |
| 00000160 | 00000000 |       loader flags       |
| 00000164 | 00000010 |  number of directories   |
| 00000168 | 0000262C | RVA of EXPORT Directory  |
| 0000016C | 00006D19 | size of EXPORT Directory |
| 00000170 | 00081898 | RVA of IMPORT Directory  |
| 00000174 | 00000028 | size of IMPORT Directory |

由于 RVA 值为 262C，所以文件偏移为 1A2C。

### IMAGE_EXPORT_DIRECTORY

`IMAGE_EXPORT_DIRECTORY` 结构体如下。

```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWROD   TimeDateStamp;          // creation time date stamp
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;                   // address of library file name
    DWORD   Base;                   // ordinal base
    DWORD   NumberOfFunctions;      // number of functions
    DWORD   NumberOfNames;          // number of names
    DWORD   AddressOfFunctions;     // address of function start address array
    DWORD   AddressOfNames;         // address of function name string array
    DWORD   AddressOfNameOrdinals;  // address of ordinal array
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

下表为其中的重要成员（全部地址均为 RVA）。

|         项目          |                          含义                          |
| :-------------------: | :----------------------------------------------------: |
|   NumberOfFunctions   |                 实际 Export 函数的个数                 |
|     NumberOfNames     |              Export 函数中具名的函数个数               |
|  AddressOfFunctions   | Export 函数地址数组（数组元素个数=AddressOfFunctions） |
|    AddressOfNames     |    函数名称地址数组（数组元素个数=AddressOfNames）     |
| AddressOfNameOrdinals |    Ordinal 地址数组（数组元素个数=AddressOfNames）     |

下图是 kernel32.dll 文件的 `IMAGE_EXPORT_DIRECTORY` 结构体与整个 EAT 结构。

![](/pics/BIN集训/RE/三/12.jpeg)

从库中获得函数地址的 API 为 `GetProcAddress()` 函数。该 API 引用 EAT 来获取指定 API 的地址。`GetProcAddress()` API 拥有函数名称，以下为它获取函数地址的过程。

1. 利用 AddressOfNames 成员转到 “函数名称数组”。
2. “函数名称数组” 中存储着字符串地址。通过比较（strcmp）字符串，查找指定的函数名称（此时数组的索引称为 name_index）。
3. 利用 AddressOfNameOrdinals 成员，转到 ordinal 数组。
4. 在 ordinal 数组中通过 name_index 查找相应的 ordinal 值。
5. 利用 AddressOfFunctions 成员转到 “函数地址数组”（EAT）。
6. 在 “函数地址数组” 中将刚刚求得的 ordinal 用作数组索引，获得指定函数的起始地址。

kernel32.dll 中所有导出函数均有相应名称，AddressOfNameOrdinals 数组的值以 index=ordinal 的形式存在。但并不是所有的 DLL 文件都如此。导出函数中也有一些函数没有名称（仅通过 ordinal 导出），AddressOfNameOrdinals 数组的值为 index!=ordinal。所以只有按照上面的顺序才能获得准确的函数地址。

> 对于没有函数名称的导出函数，可以通过 Ordinal 查找到它们的地址。从 Ordinal 值中减去 IMAGE_EXPORT_DIRECTORY.Base 成员后得到一个值，使用该值作为 “函数地址数组” 的索引，即可查找到相应函数的地址。

# Reference

[《逆向工程核心原理》](https://reversecore.com/)
https://bbs.pediy.com/thread-247114.htm
https://bbs.pediy.com/thread-247303.htm
