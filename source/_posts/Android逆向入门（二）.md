---
title: Android逆向入门（二）
date: 2020-01-31 16:10:49
tags: [re, android]
---

Android JNI 编程及 ARM 汇编入门。

<!-- more -->

# Environment

Android Studio 3.5.3

# JNI

Android 程序分两层，Java 层和 Native 层。Java 层就是 Java 代码编译为 dex 文件，而 Native 层则是 C++ 代码编译为 so 文件（动态库）。两者使用 JNI（Java Native Interface）来进行链接。相比于 Java，Native 层安全性更加高，隐蔽性更加好，某种情况下效率更加高。Java 是跨平台的语言，而这跨平台的背后都是依靠 Java 虚拟机，虚拟机采用 C/C++ 编写，适配各个系统，通过 JNI 为上层 Java 提供各种服务，保证跨平台性。Java 程序中通过 JVM 加载并调用 JNI 程序来间接地调用目标原生函数。

![](/pics/Android逆向入门/二/1.png)

如果要进行 JNI 开发，直接在 Android Studio 中新建一个 C++ 项目即可。在调试过程中，可以新建一个 `log.h` 定义几个在 C++ 文件中进行日志输出的函数：

```cpp
#include <android/log.h>

#ifndef LOG_TAG
#define LOG_TAG "MY_TAG"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#endif
```

在 Java 文件中添加日志输出：

```java
public class MainActivity extends AppCompatActivity {
    ...

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ...
        Log.d("Debug", "infomation");
    }
    ...
}
```

在需要调用 JNI 的函数中加载动态库：

```java
public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }
    ...
}
```

## Native 函数注册

### 静态注册

静态注册的理解和使用方式简单，出错率低。但必须遵循注册规则，当需要更改类名、包名或者方法时，需要按照之前方法重新生成头文件，灵活性不高。

Java 文件中的 Native 声明：

```java
public native String sayHello();
```

静态注册在 cpp 文件中通过 JNIEXPORT 和 JNICALL 两个宏定义声明，在虚拟机加载 so 时发现上面两个宏定义的函数时就会链接到对应的 native 方法。so 中的名字为类名 + 函数名的组合，并且自带两个参数，即 `JNIEnv* env` 和 `jclass`（static 方法时）/`jobject`（普通方法时）：

```cpp
#include <jni.h>
#include <string>
#include "log.h"

extern "C" {
JNIEXPORT jstring JNICALL
Java_com_assassinq_easycpp_MainActivity_sayHello(JNIEnv *env, jobject obj) {
    return env->NewStringUTF("Hello World");
}
}
```

静态注册有一些缺点：

1. Native 函数名称特别长，不利于书写；
2. 每次新增或删除接口时需要重新生成文件，比较繁琐；
3. 第一次调用时需要根据函数名建立索引，影响效率；
4. JNI 层的函数名是由 Java 接口名生成，很容易通过 hook 调用动态库中的函数。

### 动态注册

动态注册在 JNI 层通过重载 `JNI_OnLoad()` 函数来实现，系统初始化 JNI 在加载时，会调用 `JNI_OnLoad()`，而卸载时会调用 `JNI_UnLoad()`。原理是通过自定义方法把 C/C++ 函数映射到 JAVA 定义的方法，不需要通过 JAVA 方法名查找匹配 Native 函数名，也就不需要遵循静态注册的命名规则。

cpp 文件中的函数定义如下：

```cpp
jstring sayHi(JNIEnv *env, jobject obj) {
    return env->NewStringUTF("Hi World");
}
```

通过内置函数 `RegisterNatives()` 实现自定义的注册方法：

```cpp
static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
```

定义 gClassName 和 gMethods 两个变量，分别表示需要查找的类名和需要注册的方法信息：

```cpp
static const char *gClassName = "com/assassinq/easycpp/MainActivity";
static JNINativeMethod gMethods[] = {
        {"sayHi", "()Ljava/lang/String;", (void *) sayHi},
};
```

其中方法信息的结构体如下，第一个变量为方法名，第二个变量为方法签名（字符串类型，以 Smali 代码的方式），第三个变量为对应的函数指针：

```cpp
typedef struct {
    const char* name; // native 的方法名
    const char* signature; // 方法签名，例如 ()Ljava/lang/String;
    void*       fnPtr; // 函数指针
} JNINativeMethod;
```

最后重写 `JNI_OnLoad()` 函数：

```cpp
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("This jni version is not supported");
        return -1;
    }
    if (registerNativeMethods(env, gClassName, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) == JNI_FALSE) {
        LOGE("Unable to register native methods");
        return -1;
    }
    LOGE("Methods loaded successfully");
    return JNI_VERSION_1_6;
}
```

## so 动态链接库

在编译过程中，可以修改 app 目录下的 build.gradle 中的内容，使用 android.defaultConfig.ndk.abiFilters 来指示 Gradle 要构建和打包的 ABI 版本，生成不同架构下的动态链接库：

```
android {
    ...
    defaultConfig {
        ...
        ndk {
            abiFilters "armeabi-v7a", "arm64-v8a", "x86", "x86_64"
        }
    }
    ...
}
```

so 文件一般存放在 apk 的 lib 目录下（NDK r17 版本开始已经去掉了 armeabi、mips、mips64 的 ABI 支持）：

- armeabi-v7a：第 7 代及以上的 ARM 处理器。2011 年 15 月以后的生产的大部分 Android 设备都使用它。
- arm64-v8a：第 8 代、64 位 ARM 处理器，很少设备，三星 Galaxy S6 是其中之一。
- armabi：第 5 代、第 6 代的 ARM 处理器，早期的手机用的比较多。
- x86：Intel x86（平板、模拟器用得比较多）。
- x86_64：Intel x64（64 位的平板）。
- ...

## IDA 反编译 so 文件

用 IDA 打开编译后的 apk，可以看到 lib 中存在一个 libnative-lib.so：

![](/pics/Android逆向入门/二/2.png)

查看静态注册函数的反编译结果：

```cpp
int __fastcall Java_com_assassinq_easycpp_MainActivity_sayHello(_JNIEnv *a1)
{
  return _JNIEnv::NewStringUTF(a1, "Hello World");
}
```

查看动态注册的函数的反编译结果：

```cpp
int __fastcall sayHi(_JNIEnv *a1)
{
  return _JNIEnv::NewStringUTF(a1, "Hi World");
}
```

# IDA 动态调试 apk

1. 安装 apk 到手机：`adb install example.apk`
2. 将 IDA 目录下的调试文件 push 到手机上：`adb push android_server /data/local/tmp`
3. 赋给程序可执行权限：`chmod 777 android_server`
4. 启动调试服务端：`./android_server` （自定义设置端口方式：`-p23333`）
5. 手机端端口转发至电脑端：`adb forward tcp:[pc_port] tcp:[mobile_port]`
6. IDA 调试端口设置：Debugger->Process option
7. 在 Debugger setup 中勾选 Suspend on process entry point、Suspend on thread start/exit 以及 Suspend on library load/unload
8. 启动程序：`adb shell am start -D -n packageName/activityName`
9. IDA 挂接到 Native 层：Debugger->Attach to process...
10. 打开 monitor，监听并挂接到 JAVA 层：`jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700`

![](/pics/Android逆向入门/二/3.png)

PS：如果在 monitor 中没有找到对应的进程，检查一下调试的程序中 AndroidManifest.xml 中是否设置了 `android:debuggable="true"`（若没有则修改后并重新打包）。

# 动态链接库文件（.so 文件）

加载顺序：

```
init_array -> JNI_OnLoad -> ... -> fini_array
```

## so 文件查看工具

### readelf

| 参数 |                          功能                          |
| :--: | :----------------------------------------------------: |
| `-a` |                 显示 so 文件的所有信息                 |
| `-h` |                    显示 ELF 文件头                     |
| `-l` |       显示 Program Headers，动态加载时需要的信息       |
| `-S` |     显示 Section Headers，静态加载分析时需要的信息     |
| `-e` | 显示 ELF Header、Section Headers、Program Headers 信息 |
| `-s` |               显示符号表（Symbol Table）               |
| `-d` |            显示动态节区（Dynamic Section）             |

显示 ELF 文件头：

```bash
$ readelf -h libnative-lib.so
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          12932 (bytes into file)
  Flags:                             0x5000200, Version5 EABI, soft-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         8
  Size of section headers:           40 (bytes)
  Number of section headers:         27
  Section header string table index: 26
```

显示 Program headers：

```bash
$ readelf -l libnative-lib.so

Elf file type is DYN (Shared object file)
Entry point 0x0
There are 8 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00000034 0x00000034 0x00100 0x00100 R   0x4
  LOAD           0x000000 0x00000000 0x00000000 0x02ab6 0x02ab6 R E 0x1000
  LOAD           0x002e3c 0x00003e3c 0x00003e3c 0x001dc 0x001dd RW  0x1000
  DYNAMIC        0x002e8c 0x00003e8c 0x00003e8c 0x00110 0x00110 RW  0x4
  NOTE           0x000134 0x00000134 0x00000134 0x000bc 0x000bc R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  EXIDX          0x0021f4 0x000021f4 0x000021f4 0x001b8 0x001b8 R   0x4
  GNU_RELRO      0x002e3c 0x00003e3c 0x00003e3c 0x001c4 0x001c4 RW  0x4

 Section to Segment mapping:
  Segment Sections...
   00
   01     .note.android.ident .note.gnu.build-id .dynsym .dynstr .gnu.hash .hash .gnu.version .gnu.version_d .gnu.version_r .rel.dyn .rel.plt .plt .text .ARM.exidx .ARM.extab .rodata
   02     .fini_array .data.rel.ro .dynamic .got .data .bss
   03     .dynamic
   04     .note.android.ident .note.gnu.build-id
   05
   06     .ARM.exidx
   07     .fini_array .data.rel.ro .dynamic .got
```

显示 Section headers：

```bash
$ readelf -S libnative-lib.so
There are 27 section headers, starting at offset 0x3284:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.android.ide NOTE            00000134 000134 000098 00   A  0   0  4
  [ 2] .note.gnu.build-i NOTE            000001cc 0001cc 000024 00   A  0   0  4
  [ 3] .dynsym           DYNSYM          000001f0 0001f0 000190 10   A  4   1  4
  [ 4] .dynstr           STRTAB          00000380 000380 0001d3 00   A  0   0  1
  [ 5] .gnu.hash         GNU_HASH        00000554 000554 00004c 04   A  3   0  4
  [ 6] .hash             HASH            000005a0 0005a0 0000b0 04   A  3   0  4
  [ 7] .gnu.version      VERSYM          00000650 000650 000032 02   A  3   0  2
  [ 8] .gnu.version_d    VERDEF          00000684 000684 00001c 00   A  4   1  4
  [ 9] .gnu.version_r    VERNEED         000006a0 0006a0 000040 00   A  4   2  4
  [10] .rel.dyn          REL             000006e0 0006e0 0000e8 08   A  3   0  4
  [11] .rel.plt          REL             000007c8 0007c8 000088 08  AI  3  20  4
  [12] .plt              PROGBITS        00000850 000850 0000e0 00  AX  0   0  4
  [13] .text             PROGBITS        00000930 000930 0018c4 00  AX  0   0  4
  [14] .ARM.exidx        ARM_EXIDX       000021f4 0021f4 0001b8 08  AL 13   0  4
  [15] .ARM.extab        PROGBITS        000023ac 0023ac 0001a4 00   A  0   0  4
  [16] .rodata           PROGBITS        00002550 002550 000566 01 AMS  0   0  1
  [17] .fini_array       FINI_ARRAY      00003e3c 002e3c 000008 04  WA  0   0  4
  [18] .data.rel.ro      PROGBITS        00003e44 002e44 000048 00  WA  0   0  4
  [19] .dynamic          DYNAMIC         00003e8c 002e8c 000110 08  WA  4   0  4
  [20] .got              PROGBITS        00003f9c 002f9c 000064 00  WA  0   0  4
  [21] .data             PROGBITS        00004000 003000 000018 00  WA  0   0  4
  [22] .bss              NOBITS          00004018 003018 000001 00  WA  0   0  1
  [23] .comment          PROGBITS        00000000 003018 000109 01  MS  0   0  1
  [24] .note.gnu.gold-ve NOTE            00000000 003124 00001c 00      0   0  4
  [25] .ARM.attributes   ARM_ATTRIBUTES  00000000 003140 000034 00      0   0  1
  [26] .shstrtab         STRTAB          00000000 003174 00010f 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
```

显示符号表：

```bash
$ readelf -s libnative-lib.so

Symbol table '.dynsym' contains 25 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND __cxa_atexit@LIBC (2)
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND __cxa_finalize@LIBC (2)
     3: 00000000     0 OBJECT  GLOBAL DEFAULT  UND __stack_chk_guard@LIBC (2)
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@LIBC (2)
     5: 00000000     0 FUNC    GLOBAL DEFAULT  UND __android_log_print
     6: 00000000     0 OBJECT  GLOBAL DEFAULT  UND __sF@LIBC (2)
     7: 00000000     0 FUNC    GLOBAL DEFAULT  UND abort@LIBC (2)
     8: 00000000     0 FUNC    GLOBAL DEFAULT  UND fflush@LIBC (2)
     9: 00000000     0 FUNC    GLOBAL DEFAULT  UND fprintf@LIBC (2)
    10: 00000000     0 FUNC    GLOBAL DEFAULT  UND dladdr@LIBC (3)
    11: 00000000     0 FUNC    GLOBAL DEFAULT  UND __aeabi_memclr8
    12: 00000000     0 FUNC    GLOBAL DEFAULT  UND __aeabi_memcpy
    13: 00000000     0 FUNC    GLOBAL DEFAULT  UND __gnu_Unwind_Find_exidx
    14: 00000000     0 FUNC    GLOBAL DEFAULT  UND snprintf@LIBC (2)
    15: 00004018     0 NOTYPE  GLOBAL DEFAULT  ABS _edata
    16: 00004019     0 NOTYPE  GLOBAL DEFAULT  ABS _end
    17: 00000975    36 FUNC    GLOBAL DEFAULT   13 Java_com_assassinq_easycp
    18: 00000999    44 FUNC    WEAK   DEFAULT   13 _ZN7_JNIEnv12NewStringUTF
    19: 00000b87    72 FUNC    WEAK   DEFAULT   13 _ZN7_JNIEnv15RegisterNati
    20: 00000b5d    42 FUNC    WEAK   DEFAULT   13 _ZN7_JNIEnv9FindClassEPKc
    21: 00004018     0 NOTYPE  GLOBAL DEFAULT  ABS __bss_start
    22: 000009e9   224 FUNC    GLOBAL DEFAULT   13 JNI_OnLoad
    23: 00000ac9    52 FUNC    WEAK   DEFAULT   13 _ZN7_JavaVM6GetEnvEPPvi
    24: 000009c5    36 FUNC    GLOBAL DEFAULT   13 sayHi
```

显示 Dynamic Section：

```bash
$ readelf -d libnative-lib.so

Dynamic section at offset 0x2e8c contains 29 entries:
  Tag        Type                         Name/Value
 0x00000003 (PLTGOT)                     0x3fb0
 0x00000002 (PLTRELSZ)                   136 (bytes)
 0x00000017 (JMPREL)                     0x7c8
 0x00000014 (PLTREL)                     REL
 0x00000011 (REL)                        0x6e0
 0x00000012 (RELSZ)                      232 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffa (RELCOUNT)                   26
 0x00000006 (SYMTAB)                     0x1f0
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000005 (STRTAB)                     0x380
 0x0000000a (STRSZ)                      467 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x554
 0x00000004 (HASH)                       0x5a0
 0x00000001 (NEEDED)                     Shared library: [liblog.so]
 0x00000001 (NEEDED)                     Shared library: [libm.so]
 0x00000001 (NEEDED)                     Shared library: [libdl.so]
 0x00000001 (NEEDED)                     Shared library: [libc.so]
 0x0000000e (SONAME)                     Library soname: [libnative-lib.so]
 0x0000001a (FINI_ARRAY)                 0x3e3c
 0x0000001c (FINI_ARRAYSZ)               8 (bytes)
 0x0000001e (FLAGS)                      BIND_NOW
 0x6ffffffb (FLAGS_1)                    Flags: NOW
 0x6ffffff0 (VERSYM)                     0x650
 0x6ffffffc (VERDEF)                     0x684
 0x6ffffffd (VERDEFNUM)                  1
 0x6ffffffe (VERNEED)                    0x6a0
 0x6fffffff (VERNEEDNUM)                 2
 0x00000000 (NULL)                       0x0
```

### SO Helper

无名侠大佬开发的软件。可以用来快速地获取 so 文件的一些基本信息，提供较弱的汇编功能。

# ARM 汇编代码

ARM 是 ARM 公司的 32 位处理器，其汇编指令的机器码就是 32 位。

1. ARM 汇编语言是一门“低级”语言可以和系统的底层相互沟通；
2. ARM 汇编语言编写的程序运行速度快，占用内存少；
3. ARM 编写的代码难懂，难以维护；
4. C 语言能实现的 ARM 汇编语言都能实现；
5. ARM 具有 31 个通用寄存器，6 个状态寄存器；
6. ARM 处理器支持 7 种运行模式。
   1. 用户模式：ARM 处理器正常的程序执行状态。
   2. 快速中断模式：用于高速数据传输或通道处理。
   3. 外部中断模式：用于通用的中断处理。
   4. 管理模式：操作系统使用的保护模式。
   5. 数据访问终止模式：当数据或指令预取终止时进如该模式，可用于模拟存储及存储保护。
   6. 系统模式：运行具有特权的操作系统任务。
   7. 未定义指令中止模式：当未定义的指令执行时进入该模式。

> ARM 汇编难以分析的原因：IDA 自身的缺陷；函数库与类有时无法识别；自身对 ARM 汇编的熟练度。

## 函数参数传递

遵循 ATPCS 规则，前 4 个参数使用 R0~R3 传递，剩余参数通过堆栈传递。

## ARM 和 Thumb

Thumb 是 16 位的 ARM 汇编。一般地，ARM 每行代码占 4 个字节码，Thumb 每个指令占 2 个字节。两者不能混用，但可以通过 BX、BLX 等指令在跳转的时候实现切换。在动态调试的时候，IDA 对 ARM 和 Thumb 的分析会混淆，可以用 Alt+G 来修改相应的识别。

## ARM 寄存器

- R0-R7：通用寄存器
- R8-R10：不常用的通用寄存器
- R11：基质寄存器（FP）
- R12：暂时寄存器（IP）
- R13：堆栈制作（SP）
- R14：链接寄存器（LR）
- CPSR：状态寄存器

## ARM 指令

### 寄存器交互指令

- LDR：从存储器中加载数据到寄存器。
  - `LDR R1, [R2]`：把 R2 指向的位置的数据给 R1
- STR：把寄存器的数据存储到存储器
  - `STR R1, [R2]`：在 R2 指向的地址，存储 R1
- LDM：将存储器的数据加载到一个寄存器列表。
  - `LDM R0, {R1, R2, R3}`：把 R0 中的数据一次加载到 R1、R2、R3
- SDM：将一个寄存器列表的数据存储到指定的存储器
  - `SDM R0, {R1, R2, R3}`：把 R1、R2、R3 加载到 R0 单元
- PUSH：入栈
- POP：出栈

### 数据传送指令

- MOV：将立即数或寄存器的数据传送到目标寄存器

### 数据算数运算指令

#### ADD（加法）

ADD 将把两个操作数加起来，把结果放置到目的寄存器中。操作数 1 是一个寄存器，操作数 2 可以是一个寄存器，被移位的寄存器，或一个立即值。

```arm
ADD R0, R1, R2 @ R0 = R1 + R2
ADD R0, R1, #256 @ R0 = R1 + 256
ADD R0, R2, R3, LSL#1 @ R0 = R2 + (R3 << 1)
```

加法可以在有符号和无符号数上进行。

- ADC：带进位的加法

#### SUB（减法）

SUB 用操作数 1 减去操作数 2，把结果放置到目的寄存器中。操作数 1 是一个寄存器，操作数 2 可以是一个寄存器，被移位的寄存器，或一个立即值。

```arm
SUB R0, R1, R2 @ R0 = R1 - R2
SUB R0, R1, #256 @ R0 = R1 - 256
SUB R0, R2, R3, LSL#1 @ R0 = R2 - (R3 << 1)
```

减法可以在有符号和无符号数上进行。

- SBC：带进位的减法

#### MUL（乘法）和 DIV（除法）

- 给出的所有操作数、和目的寄存器必须为简单的寄存器。
- 不能对操作数 2 使用立即值或被移位的寄存器。
- 目的寄存器和操作数 1 必须是不同的寄存器。
- 不能指定 R15 为目的寄存器

MUL 提供 32 位整数乘法。如果操作数是有符号的，可以假定结果也是有符号的。

- MLA：带累加的乘法

除法指令 DIV 的条件与乘法类似。

- SDIV：带符号除法
- UDIV：不带符号位除法

### 数据逻辑运算指令

- AND：与
- ORR：或
- EOR：异或
- LSL：逻辑左移
- LSR：逻辑右移

### 比较指令

- CMP：比较指令

### 其他指令

- SWT：切换用户模式
- DCB：伪指令

### 跳转指令

- B：无条件跳转
- BL：带链接的无条件跳转
- BLX：带状态的无条件跳转
- BNE：不相等跳转
- BEQ：相等跳转

#### 偏移地址计算

- ARM：低 27 位是偏移位置
  - 偏移 = (目标地址 - 当前 PC 地址) / 指令长度
  - 正数下跳，负数上跳
- Thumb 同理
- 目标地址 = 偏移 \* 指令长度 + 当前偏移地址

## ARM 代码编写

处理器架构定义：

- `.arch` 指定了 ARM 处理器架构。
- `armv5te` 表示本程序在 armv5te 架构处理器上运行。
- `.fpu` 指定了协处理器的类型。
- `softvfp` 表示使用浮点运算库来模拟协处理运算。
- `.ebi_attribute` 指定了一些接口属性。

```arm
.arch armv5te @处理器架构
.fpu softvfp  @协处理器类型
.ebi_attribute 20, 1 @接口属性
.ebi_attribute 21, 1
.ebi_attribute 23, 1
.ebi_attribute 24, 1
.ebi_attribute 25, 1
.ebi_attribute 26, 1
.ebi_attribute 30, 1
.ebi_attribute 18, 1
```

段定义：

- `.section`：定义只读数据，属性是默认
- `.text`：定义了代码段。

注释方法：

- `/.../`：多行注释
- `@`：单行注释

标号方式（和 8086 类似）：

```arm
loop:
    ...
end loop
```

程序中所有以“.”开头的指令都是汇编指令，他们不属于 ARM 指令集：

- .file：制定了源文件名。
- .align：代码对其方式。
- .ascii：声明字符串。
- .global：声明全局变量。
- .type：指定符号的类型。

声明函数的方法：

```arm
.global 函数名
.type 函数名, %function
函数名:
    <...函数体...>
声明一个实现两个数相加的函数的代码
.global MyAdd
.type MyAdd, &function
MyAdd:
    ADD R0, R0, R1
    MOV PC, LR
```

## ARM 处理器寻址方式

### 立即寻址

```arm
@ 井号（#）作为前缀，表示16进制时以“0x”开头
MOV R0，#1234 @ R0=0x1234
```

### 寄存器寻址

```arm
MOV R0, R1 @ R0=R1
```

### 寄存器移位寻址

五种移位操作：

- LSL：逻辑左移，移位后寄存器空出的低位补 0；
- LSR：逻辑右移，移位后寄存器空出的高位补 0；
- ASR：算数右移，移动过程中符号位不变。如果操作数是整数，则移位后空出的高位补 0，否则补 1；
- ROR：循环右移，移位后移出的低位填入移位空出的高位；
- RRX：带扩展的循环右移，操作数右移移位，移位空出的高位用 C 标志的值填充。

```arm
MOV R0, R1, LSL#2 @ R0=R1*4
```

### 寄存器间接寻址

```arm
LDR R0，[R1] @ 将R1寄存器中的值作为地址，取出地址中的值赋予R0
```

### 寄存器间接基址偏移寻址

```arm
LDR R0, [R1, #-4] @ 将R1寄存器的值-0x4的值作为地址，取出地址中的值给R0
```

### 多寄存器寻址

```arm
@ LDM 是数据加载命令，指令的后缀IA表示每次执行完成加载操作后R0寄存器的值自增1
LDMIA R0, {R1, R2, R3, R4}
@ R1=[R0]
@ R2=[R0+#4]
@ R3=[R0+#8]
@ R4=[R0+#12]
@ ARM中，字表示的是一个32位。这里+#4的原因是因为32位占4个字节
```

### 堆栈寻址

```arm
STMFD SP!, {R1-R7, LR} @ 入栈，多用于保存子程序堆栈
LDMFD SP!, {R1-R7, LR} @ 出栈，多用于恢复子程序堆栈
```

### 块拷贝寻址

块拷贝可实现连续地址数据从存储器的某一位置拷贝到另一位置。

```arm
LDMIA R0!, {R1-R3} @ 从寄存器指向的存储单元中读取3个字到R1-R3寄存器。
```

### 相对寻址

相对寻址一程序计数器 PC 的当前值为基地址，指令中的地址标号作为偏移量，将两者相加之后得到的操作数的有效地址。

# References

https://www.bilibili.com/video/av45424886
https://blog.csdn.net/miao_007/article/details/87632758
https://stackoverflow.com/questions/4629308/any-simple-way-to-log-in-android-ndk-code
https://www.jianshu.com/p/acbf724fdcc9
https://blog.csdn.net/afei__/article/details/81031965
https://www.luoxudong.com/360.html
https://www.jianshu.com/p/23af9151837e
https://juejin.im/post/5afe28446fb9a07aa0483d0a
https://www.52pojie.cn/thread-699268-1-1.html
https://www.52pojie.cn/thread-673175-1-1.html
