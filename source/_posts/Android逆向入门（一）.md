---
title: Android逆向入门（一）
date: 2020-01-16 14:41:48
tags: [re, android]
---

开始学习安卓。

<!-- more -->

# APK 的组成

- asset 文件夹
  - 资源目录，不需要生成索引，在 Java 代码中需要用 AssetManager 来访问
- lib 文件夹
  - so 库存放位置，一般由 NDK 编译得到，常见于使用游戏引擎或 JNI native 调用的工程中
- META-INF 文件夹
  - 存放工程的一些属性文件，例如 Manifest.MF
- res 文件夹
  - 资源目录，在编译时自动生成索引文件（R.java），在 Java 代码中用 R.xxx.yyy 来引用
- AndroidManifest.xml
  - Android 工程的基础配置属性文件（描述 Android 应用的信息，包括类名、组件名等）
- classes.dex
  - Java 代码编译得到的 Dalvik VM 能直接执行的文件
- resources.arsc
  - 对 res 目录下资源的一个索引文件，保存了原工程中 string.xml 等文件内容
- 其他文件夹

一般来说，除了音频和视频资源（需要放在 raw 或 asset 下），使用 Java 开发的 Android 工程使用到的资源文件都会放在 res 下；使用 C++游戏引擎（或使用 Lua Unity3D 等）的资源文件均需要放在 asset 下。

# Dalvik 字节码

Dalvik 是谷歌专门为 Android 操作系统设计的一个虚拟机，经过深度的优化。虽然 Android 上的程序是使用 Java 来开发的，但是 Dalvik 和标准的 Java 虚拟机 JVM 还是两回事。Dalvik VM 是基于寄存器的，而 JVM 是基于栈的；Dalvik 有专属的文件执行格式 dex（Dalvik Executable），而 JVM 则执行的是 Java 字节码。Dalvik VM 比 JVM 速度更快，占用空间更少。

# Smali 文件结构

Smali、Baksmali 分别是指 Android 系统里的 Dalvik 虚拟机所使用的一种 dex 格式文件的汇编器、反汇编器。其语法是一种宽松式的 Jasmin/Dedexer 语法，而且它实现了 dex 格式所有功能（注解、调试信息、线路信息等）。

当我们对 APK 文件进行反编译后，便会生成此类文件。其中在 Dalvik 字节码中，寄存器都是 32 位的，能够支持任何类型，64 位类型（Long/Double）用 2 个寄存器表示；Dalvik 字节码有两种类型：原始类型、引用类型（包括对象和数组）。

## 头部定义

- `.class`
- `.super`
- `.source`

## 域定义

- `.field public`
- `.field static`
- `.field private`
- ...

## 函数定义

### Smali 函数（使用 P-V 寄存器）

在 smali 里的所有操作都必须经过寄存器来进行：本地寄存器用 v 开头、数字结尾的符号来表示，如 v0、v1、v2 等；参数寄存器则使用 p 开头、数字结尾的符号来表示，如 p0、p1、p2 等。特别注意的是，p0 不一定是函数中的第一个参数，在非 static 函数中，p0 代指 this，p1 表示函数的第一个参数，p2 代表函数中的第二个参数；而在 static 函数中 p0 才对应第一个参数（因为 Java 的 static 方法中没有 this 方法）。

```smali
.method 访问修饰符 函数名 函数签名
    .locals n # 使用 n 个寄存器，即 v0~v(n-1)
    .param p1, "savedInstanceState" # Landroid/os/Bundle # 注释
    ... # 函数实现
    return-xxx # 返回
.end method
```

### 函数调用

参数通过寄存器传递（Pn、Vn）

```smali
Invoke{参数}, 方法名
```

## Smali 字段描述符

|  Java type   |    Type descriptor     |
| :----------: | :--------------------: |
|    `void`    |          `V`           |
|  `boolean`   |          `Z`           |
|    `char`    |          `C`           |
|    `byte`    |          `B`           |
|   `short`    |          `S`           |
|    `int`     |          `I`           |
|   `float`    |          `F`           |
|    `long`    |          `J`           |
|   `double`   |          `D`           |
|   `Object`   |  `Ljava/lang/Object;`  |
|   `int[]`    |          `[I`          |
|   `byte[]`   |          `[B`          |
| `Object[][]` | `[[Ljava/lang/Object;` |

## Smali 基本语法

|    Keyword descriptor     |               Description                |
| :-----------------------: | :--------------------------------------: |
| `.field private isFlag:z` |                 定义变量                 |
|         `.method`         |                   方法                   |
|       `.parameter`        |                 方法参数                 |
|        `.prologue`        |                 方法开始                 |
|        `.line 123`        |           此方法位于第 123 行            |
| `const/high16 v0, 0x7f03` |           把 0x7f03 赋值给 v0            |
|       `return-void`       |              函数返回 void               |
|       `.end method`       |                 函数结束                 |
|      `new-instance`       |                 创建实例                 |
|       `iput-object`       |                 对象赋值                 |
|       `iget-object`       |                 调用对象                 |
|   `move-result-object`    |        将上一句的结果赋值给寄存器        |
| `new-array v0, v1, type`  | 构造指定类型与大小的数组，并赋值给寄存器 |
|   `array-length v0, v1`   | 获取指定寄存器中数组的长度并赋值给寄存器 |
|         `const/4`         |                   赋值                   |
|  `rem-int/2addr v0, v1`   |           计算模结果存入寄存器           |
|       `int-to-byte`       |               整型转字节型               |
|          `goto`           |            直接跳转到指定位置            |
|      `return-object`      |             返回一个对象类型             |

## Smali 中函数的调用

函数分为 direct 和 virtual 两种类型。direct method 就是 private 函数，其余的 public 和 protected 函数都属于 virtual method。

### `invoke-static`

调用静态函数。

```smali
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

### `invoke-super`

调用父类方法用的指令（一般用于调用 onCreate、onDestroy）。

### `invoke-direct`

调用 private 函数。

```smali
invoke-direct {p0}, Landroid/app/TabActivity;-><init>()V
```

### `invoke-virtual`

用于调用 protected 或 public 函数。

```smali
invoke-virtual {v0,v1}, Lcom/ccc;->Message(Ljava/lang/Object;)V
```

### `invoke-xxxxx/range`

当方法参数多于 5 个时（含 5 个），不能直接使用以上指令，而是在后面加上 `/range` 表示范围。

```smali
invoke-direct/range {v0 .. v5}, Lcmb/pb/ui/PBContainerActivity;->h(ILjava/lang/CharSequence;Ljava/lang/String;Landroid/content/Intent;I)Z
```

## Smali 中的条件跳转分支

|           代码           |                  含义                   |
| :----------------------: | :-------------------------------------: |
| `if-eq vA, vB, :cond_**` |   如果 vA 等于 vB 则跳转到 `:cond_**`   |
| `if-ne vA, vB, :cond_**` |  如果 vA 不等于 vB 则跳转到 `:cond_**`  |
| `if-lt vA, vB, :cond_**` |   如果 vA 小于 vB 则跳转到 `:cond_**`   |
| `if-ge vA, vB, :cond_**` | 如果 vA 大于等于 vB 则跳转到 `:cond_**` |
| `if-gt vA, vB, :cond_**` |   如果 vA 大于 vB 则跳转到 `:cond_**`   |
| `if-le vA, vB, :cond_**` | 如果 vA 小于等于 vB 则跳转到 `:cond_**` |
|  `if-eqz vA, :cond_**`   |   如果 vA 等于 0 则跳转到 `:cond_**`    |
|  `if-nez vA, :cond_**`   |  如果 vA 不等于 0 则跳转到 `:cond_**`   |
|  `if-ltz vA, :cond_**`   |   如果 vA 小于 0 则跳转到 `:cond_**`    |
|  `if-gez vA, :cond_**`   | 如果 vA 大于等于 0 则跳转到 `:cond_**`  |
|  `if-gtz vA, :cond_**`   |   如果 vA 大于 0 则跳转到 `:cond_**`    |
|  `if-lez vA, :cond_**`   | 如果 vA 小于等于 0 则跳转到 `:cond_**`  |

## Smali 代码编写

### 静态返回 HelloWorld 的方法

```smali
.class public Lf8/helloworld/helloStr; # 类声明
    .super Ljava/lang/Object; # 父类声明

    .method public static retHello()Ljava/lang/String; # 函数声明
    .locals 1 # 寄存器数量

    const-string v0, "Hello World from StaticMethod" # 新建字符串
    return-object v0 # 返回Object类型
.end method # 方法结束声明
```

### 返回静态 field 的方法

```smali
.field public static final hStr:Ljava/lang/String; = "Hello World from static field" # field声明与初始化
.method public static retHello2()Ljava/lang/String;
    .locals 1
    sget-object v0, Lf8/helloworld/helloStr;->hStr:Ljava/lang/String; # 获取field
    return-object v0
.end method
```

### 普通的函数

```smali
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public retHello3()Ljava/lang/String;
    .locals 1
    const-string v0, "Hello World from Method"
    return-object v0
.end method
```

### 普通的 field 与函数

```smali
.field public hStr2:Ljava/lang/String;
.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, "Hello field" # 初始化非静态field
    iput-object v0, p0, Lf8/helloworld/helloStr;->hStr2:Ljava/lang/String;
    return-void
.end method

.method public retHello4()Ljava/lang/String;
    .locals 1
    iget-object v0, p0, Lf8/helloworld/helloStr;->hStr2:Ljava/lang/String;
    return-object v0
.end method
```

调用时需要先初始化一个实例：

```smali
new-instance v1, Lf8/helloworld/helloStr;
invoke-direct {v1}, Lf8/helloworld/helloStr;-><init>()V
invoke-virtual {v1}, Lf8/helloworld/helloStr;->retHello3()Ljava/lang/String;
move-result-object v1
```

## Others

### Android Log

来自于包 `android/killer/log`。

```smali
invoke-static {v0}, Lcom/android/killer/Log;->LogStr(Ljava/lang/String;)V
```

### LoadLibrary

```smali
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

### stackTrace

打印当前函数堆栈，方法为 `Thread.dumpStack()`。

```smali
invoke-static {}, Ljava/lang/Thread;->dumpStack()V
```

### Method Trace

函数跟踪。

```smali
invoke-static {}, Landroid/os/Debug;->startMethodTracing()V
invoke-static {}, Landroid/os/Debug;->stopMethodTracing()V
```

需要添加权限。

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
```

保存的 trace 文件可以 dump 出来使用 monitor 来打开。

### 字符串处理

```smali
const-string v1, "%d" # 格式化描述符
const/4 v2, 0x1 # 数组长度
new-array v2, v2 [Ljava/lang/Object; # 创建Object数组
aput-object v3, v2, v4 # 填充数组
...
invoke-static {v1, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String; # 格式化字符串
# 字符串替换
invoke-virtual {v0, v1, v2}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;
invoke-virtual {v0, v1, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
```

### waitForDebugger

```smali
invoke-static {}, Landroid/os/Debug;->waitForDebugger()V
```

# apktool/ShakaApktool

```bash
java -jar apktool.jar d example.apk -o example-dir
java -jar apktool.jar b example-dir -o example.apk
```

| 选项 |  功能  |
| :--: | :----: |
| `d`  | 反编译 |
| `b`  | 回编译 |

```bash
java -jar ShakaApktool.jar d -df example.apk -o example-dir
java -jar ShakaApktool.jar b example-dir -o example.apk
```

|             选项             |          功能          |
| :--------------------------: | :--------------------: |
| `-df`、`--default-framework` | 使用默认的框架资源文件 |

# 安卓 apk 调试（不需要修改原 apk 文件）

1. 使用 apktool/ShakaApktool 反编译 apk 文件
2. 在 Android Studio 中导入源码
3. 设置远程调试选项，Host 填写为 localhost，端口填写为 8700
4. 使用 adb 以 debug 方式启动 apk：`adb shell am start -D -n packageName/ActivityName`
5. 下好断点，打开 monitor，开始调试

# References

https://www.bilibili.com/video/av45424886
https://www.52pojie.cn/thread-395689-1-1.html
https://www.52pojie.cn/thread-396966-1-1.html
https://www.52pojie.cn/thread-397858-1-1.html
