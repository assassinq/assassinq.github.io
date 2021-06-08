---
title: Raspberry Pi搭建OpenPLC模拟小型工控系统
date: 2020-07-19 09:16:42
tags: [rpi, ics]
password: assassinqkeepshumble
abstract: Sorry, the article is encrypted.
message: Need password...
wrong_pass_message: Wrong password.
wrong_hash_message: Wrong hash.
---

树莓派模拟 PLC 模拟工控环境。

<!-- more -->

# What is PLC

跟着 OpenPLC 官网重新认识一下 PLC。可编程逻辑控制器（Programmable Logic Controller）是在上世纪 70 年代用于替代时序电路的一种设备。PLC 可以接收用户编写的程序并执行对应的操作。

PLC 由 CPU、存储和 I/O 电路组成。PLC 内部的工作原理主要是持续不断地扫描一个程序，包括三个步骤：检查输入、执行程序、更新输出。

PLC 的主要编程语言是 LD（Ladder Logic，梯形逻辑/梯形图），还包括其他一些编程语言。主要有 5 种规范的编程语言：

- 图形化编程语言
  - 梯形图（Ladder Logic，LD）
  - 功用块图（Function Block Diagram，FBD）
  - 次序功用图（Sequential Function Chart，SFC）
- 文本话编程语言
  - 指令表（Instruction List，IL）
  - 结构化文本（Structured Text，ST）

## Ladder Logic

梯形图基于曾经用于处理继电器逻辑的电气梯形图。梯形图标注出了设备之间的连接关系，并被写入到继电器控制板上。因为长得像梯子就被称为梯形图，如下：

![](/pics/Raspberry-Pi搭建OpenPLC模拟小型工控系统/1.png)

这张图展示的是两个按键和一盏灯之间的关系。如果灯要被点亮，必须要同时接通正负极。此时灯已经连接至了负极，只要按下 PB1 或 PB2，灯就会连接上正极并被点亮。程序逻辑的伪代码如下：

```
IF PB1 OR PB2 is pressed THEN
Lamp turns on
```

![](/pics/Raspberry-Pi搭建OpenPLC模拟小型工控系统/2.png)

这里用 [OpenPLC Editor](https://www.openplcproject.com/plcopen-editor) 编写的程序逻辑如下：

![](/pics/Raspberry-Pi搭建OpenPLC模拟小型工控系统/3.png)

### contact

在梯形图中，最基础的元素被称作 `contact`。一个 `contact` 和一个按键类似，用于断开和闭合两种状态。如果是断开的状态，就会切断两端的电流；反之，则将两侧电流串通。`contact` 指令也被称作 `examine if on`，用于测试电路是否连通，若连通则指令为真。同理 `negated contact` 被称作 `examine if off`，若电路未连通则指令为真。

### coil

梯形图中的另一个基础元素是 `coil`，类似于继电器中的线圈，有通电（energized）和未通电（de-energized）两种状态。`coil` 可作为内存使用，在电路条件为真时表现为真。同样有 `negated/closed coil`，作用与 `coil` 相反，如果电路条件为假则表现为真。

## A Simple Project

在 OpenPLC Editor 中新建一个项目，设置几个元件的属性如下：

| Name | Class |  Type  | Location |
| :--: | :---: | :----: | :------: |
| PB1  | Local | `BOOL` | `%IX0.0` |
| PB2  | Local | `BOOL` | `%IX0.1` |
| LAMP | Local | `BOOL` | `%QX0.0` |

设置梯形图如下。点击上面的小人可以模拟电路运行，可以选择元件并右键修改为 True 或 False：

![](/pics/Raspberry-Pi搭建OpenPLC模拟小型工控系统/4.jpg)

## PLC Addressing

PLC 通常使用一种或多种协议和外界进行消息的传输。当设计 PLC 应用时，可以用 PLC 地址标记指定变量进行协议的通讯，如 `%IX10.1` 或 `%QW5` 等形式。PLC 的地址和运行环境、设备等相关，这里记录的主要是 OpenPLC 下支持的地址格式。主要有四点：

- `%` 前缀；
- 存储类型字段（用途）；
- 数据大小字段；
- 具体地址。

通过巴科斯范式表示如下：

```bnf
<plc-address> ::= "%" <storage-class> <data-size> <hierarchical-address>

<storage-class> ::= "I" | "Q" | "M"
<data-size> ::= "X" | "B" | "W" | "D" | "L"
<hierarchical-address> ::= <number> | <number> "." <oct-digit>

<number> ::= <digit> | <number> <digit>
<digit> ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
<oct-digit> ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7"
```

存储类型字段主要有以下三种：

- `I`：输入；
- `Q`：输出；
- `M`：内存。

数据大小字段中不同数据类型的存储比特长度对应不同标志，具体如下：

| `<data-size>` | Common Name | Number of Bits |       Elementary Data Types        |
| :-----------: | :---------: | :------------: | :--------------------------------: |
|      `X`      |     Bit     |       1        |               `BOOL`               |
|      `B`      |    Byte     |       8        |      `BYTE`, `SINT`, `USINT`       |
|      `W`      |    Word     |       16       |       `WORD`, `INT`, `UINT`        |
|      `D`      | Double word |       32       | `DWORD`, `DINT`, `UDINT`, `FLOAT`  |
|      `L`      |  Long word  |       64       | `LWORD`, `LINT`, `ULINT`, `DOUBLE` |

有如下在 OpenPLC 下合法的 PLC 地址：

```
%IX0.0
%IX0.7
%IB1
%QD100
%ML10
```

以下为一些不合法地址：

| Invalid Example |                        Reason                         |
| :-------------: | :---------------------------------------------------: |
|    `%IX0.8`     |    The least significant index is greater than 7.     |
|   `%IX0.0.1`    |    Three part hierarchy is not permitted address.     |
|    `%IB1.1`     | Two part hierarchy is only permitted for X data size. |
|    `%QL1024`    |         Maximum index must be less than 1024.         |

# Installation

整了个 Raspberry Pi 3B，具体怎么装的过程就不记录了，感觉一般人都可以自行完成。主要记录一下一个坑（知识点），如果要安装风扇，务必要了解一下树莓派的几个引脚，风扇的两根线中（红色是正极，黑色是负极），红色线务必连接 5V PWR，黑色线务必连接到 GND 接地：

![](/pics/Raspberry-Pi搭建OpenPLC模拟小型工控系统/5.png)

OpenPLC 的安装过程也比较简单，建议给树莓派换个 tsinghua 源：

```bash
$ git clone https://github.com/thiagoralves/OpenPLC_v3.git
$ cd OpenPLC_v3
$ ./install.sh rpi
```

在同一网段下的一台虚拟机中安装 ScadaBR：

```bash
$ git clone https://github.com/thiagoralves/ScadaBR_Installer.git
$ cd ScadaBR_Installer
$ ./install_scadabr.sh
```

# Experiment

TODO

# References

https://www.openplcproject.com/reference
http://www.raspigeek.com/index.php?c=read&id=126&page=1
https://www.freebuf.com/articles/ics-articles/213018.html
https://www.element14.com/community/community/applications/industrial-automation-space/blog/2019/08/09/trying-out-openplc-on-a-raspberry-pi
https://chinsyo.com/2019/08/10/ssh-connect-raspberry-pi-anywhere/
