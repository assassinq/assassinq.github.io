---
title: 如何给Linux添加系统调用
date: 2019-11-27 13:50:19
tags: linux
---

操作系统实验记录。

<!-- more -->

# Environment

OS：Ubuntu 16.04.6

```zsh
➜  ~ uname -a
Linux ubuntu 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 14:01:10 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

# First: Download Linux Kernel Source

```
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.20.17.tar.gz
tar -xvf linux-4.20.17.tar.gz
sudo mv linux-4.20.17/ /usr/src/
cd /usr/src/linux-4.20.17/
```

# Second: Install Dependences

```bash
sudo apt update
sudo apt install bison flex libssl-dev libncurses5-dev
```

# Third: Add My Syscall

入口（`arch/x86/entry/syscalls/syscall_64.tbl`）

```
# Here are my syscalls
548     64      mysyscall               sys_mysyscall
```

系统调用声明（`include/linux/syscalls.h`）

```c
// Here are my syscalls
asmlinkage long sys_mysyscall(void);
```

添加调用（`kernel/sys.c`）

```c
// Here are my syscalls
asmlinkage long sys_mysyscall(void) {
	printk("Hello Kernel!!!\n");
	return 1712190426;
}
```

# Forth: Compile

```bash
make mrproper
make clean
make menuconfig # 将Device drivers中的Staging drivers取消
# 下面的编译时间比较久 可以通过time记录一下时间
time make bzImage # 编译并生成压缩的内核映像 大约半个小时
time make modules # 编译模块 大约两个多小时
sudo time make modules_install # 安装模块 大约三分多种
sudo time make install # 安装内核 大约一分多钟
```

编译成功后 reboot 重启系统。

# Fifth: Test

```zsh
➜  ~ uname -a
Linux ubuntu 4.20.17 #1 SMP Thu Nov 28 22:48:22 PST 2019 x86_64 x86_64 x86_64 GNU/Linux
```

查看添加的系统调用是否成功：

```zsh
➜  ~ grep -A 1 mysyscall /proc/kallsyms
0000000000000000 T sys_mysyscall
0000000000000000 T usermodehelper_read_unlock
```

编写测试程序如下：

```cpp
#include <stdio.h>
#include <sys/syscall.h>

int main() {
	long ret = syscall(548);
	printf("%ld\n", ret);
	return 0;
}
```

运行结果，返回值为设定好的值：

```zsh
➜  ~ ./3
1712190426
```

使用 dmesg 命令（dmesg 命令显示 linux 内核的环形缓冲区信息，我们可以从中获得诸如系统架构、cpu、挂载的硬件，RAM 等多个运行级别的大量的系统信息）查看调用情况：

```zsh
➜  ~ dmesg | grep "Hello"
[  228.310507] Hello Kernel!!!
```

# References

https://www.cnblogs.com/tod-reg20130101/articles/9280792.html
https://www.zybuluo.com/hakureisino/note/514321
https://www.jianshu.com/p/b2d5fa8af581
