---
title: Ubuntu16.04下编译libc2.23
date: 2019-03-04 21:31:41
tags: linux
---

为了更好地调试堆，需要自己编译一个带 Symbol 的 libc。

<!-- more -->

# 环境和工具

- Ubuntu16.04
- glibc-2.23.tar.gz

```bash
assassinq@ubuntu ~/glibc-2.23/build$ uname -a
Linux ubuntu 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

# 准备工作

从 ftp 上把 glibc 下载下来，解压后新建一个 build 文件夹：

```bash
cd && wget http://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz \
tar -xvf glibc-2.23.tar.gz && cd glibc-2.23 \
mkdir build && cd build # mkdir build32 && cd build32
```

# 编译过程中的挖坑和填坑

在 build 文件夹下 configure，并且加上一些必要的参数使得编译时加上 symbol，并且指定输出文件夹：（转自 [2016 年 winesap 的社课](https://www.youtube.com/watch?v=wsIvqd9YqTI&feature=share)）

```bash
# x64
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
../configure --prefix=/path/to/install
# x32
CC="gcc -m32" CXX="g++ -m32" \
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
../configure --prefix=/path/to/install --host=i686-linux-gnu
```

如果没有任何意外的话就能直接 `make && make install` 编译了。下面记录一下遇到的几个坑。（感谢 [n132 大哥的博客](https://n132.github.io/2018/04/30/2018-04-30-%E7%BC%96%E8%AF%91-Libc-2-23/)）

## 某些安装包缺失

configure 的时候提示有些安装包缺失，不能生成 Makefile：

```
configure: error:
*** These critical programs are missing or too old: gawk
*** Check the INSTALL file for required versions.
```

根据提示安装一下即可：

```bash
sudo apt update && sudo apt install gawk
```

## `warnings being treated as errors`

```
In file included from regex.c:67:0:
regexec.c: In function ‘check_node_accept_bytes’:
regexec.c:3856:29: error: ‘extra’ may be used uninitialized in this function [-Werror=maybe-uninitialized]
        const unsigned char *coll_sym = extra + cset->coll_syms[i];
                             ^
cc1: all warnings being treated as errors
../o-iterator.mk:9: recipe for target '/home/assassinq/glibc-2.23/build/posix/regex.o' failed
make[2]: *** [/home/assassinq/glibc-2.23/build/posix/regex.o] Error 1
make[2]: Leaving directory '/home/assassinq/glibc-2.23/posix'
Makefile:214: recipe for target 'posix/subdir_lib' failed
make[1]: *** [posix/subdir_lib] Error 2
make[1]: Leaving directory '/home/assassinq/glibc-2.23'
Makefile:9: recipe for target 'all' failed
make: *** [all] Error 2
```

`cc1: all warnings being treated as errors` 是因为设置了警告提示，这里可以回到之前 configure 的时候，`CFLAGS` 新增加一个参数 `-Wno-error` 来去除警告：

```bash
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -Wno-error"
```

> 2020-05-02 更新：在 20.04 中编译 glibc-2.29 和 glibc-2.31 的时候发现在加 FALGS 里加 `-Wno-error` 没有用了，需要在 configure 时增加 `--disable-werror` 参数。
> 同时在 20.04 中编译 glibc-2.29 需要额外加上 `--enable-cet` 参数来避免链接报错（因为 20.04 自带的 gcc 隐式启用 `-fcf-protection` 标志）

## `ld.so.conf` 缺失

```
/home/assassinq/glibc-2.23/build/elf/ldconfig: Warning: ignoring configuration file that cannot be opened: /home/assassinq/glibc-2.23/64/etc/ld.so.conf: No such file or directory
make[1]: Leaving directory '/home/assassinq/glibc-2.23'
```

这里只需要直接 touch 一个新文件即可：

```bash
cd ../64/etc && sudo touch ld.so.conf
```

## Build with Docker

在 macOS 下使用 Docker 挂载 glibc 目录后再进行编译可能会有以下错误：

```bash
/root/tmp/elf/dl-load.c:1850: undefined reference to `__GI___xstat64'
/usr/bin/ld: /root/tmp/build/elf/librtld.os: relocation R_X86_64_PC32 against undefined symbol `__GI___xstat64' can not be used when making a shared object; recompile with -fPIC
/usr/bin/ld: final link failed: Bad value
collect2: error: ld returned 1 exit status
```

原因是 macOS 默认文件系统呢对大小写不敏感，不过解决方法似乎只有格式化成大小写不敏感的文件系统。（https://stackoverflow.com/questions/55355885/error-trying-to-install-glibc-in-wsl-relocation-r-x86-64-pc32-against-undefined）

# 调试

通过设置 `LD_LIBRARY_PATH` 把程序的动态链接库更改为添加了调试符号的版本：

```bash
$ export LD_LIBRABRY_PATH=/path/to/install/lib
```

# 参考网站

https://n132.github.io/2018/04/30/2018-04-30-%E7%BC%96%E8%AF%91-Libc-2-23/
https://www.youtube.com/watch?v=wsIvqd9YqTI&feature=share
https://stackoverflow.com/questions/8132594/disable-werror-ini-configure-file
https://www.stacknoob.com/s/bsxmrGZgZTpjwfpnpmAgNT
