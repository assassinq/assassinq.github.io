---
title: Linux Sandbox - Setuid
date: 2020-04-23 22:39:04
tags: linux
---

Yet Another Linux Sandbox Technic.

<!-- more -->

# Combination Blow

Setuid Sandbox 主要是基于 Linux Kernel 所提供的安全机制（如 DAC）来实现。简单地说就是利用 `random uid/gid + chroot() + capability` 的组合出击来达到目标。其实现非常简单，无需修改 Kernel。Setuid Sandbox 的实现简单易行。在一定程度上，它可以用于隔离不可信的程序。由于它完全依赖于 kernel 所提供的安全机制，除非攻击者能找到 kernel 的 0-day 漏洞并通过攻击获得 root 权限，否则 Setuid Sandbox 所提供的安全隔离是可以保证的。

## What is setuid

Linux 中每个进程都会有一个 uid，`uid = 0` 则为 root 用户进程（privileged），`uid > 0`则为普通用户进程（unprivileged）。不同 uid 进程之间（不包括 root 进程）是相互隔离的，各自都有自己独立的权限，互不干扰。而 root 进程具有特权，它能干任何事情。Linux uid/gid 机制主要是用于进程的权限隔离。如果你打算执行不可信的程序，那么你可以在启动该程序时为其分配一个 random uid，大概的执行流程如下：`fork() -> setuid() -> {设置相关的进程资源限制，如 RLIMIT_NPROC (0,0)} -> execve()`。而 `setuid()` 只能由 root 权限（或拥有 `CAP_SETUID` Capability）才能成功调用，所以要顺利执行这个流程需要借助某个拥有 root 权限的进程。

Linux 下为进程设置了三个 UID：

- Real UID（RUID）：进程创建者的 UID，正常情况下它一直不会变化，永远表示进程创建者，但 root 用户可以更改它；
- Saved UID（SUID）：拥有者可以为自己的可执行程序设置 SUID 位，设置后任何人执行程序，程序启动时都将获得程序拥有者的权限；
- Effective UID（EUID）：为权限检查时实际生效的 UID，意味着在判断用户权限时并不检查 RUID 及 SUID，只看 EUID。

用 `getresuid` 来获取当前用户的三个 UID：

```cpp
#include <stdio.h>
#include <unistd.h>

int main() {
    int ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) == 0) {
        printf("RUID: %d\tEUID: %d\tSUID: %d\n", ruid, euid, suid);
    } else {
        ;
    }
    return 0;
}
```

如果为文件加上 SUID 标志位，其他用户运行该文件时会获得 root 的权限。但 RUID 保持不变：

```bash
root in ~/Setuid-Sandbox λ sudo -u root ./test-uid
RUID: 0	EUID: 0	SUID: 0
root in ~/Setuid-Sandbox λ sudo -u www-data ./test-uid
RUID: 33	EUID: 33	SUID: 33
root in ~/Setuid-Sandbox λ chmod u+s ./test-uid
root in ~/Setuid-Sandbox λ ls -l ./test-uid
-rwsr-xr-x 1 root root 8720 Apr 24 19:11 ./test-uid
root in ~/Setuid-Sandbox λ sudo -u www-data ./test-uid
RUID: 33	EUID: 0	SUID: 0
```

## What is chroot

通常来说，提到 Chroot 一般有两个含义，`chroot(1)` 是 `/usr/bin/chroot`，`chroot(2)` 是 glibc 中的一个函数。Chroot 是 Linux Kernel 提供的另一个安全功能，它用于改变进程的根目录。比如运行 `chroot("/tmp/sandbox/1/")`，会启动一个新的 Shell 并设置新进程的根目录为 `"/tmp/sandbox/1/"`，那么该进程的文件操作将被限制在 `"/tmp/sandbox/1/"` 中。注意，`chroot()` 只能由 root 权限（或拥有 `CAP_SYS_CHROOT` Capability）才能成功调用。

### Chroot Command

需要静态编译 Busybox 和 Bash：

```bash
$ wget
$ tar -zxvf
$ cd  && mkdir build
$ make O=build defconfig
$ cd build && make menuconfig # Select "Build BusyBox as a static binary (no shared libs)"
$ make
$ wget http://ftp.gnu.org/gnu/bash/bash-5.0-beta.tar.gz
$ tar -zxvf bash-5.0-beta.tar.gz
$ cd bash-5.0-beta && ./configure --enable-static-link --without-bash-malloc
$ make
```

使用 chroot 来修改当前的根目录，可以看到 ls 的结果是不同的：

```bash
root in ~/Setuid-Sandbox λ ./bash
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# ./busybox ls /
bin             etc             initrd.img.old  lost+found      opt             run             sys             var
boot            home            lib             media           proc            sbin            tmp             vmlinuz
dev             initrd.img      lib64           mnt             root            srv             usr             vmlinuz.old
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# exit
exit
root in ~/Setuid-Sandbox λ chroot . ./bash
bash-5.0# ./busybox ls /
bash      busybox   chroot    chroot.c  ls
bash-5.0# exit
exit
```

### Chroot Function

进程中有 `cwd`（当前目录）和 `root`（根目录）两个目录。C 库中提供了几个函数对两者进行修改：

```cpp
int chdir(const char *path);     //依据目录名改cwd
int fchdir(int fd);              //依据文件描述符改cwd
int chroot(const char *path);    //依据目录名改root
```

```cpp
#include <unistd.h>

int main() {
    chroot(".");
    chdir("/");
    char *argv[] = {"./bash", NULL};
    execl(argv[0], argv, NULL);
    return 0;
}
```

### Create bash jail

可以使用 [jailkit](https://olivier.sessink.nl/jailkit/index.html) 创建一个安全的 jail 环境：

```bash
$ wget https://olivier.sessink.nl/jailkit/jailkit-2.20.tar.gz
$ tar -zxvf jailkit-2.20.tar.gz
$ cd jailkit-2.20 && ./configure
$ make
$ make install
```

### Combine with setuid

那么在前面叙述的执行流程中，可以先让具有 root 权限的进程去执行 `chroot()` 后再调用 `setuid() -> {...} -> execve()`。但其实这样做是行不通的，因为进程的根目录已经被修改，`execve()` 本要执行的 Binary 文件已经不可用了。Google 的一篇文章里给出了一个解决此问题的简单方法：

1. 创建一个子进程，注意使用 `clone()` 和 `CLONE_FS`，使得父子进程可以共享根目录、当前目录等等；
2. 父进程降权后执行 `execve()`，又产生一个新进程；
3. 然后父进程请求子进程执行 `chroot()`；
4. 子进程执行 `chroot()`，新的根目录会对两个子进程同时生效。
5. 父进程退出。

这个方法的前提是 父进程 需要设置 `RLIMIT_NOFILE` 为 `(0, 0)`，并且对于不可信的子进程（`execve` 创建的新进程）来说，在执行第 4 步之前应是可控的。另外，对于父进程来说，由于它是以 root 身份运行，那么就可能会成为攻击点，比如 Confused Deputy Problem。

## Capability Mechanism

Linux Capability 主要是解决 Confused Deputy Problem（如 CSRF）。Linux 支持 Capability 的主要目的是细化 root 的特权。比如拿 ping 来说，它需要使用 raw_sockets 所以需要 root 特权才能运行；如果有了 Capability 机制，由于该程序只需要一个 `CAP_NET_RAW` 的 Capability 即可运行，那么根据最小权限原则，该程序运行时可以丢弃所有多余的 Capability，以防止被误用或被攻击。所以，Capability 机制可以将 root 特权进行很好的细分。Kernel-2.6.18 起已支持 30 多种不同的 Capability，在 Kernel-2.6.24 及以上的版本中一个普通用户进程也将可以持有 Capability。

## What is rbash（Restricted Bash）

`rbash` 的主要作用是限制了部分 Bash 命令，会以一种受限的方式启动 Bash：

1. 只能执行当前目录下的可执行文件；
2. 在执行命令时命令不能带 `/`；
3. 不能改变当前工作目录；
4. 不能更改 `PATH` 或 `SHELL` 变量；
5. 不能使用重定向输出；
6. ...

```bash
root@5b0ef65c6894:~# rbash
root@5b0ef65c6894:~# cd tmp/
rbash: cd: restricted
root@5b0ef65c6894:~# ./tmp/rp-lin-x64
rbash: ./tmp/rp-lin-x64: restricted: cannot specify `/' in command names
root@5b0ef65c6894:~# export PATH=$PATH:/root/tmp
rbash: PATH: readonly variable
```

# Bypass

## Bypass setuid

当程序执行完高权限后使用 `setresuid` 进行降权操作，但是并未完全抹除高权限：

```cpp
#include <stdio.h>
#include <unistd.h>

int main() {
    int ruid, euid, suid;
    getresuid(&ruid, &euid, &suid);
    printf("RUID: %d\tEUID: %d\tSUID: %d\n", ruid, euid, suid);

    seteuid(2333); // Modify EUID
    getresuid(&ruid, &euid, &suid);
    printf("RUID: %d\tEUID: %d\tSUID: %d\n", ruid, euid, suid);

    setresuid(-1, 2, -1); // unprivileged
    getresuid(&ruid, &euid, &suid);
    printf("RUID: %d\tEUID: %d\tSUID: %d\n", ruid, euid, suid);

    setresuid(-1, 0, -1); // Get root privilege
    setresuid(123, 123, 123);
    getresuid(&ruid, &euid, &suid);
    printf("RUID: %d\tEUID: %d\tSUID: %d\n", ruid, euid, suid);
    return 0;
}
```

## Bypass chroot

Chroot 沙箱可以将进程对文件的访问限制在一个指定的目录中，但是由于 Chroot 不是一个安全的 feature，所以该沙箱可能会被逃逸出来。比如使用 [`chw00t`](https://github.com/earthquake/chw00t)。当进程中存在文件在当前 root 目录树外，即在 jail 外，即表明越狱成功，此时的 root 就是原来文件系统的 root 了。

## Bypass rbash

rbash 的绕过方法也有很多，通常跟 chroot 配合使用。不过它本身对文件操作是没有限制的。可以使用 vi、vim 等命令时：

```bash
root in ~/Setuid-Sandbox λ rbash
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# vi
# :set shell=/usr/bin/zsh
# :shell
root in ~/Setuid-Sandbox λ ls
bash  busybox  chroot  chroot.c  ls
```

可以使用 cp、mv 等文件操作命令时：

```bash
root in ~/Setuid-Sandbox λ rbash
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# cp /usr/bin/zsh .
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# ls
bash  busybox  chroot  chroot.c  ls  zsh
root@iZ2zecelicizfr2e28zon3Z:~/Setuid-Sandbox# zsh
root in ~/Setuid-Sandbox λ ls
bash  busybox  chroot  chroot.c  ls  zsh
```

# References

https://www.linuxidc.com/Linux/2015-02/112914.htm
https://atum.li/2017/04/25/linuxsandbox
https://blog.betamao.me/2019/01/31/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bchroot%E4%B8%8Erbash/
