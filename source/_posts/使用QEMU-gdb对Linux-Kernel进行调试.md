---
title: 使用QEMU+gdb对Linux Kernel进行调试
date: 2019-08-08 23:24:47
tags: [ctf, pwn, linux]
---

最近在分析一个 CVE 的时候涉及到对内核的调试，先提前研究一下。

<!-- more -->

# Environment

OS：Ubuntu 16.04（VMware Fusion）

```bash
➜  ~ uname -a
Linux ubuntu 4.4.0-92-generic #115-Ubuntu SMP Thu Aug 10 09:04:33 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
➜  ~ lsb_release -a
No LSB modules are available.
Distributor ID:    Ubuntu
Description:    Ubuntu 16.04.6 LTS
Release:    16.04
Codename:    xenial
```

# Preparation

## Dependence

安装 QEMU：

```bash
$ sudo apt install qemu qemu-system
```

一些用于编译内核的依赖：

```bash
$ sudo apt install libncurses5-dev build-essential kernel-package
```

## Linux Kernel

Linux 内核源码肯定少不了，编译完后：

```bash
$ wget https://mirrors.tuna.tsinghua.edu.cn/kernel/v4.x/linux-4.20.17.tar.gz
$ tar -zxvf linux-4.20.17.tar.gz && cd linux-4.20.17
$ make menuconfig # 直接保存即可
$ make bzImage
```

在 `make menuconfig` 中配置：

- `Kernel hacking`
  - `Compile-time checks and compiler options`
    - 选中 `Compile the kernel with debug info`
  - 选中 `Compile the kernel with frame pointers`
  - 选中 `KGDB: kernel debugger`
- `Processor type and features`
  - 取消 `Paravirtualized guest support`
- `KernelHacking`
  - 取消 `Write protect kernel read-only data structures`

过一段时间之后编译得到 `arch/x86/boot/bzImage`（被压缩后的内核文件）以及 `vmlinux`（带调试信息的内核文件）：

```bash
...
  OBJCOPY arch/x86/boot/setup.bin
  OBJCOPY arch/x86/boot/vmlinux.bin
  HOSTCC  arch/x86/boot/tools/build
  BUILD   arch/x86/boot/bzImage
Setup is 17148 bytes (padded to 17408 bytes).
System is 8385 kB
CRC 67bf4091
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

## Busybox

启动内核还需要一个简单的文件系统和一些命令，可以使用 Busybox 来构建

```bash
$ wget https://busybox.net/downloads/busybox-1.31.0.tar.bz2
$ tar -jxvf busybox-1.31.0.tar.bz2 && cd busybox-1.31.0
$ make menuconfig # Build static binary (no shared libs)
$ make install
```

在 `make menuconfig` 中配置：

- `Settings`
  - `Build Options`
    - `Build static binary (no shared libs)`（编译成静态文件）
- `Linux System Utilities`
  - 关闭 `Support mounting NFS file systems on Linux < 2.6.23`（网络文件系统）
- `Networking Utilities`
  - 关闭 `inetd`（Internet 超级服务器）

接下来在 Busybox 目录下简单配置一下启动脚本：

```
➜  _install mkdir proc sys dev etc etc/init.d
➜  _install vim etc/init.d/rcS
➜  _install chmod +x etc/init.d/rcS
➜  _install cat etc/init.d/rcS
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
```

然后创建文件系统：

```
$ find . | cpio -o --format=newc > ../rootfs.img
```

接下来就可以启动系统了：

```bash
$ qemu-system-x86_64 \
    -kernel $KERNEL_SRC/arch/x86_64/boot/bzImage \
    -initrd $BUSYBOX_SRC/rootfs.img \
    -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
    -cpu kvm64,+smep,+smap \
    --nographic \
    -gdb tcp::1234
```

# Finally

接下来使用用 gdb 进行调试：

```gdb
➜  ~ gdb -ex "target remote localhost:1234" $KERNEL_SRC/vmlinux
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 7.11.1 using Python engine 3.5
Remote debugging using localhost:1234
native_safe_halt () at ./arch/x86/include/asm/irqflags.h:50
50    }
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000000000000000  →  0x0000000000000000
$rbx   : 0xffffffff81d585c0  →  0x0000000000000001  →  0x0000000000000001
$rcx   : 0x0000000000000000  →  0x0000000000000000
$rdx   : 0x0000000000000000  →  0x0000000000000000
$rsp   : 0xffffffff81bf7e98  →  <init_thread_union+16024> mov eax, 0xff81bf7e
$rbp   : 0xffffffff81bf7e98  →  <init_thread_union+16024> mov eax, 0xff81bf7e
$rsi   : 0x0000000000000000  →  0x0000000000000000
$rdi   : 0x0000000000000000  →  0x0000000000000000
$rip   : 0xffffffff810624f6  →  0x000000841f0fc35d  →  0x000000841f0fc35d
$r8    : 0xffff88000760db60  →  0x0000000000000000  →  0x0000000000000000
$r9    : 0x0000000000000000  →  0x0000000000000000
$r10   : 0x0000000000000333  →  0x0000000000000333
$r11   : 0xffff880006d8bde0  →  0x0000000000000400  →  0x0000000000000400
$r12   : 0x0000000000000000  →  0x0000000000000000
$r13   : 0x0000000000000000  →  0x0000000000000000
$r14   : 0x0000000000000000  →  0x0000000000000000
$r15   : 0xffffffff81bf4000  →  <init_thread_union+0> add BYTE PTR [rbp-0x40], dl
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0010 $ss: 0x0018 $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
[!] Unmapped address
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff810624f1 <native_safe_halt+1> mov    rbp, rsp
   0xffffffff810624f4 <native_safe_halt+4> sti
   0xffffffff810624f5 <native_safe_halt+5> hlt
   0xffffffff810624f6 <native_safe_halt+6> pop    rbp
   0xffffffff810624f7 <native_safe_halt+7> ret
   0xffffffff810624f8                  nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff81062500 <native_halt+0>  push   rbp
   0xffffffff81062501 <native_halt+1>  mov    rbp, rsp
   0xffffffff81062504 <native_halt+4>  hlt
────────────────────────────────────────── source:./arch/x86/incl[...].h+50 ────
     45     }
     46
     47     static inline void native_safe_halt(void)
     48     {
     49         asm volatile("sti; hlt": : :"memory");
 →   50     }
     51
     52     static inline void native_halt(void)
     53     {
     54         asm volatile("hlt": : :"memory");
     55     }
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "", stopped, reason: SIGTRAP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xffffffff810624f6 → native_safe_halt()
[#1] 0xffffffff81020cee → arch_safe_halt()
[#2] 0xffffffff81020cee → default_idle()
[#3] 0xffffffff8102147f → arch_cpu_idle()
[#4] 0xffffffff810c06fa → default_idle_call()
[#5] 0xffffffff810c0a37 → cpuidle_idle_call()
[#6] 0xffffffff810c0a37 → cpu_idle_loop()
[#7] 0xffffffff810c0a37 → cpu_startup_entry(state=<optimized out>)
[#8] 0xffffffff8181accc → rest_init()
[#9] 0xffffffff81d7f023 → start_kernel()
────────────────────────────────────────────────────────────────────────────────
gef➤  b cmdline_proc_show
Breakpoint 1 at 0xffffffff81276000: file fs/proc/cmdline.c, line 7.
gef➤  c
Continuing.
```

在终端输入 `cat /proc/cmdline` 后会被断点断下来：

```bash
/ # id
uid=0 gid=0
/ # whoami
whoami: unknown uid 0
/ # pwd
/
/ # cat /proc/cmdline
```

可以跟着源码调试了：

```gdb
...
Breakpoint 1, cmdline_proc_show (m=0xffff880005f7c180, v=0x1 <irq_stack_union+1>) at fs/proc/cmdline.c:7
7    {
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xffff880000047ee0  →   push rax
$rbx   : 0x0000000000000000  →  0x0000000000000000
$rcx   : 0x0000000000003014  →  0x0000000000003014
$rdx   : 0x0000000000003013  →  0x0000000000003013
$rsp   : 0xffff880005fc3868  →   mov esp, 0xff812245
$rbp   : 0xffff880005fc38d0  →   lock cmp ah, bh
$rsi   : 0x0000000000000001  →  0x0000000000000001
$rdi   : 0xffff880005f7c180  →   add BYTE PTR [rax], al
$rip   : 0xffffffff81276000  →  <cmdline_proc_show+0> nop DWORD PTR [rax+rax*1+0x0]
$r8    : 0xffff880007619bc0  →   add BYTE PTR [rax-0xc], al
$r9    : 0xffff880005f40000  →   add BYTE PTR [rax-0xc], al
$r10   : 0x0000000000000001  →  0x0000000000000001
$r11   : 0xffff880005fc4000  →  0x0000000000000000  →  0x0000000000000000
$r12   : 0xffff880005fc3a88  →  0x0000000000000000  →  0x0000000000000000
$r13   : 0xffff880005f7d000  →  0x0000000000000000  →  0x0000000000000000
$r14   : 0xffff880005f7c180  →   add BYTE PTR [rax], al
$r15   : 0x0000000000000001  →  0x0000000000000001
$eflags: [CARRY parity adjust zero sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0010 $ss: 0x0018 $ds: 0x0000 $es: 0x0000 $fs: 0x0063 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
[!] Unmapped address
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff81275ff7 <cmdline_proc_open+23> repnz  cli
   0xffffffff81275ff9 <cmdline_proc_open+25> call   FWORD PTR [rbp-0x3d]
   0xffffffff81275ffc                  nop    DWORD PTR [rax+0x0]
   0xffffffff81276000 <cmdline_proc_show+0> nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff81276005 <cmdline_proc_show+5> push   rbp
   0xffffffff81276006 <cmdline_proc_show+6> mov    rdx, QWORD PTR [rip+0xcccffb]        # 0xffffffff81f43008 <saved_command_line>
   0xffffffff8127600d <cmdline_proc_show+13> mov    rsi, 0xffffffff81b454d3
   0xffffffff81276014 <cmdline_proc_show+20> mov    rbp, rsp
   0xffffffff81276017 <cmdline_proc_show+23> call   0xffffffff81224970 <seq_printf>
──────────────────────────────────────────────── source:fs/proc/cmdline.c+7 ────
      2     #include <linux/init.h>
      3     #include <linux/proc_fs.h>
      4     #include <linux/seq_file.h>
      5
      6     static int cmdline_proc_show(struct seq_file *m, void *v)
 →    7     {
      8         seq_printf(m, "%s\n", saved_command_line);
      9         return 0;
     10     }
     11
     12     static int cmdline_proc_open(struct inode *inode, struct file *file)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xffffffff81276000 → cmdline_proc_show(m=0xffff880005f7c180, v=0x1 <irq_stack_union+1>)
[#1] 0xffffffff812245bc → seq_read(file=0xffff880005f7d000, buf=<optimized out>, size=<optimized out>, ppos=0xffff880005fc3a88)
[#2] 0xffffffff8126d4e2 → proc_reg_read(file=<optimized out>, buf=<optimized out>, count=<optimized out>, ppos=<optimized out>)
[#3] 0xffffffff811fff55 → do_loop_readv_writev(filp=<optimized out>, iter=0xffff880005fc3958, ppos=0xffff880005fc3a88, fn=0xffffffff8126d4a0 <proc_reg_read>)
[#4] 0xffffffff81200d52 → do_readv_writev(type=0x0, file=0xffff880005f7d000, uvector=<optimized out>, nr_segs=<optimized out>, pos=0xffff880005fc3a88)
[#5] 0xffffffff81200da6 → vfs_readv(file=<optimized out>, vec=<optimized out>, vlen=<optimized out>, pos=<optimized out>)
[#6] 0xffffffff8123283a → kernel_readv(offset=<optimized out>, vlen=<optimized out>, vec=<optimized out>, file=<optimized out>)
[#7] 0xffffffff8123283a → default_file_splice_read(in=<optimized out>, ppos=<optimized out>, pipe=<optimized out>, len=0xff0000, flags=<optimized out>)
[#8] 0xffffffff81231209 → do_splice_to(in=0xffff880005f7d000, ppos=0xffff880005fc3df0, pipe=0xffff880005f7c300, len=0x1000000, flags=0x0)
[#9] 0xffffffff812312da → splice_direct_to_actor(in=<optimized out>, sd=0x1 <irq_stack_union+1>, actor=<optimized out>)
────────────────────────────────────────────────────────────────────────────────
...
```

# References

https://xz.aliyun.com/t/2306
http://pwn4.fun/2017/04/17/Linux%E5%86%85%E6%A0%B8%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%EF%BC%88%E4%B8%80%EF%BC%89%E7%8E%AF%E5%A2%83%E9%85%8D%E7%BD%AE/
https://veritas501.space/2018/06/03/kernel%E7%8E%AF%E5%A2%83%E9%85%8D%E7%BD%AE/
https://n132.github.io/2019/07/14/2019-07-14-kernel-Outset/
