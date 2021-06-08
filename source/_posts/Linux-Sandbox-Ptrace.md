---
title: Linux Sandbox - Ptrace
date: 2020-04-18 22:15:40
tags: [linux, ctf]
---

ptrace 是一个系统调用，也可以用作实现沙箱。

<!-- more -->

# What is Ptrace

ptrace 是一个系统调用，Tracer 进程可以监控和修改 Tracee 进程的运行状态，如内存、寄存器的值等。使用 ptrace 可以让某一进程处于受控状态，所以可以用作实现沙箱，如利用 ptrace 来监控 Tracee 使用哪些系统调用，并禁止 Tracee 使用某些危险的系统调用等。ptrace 使用信号来进行进程间通信：

```bash
$ kill -l
 1) SIGHUP       2) SIGINT       3) SIGQUIT      4) SIGILL       5) SIGTRAP
 2) SIGABRT      7) SIGBUS       8) SIGFPE       9) SIGKILL     10) SIGUSR1
1)  SIGSEGV     12) SIGUSR2     13) SIGPIPE     14) SIGALRM     15) SIGTERM
2)  SIGSTKFLT   17) SIGCHLD     18) SIGCONT     19) SIGSTOP     20) SIGTSTP
3)  SIGTTIN     22) SIGTTOU     23) SIGURG      24) SIGXCPU     25) SIGXFSZ
4)  SIGVTALRM   27) SIGPROF     28) SIGWINCH    29) SIGIO       30) SIGPWR
5)  SIGSYS      34) SIGRTMIN    35) SIGRTMIN+1  36) SIGRTMIN+2  37) SIGRTMIN+3
6)  SIGRTMIN+4  39) SIGRTMIN+5  40) SIGRTMIN+6  41) SIGRTMIN+7  42) SIGRTMIN+8
7)  SIGRTMIN+9  44) SIGRTMIN+10 45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13
8)  SIGRTMIN+14 49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12
9)  SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9  56) SIGRTMAX-8  57) SIGRTMAX-7
10) SIGRTMAX-6  59) SIGRTMAX-5  60) SIGRTMAX-4  61) SIGRTMAX-3  62) SIGRTMAX-2
11) SIGRTMAX-1  64) SIGRTMAX
```

# How to trace

ptrace 的作用：

- Tracer 追踪 Tracee 的执行
- 拦截特定的事件（TRAP、SYSCALL）
- 读写 Tracee 的运行状态，如内存、寄存器的值等
- 用来实现 gdb 和 strace

ptrace 的函数原型如下。其中 `request` 指明进行的操作，`pid` 为被追踪的进程（`pid`、`addr` 和 `data` 有时不会派上用场，根据具体情况而定）：

```cpp
#include <sys/ptrace.h>
#include <sys/user.h>

long ptrace(enum __ptrace_request request, pid_t pid,
                        void *addr, void *data);
```

`request` 有很多定义，这里记录几个常用的（详见 [Linux Programmer's Manual](http://man7.org/linux/man-pages/man2/ptrace.2.html)）：

- `PTRACE_TRACEME`：表明该进程会被父进程追踪。`pid`、`addr` 和 `data` 的值被忽略。这也是唯一能被 Tracee 使用的 `request`，其他的 `request` 都由 Tracer 指定；
- `PTRACE_ATTACH`：Tracer 向 Tracee 发送 SIGSTOP 信号使其暂停，并对 Tracee 追踪；
- `PTRACE_SEIZE`（从 Linux 3.4 开始有的 `request`）：追踪指定 `pid` 的进程，但不会像 `PTRACE_ATTACH` 一样让 Tracee 暂停。`addr` 必须为 0，`data` 指定 ptrace 选项；
- `PTRACE_DETACH`：解除追踪关系，Tracee 将继续运行；
- `PTRACE_CONT`：重启停止的 Tracee 进程，如果 `data` 不为 0，该值就会被当成对应的 Signal 传给 Tracee；反之不会发送 Signal。`addr` 的值被忽略；
- `PTRACE_SYSCALL`：在系统调用的入口或是出口处将 Tracee 进程停止并进行追踪。`addr` 的值被忽略；
- `PTRACE_PEEKUSER`：在 Tracee 的用户内存里获取一个字的数据，其中 `addr` 是在结构体 `user`（`/usr/include/sys/user.h`）中的偏移。

## Trace Child Process

- 先在子进程中调用 `ptrace(PTRACE_TRACEME)`；
- 在父进程中使用 `waitpid(pid)` 等待；
- 然后使用 `ptrace(PTRACE_CONT)` 继续执行；
  - 如果没有遇到 `int 0x3` 就会一直跑；
  - 要追 syscall 的时候可以用 `ptrace(PTRACE_SYSCALL)`。

测试代码如下。子进程被父进程追踪，父进程在等待追踪结束后，重启子进程：

```cpp
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (pid) {
        while (1) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)){
                break;
            }
            // ...
            ptrace(PTRACE_CONT, pid, 0, 0);
        }
    } else {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/bin/ls", "ls", NULL);
    }
}
```

## Trace syscall

- 使用 `ptrace(PTRACE_PEEKUSER)` 来读取 CPU；
  - addr 为结构体 `user` 中的偏移；
  - [`arch/x86/include/asm/user_32.h`](https://elixir.bootlin.com/linux/v4.4.31/source/arch/x86/include/asm/user_32.h)（`/usr/include/sys/user.h`）
  - orig_rax 为系统调用号；
- syscall 分别在 enter 和 exit 时各中断一次；
  - exit 的时候可以在 rax 获取返回值。

添加一个 incall 来判断在 syscall 的 enter 和 exit 之间的切换，并在系统调用退出时输出调用号；然后获取 `user` 结构体中的 `orig_rax` 字段，即系统调用号：

```cpp
    int incall = 0;
    while (1) {
        // ...
        long orig_rax = ptrace(PTRACE_PEEKUSER, pid,
            offsetof(struct user, regs.orig_rax), 0);
        if (incall) {
            printf("nr = %ld\n", orig_rax);
        }
        incall = ~incall;
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
```

## 读取 Tracee 的内容

- `ptrace(PTRACE_PEEKDATA)`
- 固定读一个字（4 字节）

`/bin/ls` 中调用了 write 进行输出，可以对 write 进行追踪并获取相应的内容：

```cpp
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (pid) {
        int incall = 0;
        while (1) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)){
                break;
            }
            long orig_rax = ptrace(PTRACE_PEEKUSER, pid,
                offsetof(struct user, regs.orig_rax), 0);
            long rsi = ptrace(PTRACE_PEEKUSER, pid,
                offsetof(struct user, regs.rsi), 0);
            long rdx = ptrace(PTRACE_PEEKUSER, pid,
                offsetof(struct user, regs.rdx), 0);
            long rax = ptrace(PTRACE_PEEKUSER, pid,
                offsetof(struct user, regs.rax), 0);
            //printf("nr = %ld\n", orig_rax);
            if (incall) {
                if (orig_rax == 1) {
                    printf("write(\"");
                    for (int i = 0; i < rdx; i++) {
                        int d = ptrace(PTRACE_PEEKDATA, pid,
                            rsi + i, 0);
                        printf("%c", d & 0xff);
                    }
                }
            } else {
                if (orig_rax == 1) {
                    printf("\") = %d\n", (int)rax);
                }
            }
            incall = ~incall;
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
    } else {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/bin/ls", "ls", NULL);
    }
}
```

运行结果：

```bash
➜  ptrace ./ptrace
write("a  a.c	escape	escape.c  Makefile  ptrace  ptrace.c
a  a.c	escape	escape.c  Makefile  ptrace  ptrace.c
") = 51
```

# Bypass Ptrace Sandbox

- 摆脱对 syscall 的追踪
  - Fork 脱离 Tracer
  - 砍掉父进程
- 绕过 syscall 的检查
  - `syscall_restart` 等造成 incall 计算错误

## Escape by Fork

- 只要 ptrace 没有跟踪好 fork、vfork、clone，子进程就不会被 ptrace 跟踪；
- 正确的做法是要继续跟好子进程，或者直接禁止 fork。
  - 可以设置 `PTRACE_O_TRACECLONE` 选项，会自动跟踪 clone 出来的新进程。

测试代码如下：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (pid) {
        int incall = 0;
        while (1) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)){
                break;
            }
            long orig_rax = ptrace(PTRACE_PEEKUSER, pid,
                offsetof(struct user, regs.orig_rax), 0);
            if (incall) {
                if (orig_rax == 59) {
                    printf("SYS_execve detected\n");
                    kill(pid, SIGKILL);
                    exit(0);
                }
            }
            incall = ~incall;
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
    } else {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("./a", "a", NULL);
    }
}
```

子进程新 fork 一个进程来执行 execve：

```cpp
    if (fork()) {
        sleep(1);
    } else {
        execl("/bin/ls", "ls", 0);
    }
```

运行结果：

```bash
➜  ptrace ./ptrace
a  a.c	escape	escape.c  Makefile  ptrace  ptrace.c
```

## Escape by Kill

- 杀死父进程；
  - `kill(getppid(), 9);`；
  - ppid 无法获取时可以尝试 pid-1；
  - `/proc/self/stat` 中可以拿到 pid 和 ppid；
  - `kill(-1, 9);` 杀死除了自己以外的所有进程。
- 设置 `PTRACE_O_EXITKILL` 可以让 Tracer 结束时把所有的 Tracee 杀死。

在子进程中杀死父进程：

```cpp
    kill(getppid(), 9);
    execl("/bin/ls", "ls", 0);
```

运行效果：

```bash
➜  ptrace ./ptrace
[1]    2211 killed     ./ptrace
a  a.c  escape  escape.c  Makefile  ptrace  ptrace.c
```

用 alarm 和 sleep 可以搅乱 syscall 进出的顺序：

```cpp
    alarm(1);
    sleep(2);
    execl("/bin/ls", "ls", 0);
```

加上一条用来判断进出 syscall 的输出：

```cpp
            printf("%s %ld\n", (incall ? "Enter" : "Exit"), orig_rax);
```

运行效果如下。在执行 alarm 后会导致 sys_nanosleep（35）由进入了一次，后面会调用一个 sys_restart_syscall（219），大概可能和 syscall 的原理有关。在这之后的 syscall 的顺序就会乱掉：

```bash
Enter 35
Exit 35
Enter 35
Exit 219
Enter 219
Exit 59
Enter 59
```

# References

https://www.youtube.com/watch?v=gQXyZY7Ucjc
https://blog.betamao.me/2019/02/02/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bptrace/
https://atum.li/2017/04/25/linuxsandbox/#ptrace
