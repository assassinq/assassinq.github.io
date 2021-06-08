---
title: 2018-ZJGSUCTF
date: 2018-05-07 12:06:41
tags: [ctf, wp]
---

第一次连续肝了两天的比赛，真正感受到了比赛的氛围，还有被大佬带飞的感觉，记录一下简单的几道题。

<!-- more -->

# WEB

## 奇淫技巧

第一关，md5 碰撞。

第二关，数组绕过。

第三关，%00 截断。

第四关，PHP 伪协议 `data:text/plain,<?php phpinfo()?>`。（附上[大佬博客](https://lalajun.github.io/2018/03/19/WEB-LFI%E4%B8%8ERFI%E5%88%A9%E7%94%A8/)）

## 送分的

点击 `flag in here` 后，跳转到另一个网站，提示为非法源无法访问。

想到 `X-Forwarded-For` 和 `Referer`，经过尝试得到 flag。

![](/pics/2018-ZJGSUCTF/WEB/1.jpg)

## 给你的小世界

打开网站先欣赏一遍精彩的小故事，然后查看源码，得到提示。

![](/pics/2018-ZJGSUCTF/WEB/2.jpg)

第一段字母显然是 base64，然后根据解码后得到的提示分别 base32、base16 解密得到 flag。

# RE

RE 这块主要是复现。

## 签到题

发现题目打不开，原来是文本文件，有一段 C 代码和汇编组成。

![](/pics/2018-ZJGSUCTF/RE/1.jpg)

可以判断下面的汇编代码就是函数 `ck1()` 的汇编形式。具体操作也很容易看出：

```asm
.text:0040104A loc_40104A:                             ; CODE XREF: ck1+1F↑j
.text:0040104A                 mov     ecx, [ebp+var_4]
.text:0040104D                 cmp     ecx, [ebp+arg_4]
.text:00401050                 jge     short loc_40106B
.text:00401052                 mov     edx, [ebp+arg_0]
.text:00401055                 add     edx, [ebp+var_4]
.text:00401058                 movsx   eax, byte ptr [edx]
.text:0040105B                 xor     eax, 30h
.text:0040105E                 add     eax, 1
.text:00401061                 mov     ecx, [ebp+arg_0]
.text:00401064                 add     ecx, [ebp+var_4]
.text:00401067                 mov     [ecx], al
.text:00401069                 jmp     short loc_401041
```

可以看到就是把 `enc` 字符串中的每个字符分别和 `0x30` 异或后再加一。

加密脚本（实际上就是填充函数 `ck1()` 的内容）如下：

```cpp
#include <stdio.h>
#include <string.h>
int main() {
    char enc[37]="\x55\x5b\x50\x56\x4a\x66\x54\x5b\x52\x5e\x5c\x54\x6e\x43\x1f\x6e\x41\x54\x6e\x43\x57\x58\x42\x6e\x58\x42\x6e\x5e\x5d\x5b\x48\x6e\x50\x42\x5c\x4c";
	for(int i = 0; i < strlen(enc); i++) {
	    enc[i] ^= 0x30;
	    enc[i] += 1;
	}
	printf("%s\n",enc);
    return 0;
}
```

## babyre

这题涉及到 ida 的一个小技巧 patch，通过[看雪上的一篇文章](https://bbs.pediy.com/thread-158896.htm)了解了一下。f5 发现不行，显示栈不平衡，需要 patch。

![](/pics/2018-ZJGSUCTF/RE/2.jpg)

先根据提示找到出错的位置。在 option 中勾选显示栈指针。然后再找到距离 `ret` 最近的 `call`，然后修改栈指针的值。

![](/pics/2018-ZJGSUCTF/RE/3.jpg)

![](/pics/2018-ZJGSUCTF/RE/4.jpg)

成功 f5 后审计代码：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *enc1; // esi
  signed int v4; // eax
  int v5; // esi
  char sbox; // [esp+Ch] [ebp-238h]
  char Dst; // [esp+Dh] [ebp-237h]
  char key; // [esp+10Ch] [ebp-138h]
  char v10; // [esp+12Eh] [ebp-116h]
  char input[52]; // [esp+20Ch] [ebp-38h]

  sbox = 0;
  memset(&Dst, 0, 0xFFu);
  strcpy(&key, "flag{this_is_not_the_flag_hahaha}");
  memset(&v10, 0, 0xDEu);
  printf("input flag:\n");
  scanf("%50s", input);
  if ( strlen(input) == 33 )
  {
    enc1 = base64encypt(input);
    rc4_init(&sbox, (int)&key, strlen(&key));
    rc4_crypto((int)&sbox, (int)enc1, strlen(enc1));
    v4 = 0;
    v5 = enc1 - flag;
    do
    {
      if ( flag[v5 + v4] != flag[v4] )
        exit(0);
      ++v4;
    }
    while ( v4 < 44 );
    printf("Congratulation!!!!!!\n");
  }
  return 0;
}
```

经过对代码的审计，判断出先对输入字符串进行了 base64 加密，然后再通过 rc4 加密。在内存中分别找到 base64 的表以及被加密的 flag。

![](/pics/2018-ZJGSUCTF/RE/5.jpg)

![](/pics/2018-ZJGSUCTF/RE/6.jpg)

用 python2 中的 `pycrypto`（使用方法：`from Crypto.Cipher`）进行 rc4 的加解密；用 `base64` 库进行 base64 加解密。脚本如下：

```python
from Crypto.Cipher import ARC4
import base64
import string
print '-----------------ARC4-----------------'
key = 'flag{this_is_not_the_flag_hahaha}'
flag = '\x20\xC3\x1A\xAE\x97\x3C\x7A\x41\xDE\xF6\x78\x15\xCB\x4B\x4C\xDC\x26\x55\x8B\x55\xE5\xE9\x55\x75\x40\x3D\x82\x13\xA5\x60\x13\x3B\xF5\xD8\x19\x0E\x47\xCF\x5F\x5E\xDE\x9D\x14\xBD'
enc1 = ARC4.new(key).decrypt(flag)
print enc1
print '----------------base64----------------'
replaced = ''
Base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
table = 'ABCDEFGHIJSTUVWKLMNOPQRXYZabcdqrstuvwxefghijklmnopyz0123456789+/'
for ch in enc1:
    if ch in Base64:
        replaced += Base64[string.find(table, str(ch))]
    elif ch == '=':
        replaced += '='
print base64.b64decode(replaced)
```

## New driver

拖进 OD 一运行就退出了。拖进 ida 发现有 tls 反调试：

![](/pics/2018-ZJGSUCTF/RE/7.jpg)

用 PEview 查看 exe 中相关 PE 结构，然后在 010editor 中将对应部分的 value 清零：

![](/pics/2018-ZJGSUCTF/RE/8.jpg)

除去 tls 后查壳发现有 upx。脱去后放进 ida：

```cpp
int main_0()
{
  HANDLE thread_2; // [esp+D0h] [ebp-14h]
  HANDLE thread_1; // [esp+DCh] [ebp-8h]

  j_read_input();
  hObject = CreateMutexW(0, 0, 0);
  j_strcpy(Dest, Source);
  thread_1 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)one, 0, 0, 0);
  thread_2 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)two, 0, 0, 0);
  CloseHandle(thread_1);
  CloseHandle(thread_2);
  while ( dword_418008 != -1 )
    ;
  j_print_dest();
  CloseHandle(hObject);
  return 0;
}
```

一开始读取输入字符串，中间创建了两个线程，然后最后与被加密的 flag 进行比较以及输出 flag。回去看两个线程发现第二个线程没干什么事，主要是第一个线程进行了加密。其中加密函数的 sp 指针不平衡，需要修改指针值。修改后，进入函数：

```cpp
char **__cdecl encrypt(char *input, int index)
{
  char **result; // eax
  char v3; // [esp+D3h] [ebp-5h]

  v3 = input[index];
  if ( (v3 < 'a' || v3 > 'z') && (v3 < 'A' || v3 > 'Z') )
    exit(0);
  if ( v3 < 'a' || v3 > 'z' )                   // lower case
  {
    result = (char **)table;
    input[index] = table[input[index] - 38];
  }
  else                                          // upper case
  {
    result = (char **)table;
    input[index] = table[input[index] - 96];
  }
  return result;
}
```

对每个字符大小写进行了判断，然后减法操作。还有一点是两个线程每次循环分别都 sleep 了 100s，那么依次循环就会造成奇偶依次加密。solve 脚本：

```python
table = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm'
enc = [0x54, 0x4F, 0x69, 0x5A, 0x69, 0x5A, 0x74, 0x4F, 0x72, 0x59, 0x61, 0x54, 0x6F, 0x55, 0x77, 0x50, 0x6E, 0x54, 0x6F, 0x42, 0x73, 0x4F, 0x61, 0x4F, 0x61, 0x70, 0x73, 0x79, 0x53, 0x79]
flag = ''
for i in range(len(enc)):
  if i % 2 == 0:
    flag += chr(enc[i])
  else:
    idx = table.index(chr(enc[i]))
    if idx > 26: # lower case
      flag += chr(idx + 38)
    else: # upper case
      flag += chr(idx + 96)
print 'flag:', flag
```

## Old driver

32 位 exe 文件，拖进 ida 后，除了判断了字串长度为 40 和前后缀的 check，还发现函数被加密了：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // ecx
  signed int j; // eax
  char input[39]; // [esp+0h] [ebp-40h]
  char v7; // [esp+27h] [ebp-19h]
  int v8; // [esp+34h] [ebp-Ch]
  __int16 v9; // [esp+38h] [ebp-8h]
  char v10; // [esp+3Ah] [ebp-6h]

  input[0] = 0;
  memset(&input[1], 0, 0x31u);
  printf("input flag:\n");
  scanf("%50s", input);
  if ( strlen(input) == 40 )
  {
    for ( i = 0; i < (char *)nullsub_1 - (char *)dword_401000; ++i )
      *((_BYTE *)dword_401000 + i) ^= 0xBBu;
    v9 = 32123;
    v8 = 1734437990;
    v10 = 0;
    j = 0;
    do
    {
      if ( input[j] != *((_BYTE *)&v8 + j) )
        goto LABEL_8;
      ++j;
    }
    while ( j < 5 );
    LOBYTE(i) = v7;
    if ( v7 != *((_BYTE *)&v8 + j) )
LABEL_8:
      exit(0);
    ((void (__fastcall *)(int, char *))loc_4010B0)(i, input);
  }
  return 0;
}
```

可以用 IDAPython 来 patch 一下：

```python
from ida_bytes import *
start_addr = 0x00401000
end_addr = 0x00401260
for i in range(start_addr, end_addr, 4):
  tmp = get_bytes(i, 1)
  patch_bytes(i, chr(ord(tmp) ^ 0xbb))
```

或者用 Ollydbg 把解密过后的程序 dump 出来。找到加密过后的位置设下断点，断下来之后 dump 即可（注意前面还需要过一个长度的 check）：

![](/pics/2018-ZJGSUCTF/RE/9.jpg)

把 dump 出来的程序拖进 ida：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // ecx
  signed int j; // eax
  char input[39]; // [esp+0h] [ebp-40h]
  char v7; // [esp+27h] [ebp-19h]
  int v8; // [esp+34h] [ebp-Ch]
  __int16 v9; // [esp+38h] [ebp-8h]
  char v10; // [esp+3Ah] [ebp-6h]

  input[0] = 0;
  memset(&input[1], 0, 0x31u);
  printf("input flag:\n");
  scanf("%50s", input);
  if ( strlen(input) == 40 )
  {
    for ( i = 0; i < (char *)nullsub_1 - (char *)maze_solve; ++i )
      *((_BYTE *)maze_solve + i) ^= 0xBBu;
    v9 = '}{';
    v8 = 'galf';
    v10 = 0;
    j = 0;
    do
    {
      if ( input[j] != *((_BYTE *)&v8 + j) )
        goto LABEL_8;
      ++j;
    }
    while ( j < 5 );
    LOBYTE(i) = v7;
    if ( v7 != *((_BYTE *)&v8 + j) )
LABEL_8:
      exit(0);
    base64(i, input);
  }
  return 0;
}
```

进入加密函数后，先是对六位异或，然后 base64 几位字符，最后走个 maze。solve 脚本：

```python
import base64
flag = 'flag{'
enc1 = [0xF2, 0xEE, 0xEF, 0xF5, 0xD9, 0xEF]
for i in range(len(enc1)):
  flag += chr(enc1[i] ^ 0x86)
enc2 = 'z91c'[::-1] + 'fNWb'[::-1]
flag += base64.b64decode(enc2)
# maze
# --------
# g +    +
# + + ++ +
# + + #+ +
# + ++++ +
# + ++++ +
# +      +
# --------
# 'a'-down '2'-up 'q'-left 'w'-right
path = 'waaaaawwwww22222qqaaw'
flag += path
flag += '}'
print 'flag:', flag
```

## 秋名山车神

```shell
$ file re5
re5: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1c630722da16df2163ff83ea21cce93bf6b71a87, not stripped
```

32 位 elf 拖进 ida 查看：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-2F0h]
  char m_t; // [esp+80h] [ebp-270h]
  char matrix; // [esp+180h] [ebp-170h]
  char input; // [esp+282h] [ebp-6Eh]
  int pipes[2]; // [esp+2C8h] [ebp-28h]
  __pid_t pid; // [esp+2D0h] [ebp-20h]
  size_t length; // [esp+2D4h] [ebp-1Ch]
  int *v11; // [esp+2E4h] [ebp-Ch]

  v11 = &argc;
  length = 0;
  memset(&v4, 0, 0x80u);
  puts("input flag:");
  __isoc99_scanf();
  length = strlen(&input);
  if ( length != 64 )
    return 0;
  if ( pipe(pipes) < 0 )
    exit(1);
  pid = fork();
  if ( pid < 0 )
    exit(1);
  if ( pid <= 0 )                               // children process
  {
    close(pipes[1]);
    read(pipes[0], &input, length);
    ck2((char **)&matrix, &input);
    ck3((char **)key_matrix, (char **)&matrix, (int)&m_t, 8, 8, 8);
    if ( ck4((int)&m_t) )
      printf("Congratulate!!!");
  }
  else                                          // father process
  {
    close(pipes[0]);
    ck1(&input, length);
    write(pipes[1], &input, length);
    wait(0);
  }
  return 0;
}
```

main 函数中主要是先读取一个字符串，如果长度不为 64 则退出。之后 fork 了一个子进程，然后新建一个 pipe，在父进程把字符串输入 pipe，经过 `ck1()` 之后送到 pipe 里；子进程从 pipe 读取字符串，经过 `ck2()` 和 `ck3()` 后，在 `ck4()` 里判断。下面一个个分析。

`ck1()` 是 rot13 加密：

```cpp
int __cdecl ck1(char *input, int length)
{
  int result; // eax
  char v3; // [esp+Bh] [ebp-5h]
  int i; // [esp+Ch] [ebp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= length )
      break;
    v3 = input[i] + 13;
    if ( input[i] <= 96 || input[i] > 122 )
    {
      if ( input[i] <= 64 || input[i] > 90 )
      {
        v3 = input[i];
      }
      else if ( (unsigned __int8)v3 > 0x5Au )
      {
        v3 = input[i] - 13;
      }
    }
    else if ( (unsigned __int8)v3 > 0x7Au )
    {
      v3 = input[i] - 13;
    }
    input[i] = v3;
  }
  return result;
}
```

`ck2()` 这里把输入的字符串转化成 8x8 的矩阵：

```cpp
signed int __cdecl ck2(char **m, char *input)
{
  signed int result; // eax
  int v3; // eax
  char *v4; // edx
  int v5; // [esp+4h] [ebp-Ch]
  signed int i; // [esp+8h] [ebp-8h]
  signed int j; // [esp+Ch] [ebp-4h]

  result = 134520832;
  v5 = 0;
  for ( i = 0; i <= 7; ++i )
  {
    for ( j = 0; j <= 7; ++j )
    {
      v3 = v5;
      v5 += (int)&(&GLOBAL_OFFSET_TABLE_)[4290763520] + 1;
      v4 = (char *)input[v3];
      result = j;
      (&m[8 * i])[j] = v4;
    }
  }
  return result;
}
```

`ck3()` 将输入的矩阵与一个 global 的矩阵 `key` 相乘：

```cpp
int __cdecl ck3(char **key, char **input, char **a3, int a4_8, int a5_8, int a6_8)
{
  int result; // eax
  int m; // [esp+4h] [ebp-10h]
  int i; // [esp+8h] [ebp-Ch]
  int k; // [esp+8h] [ebp-Ch]
  int j; // [esp+Ch] [ebp-8h]
  int l; // [esp+Ch] [ebp-8h]

  for ( i = 0; i < a5_8; ++i )
  {
    for ( j = 0; j < a4_8; ++j )
      (&a3[8 * i])[j] = 0;
  }
  for ( k = 0; ; ++k )
  {
    result = k;
    if ( k >= a5_8 )
      break;
    for ( l = 0; l < a4_8; ++l )
    {
      for ( m = 0; m < a6_8; ++m )
        (&a3[8 * k])[l] = &(&a3[8 * k])[l][(_DWORD)(&key[8 * k])[m] * (_DWORD)(&input[8 * m])[l]];
    }
  }
  return result;
}
```

最后的 `ck4()` 将输出的矩阵与 global 的 `enc_flag` 进行比较：

```cpp
signed int __cdecl ck4(char **m)
{
  signed int i; // [esp+8h] [ebp-Ch]
  signed int j; // [esp+Ch] [ebp-8h]

  for ( i = 0; i <= 7; ++i )
  {
    for ( j = 0; j <= 7; ++j )
    {
      if ( (&m[8 * i])[j] != *(char **)&enc_flag[4 * (8 * i + j)] )
        return 0;
    }
  }
  return 1;
}
```

主要用 numpy，可以比较方便地实现矩阵间的运算。脚本如下：

```python
import numpy as np
key = [0x0000002B, 0x00000016, 0x0000001E, 0x00000053, 0x00000035, 0x00000039, 0x00000020, 0x00000029, 0x00000035, 0x00000063, 0x0000000A, 0x00000028, 0x0000002C, 0x00000006, 0x00000032, 0x0000002A, 0x00000055, 0x00000039, 0x00000014, 0x0000005F, 0x00000020, 0x00000019, 0x00000034, 0x00000021, 0x00000019, 0x0000000B, 0x0000005A, 0x00000009, 0x00000050, 0x00000034, 0x0000006F, 0x0000005C, 0x00000016, 0x0000001A, 0x00000068, 0x00000063, 0x00000034, 0x0000004E, 0x00000016, 0x00000045, 0x0000004C, 0x00000053, 0x0000002F, 0x0000003F, 0x0000003F, 0x00000028, 0x00000069, 0x00000051, 0x00000039, 0x00000044, 0x00000012, 0x00000024, 0x0000000A, 0x0000004D, 0x00000055, 0x00000031, 0x00000049, 0x0000003B, 0x00000040, 0x0000003B, 0x00000043, 0x00000028, 0x00000021, 0x00000036]
enc = [0x00009A06, 0x0000879A, 0x00007DC4, 0x00008F1F, 0x000088AC, 0x0000850B, 0x0000785D, 0x0000822E, 0x00008FBC, 0x00007F69, 0x000081E5, 0x00008714, 0x00008572, 0x00008786, 0x00006A94, 0x000076FE, 0x0000A871, 0x00009A1E, 0x0000967E, 0x00009D97, 0x00009D4B, 0x00009AC6, 0x00007E38, 0x00008C62, 0x0000CD4A, 0x00009116, 0x0000A837, 0x0000A960, 0x0000A3A7, 0x00009B7E, 0x0000AC9C, 0x0000AB9E, 0x0000C94C, 0x0000AD7C, 0x0000A2C8, 0x0000BD86, 0x0000B1ED, 0x0000AD94, 0x0000A195, 0x0000AFE8, 0x0000ED71, 0x0000C239, 0x0000CD7E, 0x0000D459, 0x0000CEFF, 0x0000CBBC, 0x0000B972, 0x0000C36F, 0x0000A82A, 0x000089EF, 0x00008CBF, 0x00009AD1, 0x0000868F, 0x000086A6, 0x00007A26, 0x00007CD2, 0x0000C000, 0x0000A97A, 0x0000A470, 0x0000B3C8, 0x0000AFE5, 0x0000ABB9, 0x00008F7D, 0x0000A70A]
key = np.mat(key).reshape(8, 8)
enc = np.mat(enc).reshape(8, 8)
# enc = key * out
# out = key逆 * enc
out = key.I * enc
out = out.reshape(1, 64).tolist()[0]
for i in range(len(out)):
  out[i] = int(round(out[i]))
print out

flag = ''
for i in range(len(out)):
  flag += chr(out[i])
print flag

def rot13(s):
	out = ''
	for ch in s:
		tmp = ord(ch) + 13
		if ch.isupper():
			if tmp > 90:
				tmp -= 26
		elif ch.islower():
			if tmp > 122:
				tmp -= 26
		else:
			tmp = ord(ch)
		out += chr(tmp)
	return out

flag = rot13(flag)
print 'flag:', flag
```

# CRYPTO

## 贝斯家族永不言败

各种 base 解码。

## 壮壮可能是疯了...

通过猪圈密码解开第一步。

![](/pics/2018-ZJGSUCTF/CRYPTO/1.png)

# MISC

## 这是神魔鬼

词频题，解码网站在[这里](https://www.quipqiup.com)。

## 表情包 10 块钱

用 stegsolve 打开 gif 逐帧查看，快速看过 260+的图像后，收集到一张二维码的四片碎片，用美图秀秀拼接起来，再 XOR 一下，扫码得到 flag。

## 童年

用金手指作弊通关魂斗罗得到 flag。

![](/pics/2018-ZJGSUCTF/MISC/1.jpg)

# 参考网站

https://esebanana.github.io/2018/05/07/wp_2018_5_7_ZJGSUCTF/
https://bbs.pediy.com/thread-158896.htm
https://esebanana.github.io/2018/04/08/re_10_tls_smc/
https://esebanana.github.io/2018/04/12/re_11_tou_ke/
https://www.52pojie.cn/thread-593356-1-1.html
