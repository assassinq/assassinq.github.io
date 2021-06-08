---
title: Python实现DES、AES加密解密算法
date: 2019-11-14 10:09:38
tags: [crypto, python]
---

通过实现 DES 和 AES 深入了解对称加密（实现均采用 CBC 模式）。

<!-- more -->

# DES

数据加密标准（英语：Data Encryption Standard，缩写为 DES）是一种对称密钥加密块密码算法，1976 年被美国联邦政府的国家标准局确定为联邦资料处理标准（FIPS），随后在国际上广泛流传开来。它基于使用 56 位密钥的对称算法。这个算法因为包含一些机密设计元素，相对短的密钥长度以及怀疑内含美国国家安全局（NSA）的后门而在开始时有争议，DES 因此受到了强烈的学院派式的审查，并以此推动了现代的块密码及其密码分析的发展。

## 算法流程

DES 是一种典型的块密码—一种将固定长度的明文通过一系列复杂的操作变成同样长度的密文的算法。对 DES 而言，块长度为 64 位。同时，DES 使用密钥来自定义变换过程，因此算法认为只有持有加密所用的密钥的用户才能解密密文。密钥表面上是 64 位的，然而只有其中的 56 位被实际用于算法，其余 8 位可以被用于奇偶校验，并在算法中被丢弃。因此，DES 的有效密钥长度仅为 56 位。

### 整体结构

算法的整体结构中，有 16 个相同的处理过程（round），并在首尾各有一次置换，称为 $IP$ 与 $FP$（或称 $IP^-1$，$FP$ 为 $IP$ 的反函数。$IP$ 和 $FP$ 几乎没有密码学上的重要性，为了在 1970 年代中期的硬件上简化输入输出数据库的过程而被显式的包括在标准中。

在主处理回次前，数据块被分成两个 32 位的半块，并被分别处理；这种交叉的方式被称为费斯妥结构。费斯妥结构保证了加密和解密过程足够相似—唯一的区别在于子密钥在解密时是以反向的顺序应用的，而剩余部分均相同。这样的设计大大简化了算法的实现，尤其是硬件实现，因为没有区分加密和解密算法的需要。

$\oplus$ 符号代表异或（XOR）操作。“F 函数”将数据半块与某个子密钥进行处理。然后，一个 F 函数的输出与另一个半块异或之后，再与原本的半块组合并交换顺序，进入下一个回次的处理。在最后一个回次完成时，两个半块需要交换顺序，这是费斯妥结构的一个特点，以保证加解密的过程相似。

![](/pics/Python实现DES、AES加密解密算法/1.png)

### 费斯妥函数（F 函数）

费斯妥函数（F 函数）的过程中，其每次对半块（32 位）进行操作，并包括四个步骤：

- 扩张：用扩张置换（图中的 E）将 32 位的半块扩展到 48 位，其输出包括 8 个 6 位的块，每块包含 4 位对应的输入位，加上两个邻接的块中紧邻的位。
- 与密钥混合：用异或操作将扩张的结果和一个子密钥进行混合。16 个 48 位的子密钥—每个用于一个回次的 F 变换—是利用密钥调度从主密钥生成的（见下文）。
- S 盒：在与子密钥混合之后，块被分成 8 个 6 位的块，然后使用“S 盒”，或称“置换盒”进行处理。8 个 S 盒的每一个都使用以查找表方式提供的非线性的变换将它的 6 个输入位变成 4 个输出位。S 盒提供了 DES 的核心安全性—如果没有 S 盒，密码会是线性的，很容易破解。
- 置换：最后，S 盒的 32 个输出位利用固定的置换，“P 置换”进行重组。这个设计是为了将每个 S 盒的 4 位输出在下一回次的扩张后，使用 4 个不同的 S 盒进行处理。

S 盒，P 置换和 E 扩张各自满足了克劳德·香农在 1940 年代提出的实用密码所需的必要条件，“混淆与扩散”。

![](/pics/Python实现DES、AES加密解密算法/2.png)

### 密钥调度

加密过程中密钥调度—产生子密钥的算法里，首先使用选择置换 1（PC-1）从 64 位输入密钥中选出 56 位的密钥—剩下的 8 位要么直接丢弃，要么作为奇偶校验位。然后，56 位分成两个 28 位的半密钥；每个半密钥接下来都被分别处理。在接下来的回次中，两个半密钥都被左移 1 或 2 位（由回次数决定），然后通过选择置换 2（PC-2）产生 48 位的子密钥—每个半密钥 24 位。移位（图中由<<标示）表明每个子密钥中使用了不同的位，每个位大致在 16 个子密钥中的 14 个出现。

解密过程中，除了子密钥输出的顺序相反外，密钥调度的过程与加密完全相同。

![](/pics/Python实现DES、AES加密解密算法/3.png)

## 算法实现

```python
#!/usr/bin/env python
# -*- encoding=utf-8 -*-

ENCRYPT = 0
DECRYPT = 1
BLOCK_SIZE = 8

# 明文分组初始置换表
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16,
      8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# 末置换表
IP_ = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61,
       29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# S盒压缩置换表（6bit->4bit）
S1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3,
      8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
S2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11,
      5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
S3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15,
      1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
S4 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14,
      9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
S5 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8,
      6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
S6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3,
      8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
S7 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8,
      6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
S8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9,
      2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
S = [S1, S2, S3, S4, S5, S6, S7, S8]

# P盒置换表（32bit）
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31,
     10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# 密钥置换表（64bit->56bit）
PC_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44,
        36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# 密钥压缩置换表（56bit->48bit）
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# 明文扩展置换表（32bit->48bit）
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
     17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# 子密钥循环左移位数表（16次）
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

sub_keys = [[0] * 48] * 16

def convert_string_to_bitlist(string):
    data = [ord(c) for c in string]
    l = len(data) * 8
    result = [0] * l
    pos = 0
    for ch in data:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1
    return result

def convert_bitlist_to_string(bitlist):
    result = []
    pos = 0
    c = 0
    while pos < len(bitlist):
        c += bitlist[pos] << (7 - pos % 8)
        if pos % 8 == 7:
            result.append(c)
            c = 0
        pos += 1
    return ''.join([chr(c) for c in result])

def permute(table, block):
    return list(map(lambda x: block[x - 1], table))

def create_sub_keys(key):
    key = permute(PC_1, convert_string_to_bitlist(key))
    i = 0
    lkey = key[:28]
    rkey = key[28:]
    while i < 16:
        j = 0
        while j < SHIFT[i]:
            lkey.append(lkey[0])
            del lkey[0]
            rkey.append(rkey[0])
            del rkey[0]
            j += 1
        sub_keys[i] = permute(PC_2, lkey + rkey)
        # print sub_keys[i]
        i += 1

def des_cipher(block, choice):
    block = permute(IP, block)
    lblock = block[:32]
    rblock = block[32:]
    if choice == ENCRYPT:
        iteration = 0
        iteration_adjustment = 1
    elif choice == DECRYPT:
        iteration = 15
        iteration_adjustment = -1
    i = 0
    # 16轮F函数
    while i < 16:
        rtemp = rblock[:]
        # 将右半块32位扩展为48位
        rblock = permute(E, rblock)
        # 将扩展后的右半块和轮密钥进行逐位异或
        rblock = list(map(lambda x, y: x ^ y, rblock, sub_keys[iteration]))
        b = [rblock[:6], rblock[6:12], rblock[12:18], rblock[18:24],
             rblock[24:30], rblock[30:36], rblock[36:42], rblock[42:]]
        j = 0
        bn = [0] * 32
        pos = 0
        # S盒置换
        while j < 8:
            row = (b[j][0] << 1) + b[j][5]
            col = (b[j][1] << 3) + (b[j][2] << 2) + (b[j][3] << 1) + b[j][4]
            v = S[j][(16 * row) + col]
            bn[pos] = (v & 8) >> 3
            bn[pos + 1] = (v & 4) >> 2
            bn[pos + 2] = (v & 2) >> 1
            bn[pos + 3] = v & 1
            pos += 4
            j += 1
        # 与P盒进行置换
        rblock = permute(P, bn)
        rblock = list(map(lambda x, y: x ^ y, rblock, lblock))
        lblock = rtemp
        i += 1
        iteration += iteration_adjustment
    final = permute(IP_, rblock + lblock)
    return final

def cipher(data, key, iv, choice):
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length illegal.")
    if len(key) != 8 or len(iv) != 8:
        raise ValueError("key/iv\'s length should be 8.")
    create_sub_keys(key)
    iv = convert_string_to_bitlist(iv)
    i = 0
    result = []
    while i < len(data):
        block = convert_string_to_bitlist(data[i:i + 8])
        if choice == ENCRYPT:
            block = list(map(lambda x, y: x ^ y, block, iv))
            block = des_cipher(block, choice)
            iv = block
        elif choice == DECRYPT:
            temp = block[:]
            block = des_cipher(block, choice)
            block = list(map(lambda x, y: x ^ y, block, iv))
            iv = temp
        result.append(convert_bitlist_to_string(block))
        i += 8
    return ''.join(result)

if __name__ == '__main__':
    key = '#qianfei'
    iv = '0' * 8
    data = '#qianfei11111111'
    ciphertext = cipher(data, key, iv, ENCRYPT)
    # print [ord(c) for c in ciphertext]
    print ciphertext
    plaintext = cipher(ciphertext, key, iv, DECRYPT)
    # print [ord(c) for c in plaintext]
    print plaintext
```

# 3DES

密码学中，三重数据加密算法（英语：Triple Data Encryption Algorithm，缩写为 TDEA，Triple DEA），或称 3DES（Triple DES），是一种对称密钥加密块密码，相当于是对每个数据块应用三次数据加密标准（DES）算法。由于计算机运算能力的增强，原版 DES 密码的密钥长度变得容易被暴力破解；3DES 即是设计用来提供一种相对简单的方法，即通过增加 DES 的密钥长度来避免类似的攻击，而不是设计一种全新的块密码算法。

## 算法流程

三重 DES 的本质上就是经过了三次 DES 操作，密钥长度为 24 字节，拆分为三个长为 8 字节的密钥，加密时依次对明文进行加密、解密、加密的操作，解密时相反。具体如下：

$$
Ciphertext = E_{K3}(D_{K2}(E_{K1}(Plaintext))) \\
Plaintext = D_{K1}(E_{K2}(D_{K3}(Ciphertext)))
$$

## 算法实现

```python
...

def triple_encipher(data, masterKey, iv):
    if len(masterKey) == 8:
        key1 = masterKey[:8]
        key2 = masterKey[:8]
        key3 = masterKey[:8]
    elif len(masterKey) == 16:
        key1 = masterKey[:8]
        key2 = masterKey[8:16]
        key3 = masterKey[:8]
    else:
        key1 = masterKey[:8]
        key2 = masterKey[8:16]
        key3 = masterKey[16:24]
    keys = [key1, key2, key3]
    # print keys
    i = 0
    result = []
    while i < len(data):
        block = cipher(data[i:i + 8], keys[0], iv, ENCRYPT)
        block = cipher(block, keys[1], iv, DECRYPT)
        block = cipher(block, keys[2], iv, ENCRYPT)
        iv = block
        result.append(block)
        i += 8
    return ''.join(result).encode('base64')

def triple_decipher(data, masterKey, iv):
    if len(masterKey) == 8:
        key1 = masterKey[:8]
        key2 = masterKey[:8]
        key3 = masterKey[:8]
    elif len(masterKey) == 16:
        key1 = masterKey[:8]
        key2 = masterKey[8:16]
        key3 = masterKey[:8]
    else:
        key1 = masterKey[:8]
        key2 = masterKey[8:16]
        key3 = masterKey[16:24]
    keys = [key1, key2, key3]
    # print keys
    i = 0
    result = []
    data = data.decode('base64')
    while i < len(data):
        temp = data[i:i + 8]
        block = cipher(data[i:i + 8], keys[2], iv, DECRYPT)
        block = cipher(block, keys[1], iv, ENCRYPT)
        block = cipher(block, keys[0], iv, DECRYPT)
        iv = temp
        result.append(block)
        i += 8
    return ''.join(result)

if __name__ == '__main__':
    key = '#qianfei'
    iv = '0' * 8
    data = '#qianfei11111111'
    ciphertext = triple_encipher(data, key, iv)
    # print [ord(c) for c in ciphertext]
    print ciphertext
    plaintext = triple_decipher(ciphertext, key, iv)
    # print [ord(c) for c in plaintext]
    print plaintext
```

# AES

高级加密标准（英语：Advanced Encryption Standard，缩写：AES），在密码学中又称 Rijndael 加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的 DES，已经被多方分析且广为全世界所使用。经过五年的甄选流程，高级加密标准由美国国家标准与技术研究院（NIST）于 2001 年 11 月 26 日发布于 FIPS PUB 197，并在 2002 年 5 月 26 日成为有效的标准。2006 年，高级加密标准已然成为对称密钥加密中最流行的算法之一。

## 算法流程

严格地说，AES 和 Rijndael 加密法并不完全一样（虽然在实际应用中两者可以互换），因为 Rijndael 加密法可以支持更大范围的区块和密钥长度：AES 的区块长度固定为 128 比特，密钥长度则可以是 128，192 或 256 比特；而 Rijndael 使用的密钥和区块长度均可以是 128，192 或 256 比特。加密过程中使用的密钥是由 Rijndael 密钥生成方案产生。

|   AES   | 密钥长度（32 位比特字) | 分组长度(32 位比特字) | 加密轮数 |
| :-----: | :--------------------: | :-------------------: | :------: |
| AES-128 |           4            |           4           |    10    |
| AES-192 |           6            |           4           |    12    |
| AES-256 |           8            |           4           |    14    |

大多数 AES 计算是在一个特别的有限域完成的。AES 加密过程是在一个 4×4 的字节矩阵上运作，这个矩阵又称为“体（state）”，其初值就是一个明文区块（矩阵中一个元素大小就是明文区块中的一个 Byte）。（Rijndael 加密法因支持更大的区块，其矩阵的“列数（Row number）”可视情况增加）加密时，各轮 AES 加密循环（除最后一轮外）均包含 4 个步骤：

- 轮密钥加：矩阵中的每一个字节都与该次回合密钥做 XOR 运算；每个子密钥由密钥生成方案产生。
- 字节代换：透过一个非线性的替换函数，用查找表的方式把每个字节替换成对应的字节。
- 行位移：将矩阵中的每个横列进行循环式移位。
- 列混合：为了充分混合矩阵中各个直行的操作。这个步骤使用线性转换来混合每内联的四个字节。最后一个加密循环中省略 MixColumns 步骤，而以另一个轮密钥取代。

### 轮密钥加

轮密钥加中，密钥将会与原矩阵合并。在每次的加密循环中，都会由主密钥产生一把回合密钥（透过 Rijndael 密钥生成方案产生），这把密钥大小会跟原矩阵一样，以与原矩阵中每个对应的字节作异或（⊕）加法。

![](/pics/Python实现DES、AES加密解密算法/4.png)

### 字节代换

在字节代换步骤中，矩阵中的各字节透过一个 8 位的 S-box 进行转换。这个步骤提供了加密法非线性的变换能力。S-box 与 $GF(2^{8})$ 上的乘法反元素有关，已知具有良好的非线性特性。为了避免简单代数性质的攻击，S-box 结合了乘法反元素及一个可逆的仿射变换矩阵建构而成。此外在建构 S-box 时，刻意避开了固定点与反固定点，即以 S-box 替换字节的结果会相当于错排的结果。

![](/pics/Python实现DES、AES加密解密算法/5.png)

### ShiftRows

行位移描述矩阵的列操作。在此步骤中，每一列都向左循环位移某个偏移量。在 AES 中（区块大小 128 位），第一列维持不变，第二列里的每个字节都向左循环移动一格。同理，第三列及第四列向左循环位移的偏移量就分别是 2 和 3。128 位和 192 比特的区块在此步骤的循环位移的模式相同。经过行位移之后，矩阵中每一竖行，都是由输入矩阵中的每个不同行中的元素组成。Rijndael 算法的版本中，偏移量和 AES 有少许不同；对于长度 256 比特的区块，第一列仍然维持不变，第二列、第三列、第四列的偏移量分别是 1 字节、2 字节、3 字节。除此之外，行位移操作步骤在 Rijndael 和 AES 中完全相同。

![](/pics/Python实现DES、AES加密解密算法/6.png)

### 列混合

在列混合步骤，每一行的四个字节透过线性变换互相结合。每一行的四个元素分别当作$1, x, x^2, x^3$ 的系数，合并即为 $GF(2^{8})$ 中的一个多项式，接着将此多项式和一个固定的多项式 $c(x)=3x^{3}+x^{2}+x+2$ 在模 $x^4+1$ 下相乘。此步骤亦可视为 Rijndael 有限域之下的矩阵乘法。列混合函数接受 4 个字节的输入，输出 4 个字节，每一个输入的字节都会对输出的四个字节造成影响。因此行位移和列混合两步骤为这个密码系统提供了扩散性。

![](/pics/Python实现DES、AES加密解密算法/7.png)

## 算法实现

这里实现了采用 CBC 模式且密钥长度为 128 位的 AES 算法：

```python
#!/usr/bin/env python
# -*- encoding=utf-8 -*-

ENCRYPT = 0
DECRYPT = 1
BLOCK_SIZE = 16

S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
S_ = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]

round_keys = [[0] * 4] * 44

def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def convert_string_to_matrix(string):
    matrix = []
    for i in range(16):
        byte = ord(string[i])
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i / 4].append(byte)
    return matrix

def convert_matrix_to_string(matrix):
    string = ''
    for i in range(4):
        for j in range(4):
            string += chr(matrix[i][j])
    return string

def generate_round_keys(master_key):
    round_keys[:4] = convert_string_to_matrix(master_key)
    # print round_keys
    for i in range(4, 4 * 11):
        temp = []
        if i % 4 == 0:
            # print round_keys[i - 4][0]
            # print round_keys[i - 1][0]
            # print Rcon[i/4]
            byte = round_keys[i - 4][0] ^ S[round_keys[i - 1][1]] ^ Rcon[i / 4]
            # print i, byte
            temp.append(byte)
            for j in range(1, 4):
                byte = round_keys[i - 4][j] ^ S[round_keys[i - 1][(j + 1) % 4]]
                # print byte
                temp.append(byte)
        else:
            for j in range(4):
                byte = round_keys[i - 4][j] ^ round_keys[i - 1][j]
                temp.append(byte)
        round_keys[i] = temp
    # print round_keys

def add_round_key(matrix, round_key):
    for i in range(4):
        for j in range(4):
            matrix[i][j] ^= round_key[i][j]
    return matrix

def sub_bytes(matrix, table):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = table[matrix[i][j]]
    return matrix

def shift_single_row(matrix, line, n):
    i = 0
    while i < n:
        temp = matrix[0][line]
        for j in range(3):
            matrix[j][line] = matrix[j + 1][line]
        matrix[3][line] = temp
        i += 1
    return matrix

def shift_rows(matrix, inversed=False):
    if inversed == True:
        matrix = shift_single_row(matrix, 1, 3)
        matrix = shift_single_row(matrix, 2, 2)
        matrix = shift_single_row(matrix, 3, 1)
    else:
        matrix = shift_single_row(matrix, 1, 1)
        matrix = shift_single_row(matrix, 2, 2)
        matrix = shift_single_row(matrix, 3, 3)
    return matrix

def mix_single_column(matrix):
    t = 0
    for i in range(4):
        t ^= matrix[i]
    # print 'x =>', t
    temp = matrix[0]
    for i in range(3):
        matrix[i] ^= t ^ xtime(matrix[i] ^ matrix[i + 1])
    matrix[3] ^= t ^ xtime(matrix[3] ^ temp)
    return matrix

def mix_columns(matrix, inversed=False):
    if inversed == True:
        for i in range(4):
            u = xtime(xtime(matrix[i][0] ^ matrix[i][2]))
            v = xtime(xtime(matrix[i][1] ^ matrix[i][3]))
            matrix[i][0] ^= u
            matrix[i][1] ^= v
            matrix[i][2] ^= u
            matrix[i][3] ^= v
        matrix = mix_columns(matrix)
    else:
        for i in range(4):
            # print 'm =>', matrix[i]
            matrix[i] = mix_single_column(matrix[i])
    return matrix

def aes_cipher(block, rounds, choice):
    if len(block) != 16:
        raise ValueError("Block\'s length must be 16.")
    matrix = convert_string_to_matrix(block)
    if choice == ENCRYPT:
        matrix = add_round_key(matrix, round_keys[:4])
        i = 1
        while i < rounds:
            matrix = sub_bytes(matrix, S)
            matrix = shift_rows(matrix)
            matrix = mix_columns(matrix)
            matrix = add_round_key(matrix, round_keys[4 * i:4 * i + 4])
            i += 1
        matrix = sub_bytes(matrix, S)
        matrix = shift_rows(matrix)
        matrix = add_round_key(matrix, round_keys[40:])
    elif choice == DECRYPT:
        matrix = add_round_key(matrix, round_keys[40:])
        matrix = shift_rows(matrix, inversed=True)
        matrix = sub_bytes(matrix, S_)
        i = rounds - 1
        while i > 0:
            matrix = add_round_key(matrix, round_keys[4 * i:4 * i + 4])
            matrix = mix_columns(matrix, inversed=True)
            matrix = shift_rows(matrix, inversed=True)
            matrix = sub_bytes(matrix, S_)
            i -= 1
        matrix = add_round_key(matrix, round_keys[:4])
    return convert_matrix_to_string(matrix)

def cipher(data, key, iv, rounds, choice):
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length illegal.")
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("key/iv\'s length should be 16.")
    generate_round_keys(key)
    i = 0
    result = []
    while i < len(data):
        block = data[i:i + 16]
        if choice == ENCRYPT:
            block = list(map(lambda x, y: ord(x) ^ ord(y), block, iv))
            block = ''.join([chr(c) for c in block])
            block = aes_cipher(block, rounds, choice)
            iv = block
        elif choice == DECRYPT:
            temp = block[:]
            block = aes_cipher(block, rounds, choice)
            block = list(map(lambda x, y: ord(x) ^ ord(y), block, iv))
            block = ''.join([chr(c) for c in block])
            iv = temp
        result.append(block)
        i += BLOCK_SIZE
    return ''.join(result)

if __name__ == '__main__':
    key = '#qianfei12345678'
    iv = '0' * 16
    ciphertext = cipher('#qianfei12345678', key, iv, 10, ENCRYPT)
    print ciphertext
    plaintext = cipher(ciphertext, key, iv, 10, DECRYPT)
    print plaintext
```

# References

https://en.wikipedia.org/wiki/Data_Encryption_Standard
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
https://blog.csdn.net/Apollon_krj/article/details/76124722
https://github.com/twhiteman/pyDes/blob/master/pyDes.py
https://en.wikipedia.org/wiki/Triple_DES
http://blog.niuhemoon.xyz/pages/2018/05/18/Python-Symmetric-encryption/
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
https://www.cxyxiaowu.com/3239.html
