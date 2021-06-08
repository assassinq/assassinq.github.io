---
title: C语言实现RC2、RC5、RC6加密解密算法
date: 2019-09-03 13:38:28
tags: [c, crypto]
---

RC 算法是由 Ron Rivest 发明的一系列对称密钥加密算法。虽然这一系列的算法名字相似，但实际上算法之间没有太大的关联。

<!-- more -->

# Intro

现在总共有六个 RC 系列的算法。其中 RC1 从来没有发布过，RC3 在开始使用前就被证明是不安全的。余下的都是现如今有所运用的算法。

1. RC2 是一个于 1987 年发布的 64 位分组加密算法。
2. RC4 是当今运用最广泛的序列密码。
3. RC5 是一个于 1994 年发布的 32/64/128 位分组加密算法。
4. RC6 是一个于 1997 年发布的基于 RC5 的 128 位分组加密算法，在当年 AES 的评选中曾是 AES 决赛算法。

了解过算法的基本知识后，下面是 RC2、RC5 以及 RC6 在 C 语言下的实现。

# [RC2](https://en.wikipedia.org/wiki/RC2)

RC2 是一种分组密码，和 DES 很像，它的输入和输出的长度都是 64 位，而密钥是可变的，长度范围是从 1 到 128 比特，目前使用的是 8 比特的密钥。RC2 被设计成能够在 16 位处理器上运行。在 IBM AT 上它能够比 DES 的加密速度快一倍（假设在完成密钥扩展的情况下）。

RC2 总共分为三个算法步骤。分别是密钥扩展、加密、解密。

![](/pics/C语言实现RC2、RC5、RC6加密解密算法/rc2.png)

## 密钥扩展算法

密钥扩展通过一个长度变化的密钥生成 64 个字数组。

```cpp
void rc2_keygen(unsigned short xkey[64], const unsigned char *key, unsigned len, unsigned bits)
{
    unsigned char x;
    unsigned i;
    /* 256-entry permutation table, probably derived somehow from pi */
    static const unsigned char PITABLE[256] = {0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D, 0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2, 0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32, 0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82, 0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC, 0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26, 0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03, 0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7, 0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A, 0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC, 0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39, 0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31, 0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9, 0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9, 0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E, 0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD};

    assert(len > 0 && len <= 128);
    assert(bits <= 1024);
    if (!bits)
        bits = 1024;

    memcpy(xkey, key, len);

    /* Phase 1: Expand input key to 128 bytes */
    // for i = T, T+1, ..., 127 do
    //     L[i] = PITABLE[L[i-1] + L[i-T]];
    if (len < 128)
    {
        i = 0;
        x = ((unsigned char *)xkey)[len - 1];
        do
        {
            x = PITABLE[(x + ((unsigned char *)xkey)[i++]) & 255];
            ((unsigned char *)xkey)[len++] = x;
        } while (len < 128);
    }

    /* Phase 2 - reduce effective key size to "bits" */
    // L[128-T8] = PITABLE[L[128-T8] & TM];
    len = (bits + 7) >> 3; // bits = T1, len = T8, T8 = (T1+7)/8;
    i = 128 - len;
    x = PITABLE[((unsigned char *)xkey)[i] & (255 >> (7 & -bits))]; // (255 >> (7 & -bits) = TM, TM = 255 MOD 2^(8 + T1 - 8*T8);
    ((unsigned char *)xkey)[i] = x;

    // for i = 127-T8, ..., 0 do
    //     L[i] = PITABLE[L[i+1] XOR L[i+T8]];
    while (i--)
    {
        x = PITABLE[x ^ ((unsigned char *)xkey)[i + len]];
        ((unsigned char *)xkey)[i] = x;
    }

    /* Phase 3 - copy to xkey in little-endian order */
    i = 63;
    do
    {
        xkey[i] = ((unsigned char *)xkey)[2 * i] +
                  (((unsigned char *)xkey)[2 * i + 1] << 8);
    } while (i--);
}
```

## 加密算法

加密操作将一组 64 比特的字存入 4 个字中再进行加密。

```cpp
void rc2_encrypt(unsigned short xkey[64], unsigned char *plain, unsigned char *cipher)
{
    // xkey = K, plain = R
    unsigned x76, x54, x32, x10, i;

    x76 = (plain[7] << 8) + plain[6];
    x54 = (plain[5] << 8) + plain[4];
    x32 = (plain[3] << 8) + plain[2];
    x10 = (plain[1] << 8) + plain[0];

    for (i = 0; i < 16; i++)
    {
        // R[i] = R[i] + K[j] + (R[i-1] & R[i-2]) + ((~R[i-1]) & R[i-3]);
        // j = j + 1;
        // R[i] = R[i] rol s[i];
        x10 += (x32 & ~x76) + (x54 & x76) + xkey[4 * i + 0];
        x10 = (x10 << 1) + (x10 >> 15 & 1);

        x32 += (x54 & ~x10) + (x76 & x10) + xkey[4 * i + 1];
        x32 = (x32 << 2) + (x32 >> 14 & 3);

        x54 += (x76 & ~x32) + (x10 & x32) + xkey[4 * i + 2];
        x54 = (x54 << 3) + (x54 >> 13 & 7);

        x76 += (x10 & ~x54) + (x32 & x54) + xkey[4 * i + 3];
        x76 = (x76 << 5) + (x76 >> 11 & 31);

        // R[i] = R[i] + K[R[i-1] & 63];
        if (i == 4 || i == 10)
        {
            x10 += xkey[x76 & 63];
            x32 += xkey[x10 & 63];
            x54 += xkey[x32 & 63];
            x76 += xkey[x54 & 63];
        }
    }

    cipher[0] = (unsigned char)x10;
    cipher[1] = (unsigned char)(x10 >> 8);
    cipher[2] = (unsigned char)x32;
    cipher[3] = (unsigned char)(x32 >> 8);
    cipher[4] = (unsigned char)x54;
    cipher[5] = (unsigned char)(x54 >> 8);
    cipher[6] = (unsigned char)x76;
    cipher[7] = (unsigned char)(x76 >> 8);
}
```

## 解密算法

解密操作即为加密操作的逆运算。

```cpp
void rc2_decrypt(unsigned short xkey[64], unsigned char *plain, unsigned char *cipher)
{
    unsigned x76, x54, x32, x10, i;

    x76 = (cipher[7] << 8) + cipher[6];
    x54 = (cipher[5] << 8) + cipher[4];
    x32 = (cipher[3] << 8) + cipher[2];
    x10 = (cipher[1] << 8) + cipher[0];

    i = 15;
    do
    {
        // R[i] = R[i] ror s[i];
        // R[i] = R[i] - K[j] - (R[i-1] & R[i-2]) - ((~R[i-1]) & R[i-3]);
        // j = j - 1;
        x76 &= 65535;
        x76 = (x76 << 11) + (x76 >> 5);
        x76 -= (x10 & ~x54) + (x32 & x54) + xkey[4 * i + 3];

        x54 &= 65535;
        x54 = (x54 << 13) + (x54 >> 3);
        x54 -= (x76 & ~x32) + (x10 & x32) + xkey[4 * i + 2];

        x32 &= 65535;
        x32 = (x32 << 14) + (x32 >> 2);
        x32 -= (x54 & ~x10) + (x76 & x10) + xkey[4 * i + 1];

        x10 &= 65535;
        x10 = (x10 << 15) + (x10 >> 1);
        x10 -= (x32 & ~x76) + (x54 & x76) + xkey[4 * i + 0];

        // R[i] = R[i] - K[R[i-1] & 63];
        if (i == 5 || i == 11)
        {
            x76 -= xkey[x54 & 63];
            x54 -= xkey[x32 & 63];
            x32 -= xkey[x10 & 63];
            x10 -= xkey[x76 & 63];
        }
    } while (i--);

    plain[0] = (unsigned char)x10;
    plain[1] = (unsigned char)(x10 >> 8);
    plain[2] = (unsigned char)x32;
    plain[3] = (unsigned char)(x32 >> 8);
    plain[4] = (unsigned char)x54;
    plain[5] = (unsigned char)(x54 >> 8);
    plain[6] = (unsigned char)x76;
    plain[7] = (unsigned char)(x76 >> 8);
}
```

# [RC5](https://en.wikipedia.org/wiki/RC5)

RC5 同样也是分组密码，它支持可变的分组大小(32、64 或 128 比特)，密钥长度（0 至 2040 位）和加密轮数（0 ～ 255）。RC5 中有几个参数，w 代表一个字的字节大小，RC5 是以一个字为单位来进行所有操作的；r 代表加密轮数；b 代表密钥的长度。RC5 常用的 w 通常为 16、32 和 64。下面实现的是 w 为 32 时的 RC5 算法。

RC5 和 RC2 类似，总共分为三个算法步骤。分别是密钥扩展、加密、解密。

![](/pics/C语言实现RC2、RC5、RC6加密解密算法/rc5.png)

算法中需要一些宏定义：

```cpp
typedef unsigned int WORD;           /* Should be 32-bit = 4 bytes        */
#define w 32                         /* word size in bits                 */
#define r 12                         /* number of rounds                  */
#define b 16                         /* number of bytes in key            */
#define c 4                          /* number words in key               */
#define t 26                         /* size of table S = 2*(r+1) words   */
WORD S[t];                           /* expanded key table                */
WORD P = 0xb7e15163, Q = 0x9e3779b9; /* magic constants                   */
/* Rotation operators. x must be unsigned, to get logical right shift     */
#define ROTL(x, y) (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
#define ROTR(x, y) (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))
```

## 密钥扩展算法

密钥扩展首先分别初始化 L 数组和 S 盒，随后通过 L 进行按字异或得到 S 盒。

```cpp
void rc5_keygen(unsigned char *K) /* secret input ket K[0...b-1] */
{
    WORD i, j, k, u = w / 8, A, B, L[c];
    /* Initialize L, then S, then mix key into S */
    for (i = b - 1, L[c - 1] = 0; i != -1; i--)
    {
        L[i / u] = (L[i / u] << 8) + K[i];
    }
    for (S[0] = P, i = 1; i < t; i++)
    {
        S[i] = S[i - 1] + Q;
    }
    for (A = B = i = j = k = 0; k < 3 * t; k++, i = (i + 1) % t, j = (j + 1) % c) /* 3*t > 3*c */
    {
        A = S[i] = ROTL(S[i] + (A + B), 3);
        B = L[j] = ROTL(L[j] + (A + B), (A + B));
    }
}
```

## 加密算法

加密涉及的一个简单轮函数的加密。基于安全需要和时间方面的考虑，建议 12 或 20 轮加密。

```cpp
void rc5_encrypt(unsigned char *plain, unsigned char *cipher) /* 2 WORD input pt/output ct */
{
    WORD pt[2], ct[2];
    for (int i = 0; i < 2; i++)
    {
        pt[i] = plain[4 * i] + (plain[4 * i + 1] << 8) + (plain[4 * i + 2] << 16) + (plain[4 * i + 3] << 24);
    }

    WORD A = pt[0] + S[0], B = pt[1] + S[1];
    for (int i = 1; i <= r; i++)
    {
        A = ROTL(A ^ B, B) + S[2 * i];
        B = ROTL(B ^ A, A) + S[2 * i + 1];
    }
    ct[0] = A;
    ct[1] = B;
    for (int i = 0; i < 2; i++)
    {
        cipher[4 * i] = ct[i] & 0xFF;
        cipher[4 * i + 1] = (ct[i] >> 8) & 0xFF;
        cipher[4 * i + 2] = (ct[i] >> 16) & 0xFF;
        cipher[4 * i + 3] = (ct[i] >> 24) & 0xFF;
    }
}
```

## 解密算法

解密实际上就是加密过程的逆运算。

```cpp
void rc5_decrypt(unsigned char *cipher, unsigned char *plain) /* 2 WORD input ct/output pt */
{
    WORD pt[2], ct[2];
    for (int i = 0; i < 2; i++)
    {
        ct[i] = cipher[4 * i] + (cipher[4 * i + 1] << 8) + (cipher[4 * i + 2] << 16) + (cipher[4 * i + 3] << 24);
    }
    WORD B = ct[1], A = ct[0];
    for (int i = r; i > 0; i--)
    {
        B = ROTR(B - S[2 * i + 1], A) ^ A;
        A = ROTR(A - S[2 * i], B) ^ B;
    }
    pt[1] = B - S[1];
    pt[0] = A - S[0];
    for (int i = 0; i < 2; i++)
    {
        plain[4 * i] = pt[i] & 0xFF;
        plain[4 * i + 1] = (pt[i] >> 8) & 0xFF;
        plain[4 * i + 2] = (pt[i] >> 16) & 0xFF;
        plain[4 * i + 3] = (pt[i] >> 24) & 0xFF;
    }
}
```

# [RC6](https://en.wikipedia.org/wiki/RC6)

RC6 是一个从 RC5 派生而来的对称分组加密算法，用以满足高级加密标准（AES）竞赛的要求。RC6 拥有 128 位的块大小，支持 128、192、256 位乃至 2040 位的密钥长度。像 RC5 一样，RC6 是可以被参数化的。它也因而支持变长的分组大小、密钥长度以及加密轮数。RC6 和 RC5 在结构、使用基于数据的置换规则、取模加法以及异或操作等很多方面都很相似。事实上，RC6 可以被看做是交织的两组平行的 RC5 加密。其中，RC6 使用了乘法运算，能够让置换基于字中每一位，而不是其中的几位。

![](/pics/C语言实现RC2、RC5、RC6加密解密算法/rc6.jpeg)

算法中需要一些宏定义：

```cpp
typedef unsigned int WORD;           /* Should be 32-bit = 4 bytes        */
#define w 32                         /* word size in bits                 */
#define r 20                         /* based on security estimates       */
#define bytes (w / 8)                /* bytes per word                    */
#define c ((b + bytes - 1) / bytes)  /* key in words, rounded up          */
#define R24 (2 * r + 4)              /* length of array S                 */
#define lgw 5                        /* log2(w) -- wussed out             */
WORD S[R24 - 1];                     /* Key schedule                      */
WORD P = 0xb7e15163, Q = 0x9e3779b9; /* magic constants                   */
/* Rotation operators. x must be unsigned, to get logical right shift     */
#define ROTL(x, y) (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
#define ROTR(x, y) (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))
```

## 密钥扩展算法

RC6 中接受的密钥长度相比于 RC5 更长，生成的 S 盒大小为 2r+4。

```cpp
void rc6_keygen(unsigned char *K, int b)
{
    int i, j, s, v;
    WORD L[(32 + bytes - 1) / bytes]; /* Big enough for max b */
    WORD A, B;

    L[c - 1] = 0;
    for (i = b - 1; i >= 0; i--)
        L[i / bytes] = (L[i / bytes] << 8) + K[i];

    S[0] = P;
    for (i = 1; i <= 2 * r + 3; i++)
        S[i] = S[i - 1] + Q;

    A = B = i = j = 0;
    v = R24;
    if (c > v)
        v = c;
    v *= 3;

    for (s = 1; s <= v; s++)
    {
        A = S[i] = ROTL(S[i] + A + B, 3);
        B = L[j] = ROTL(L[j] + A + B, A + B);
        i = (i + 1) % R24;
        j = (j + 1) % c;
    }
}
```

## 加密算法

RC6 加密时比 RC5 多了乘法运算，加密过程也变得更复杂。

```cpp
void rc6_encrypt(unsigned char *plain, unsigned char *cipher)
{
    WORD pt[4], ct[4];
    for (int i = 0; i < 4; i++)
    {
        pt[i] = plain[4 * i] + (plain[4 * i + 1] << 8) + (plain[4 * i + 2] << 16) + (plain[4 * i + 3] << 24);
    }

    WORD A, B, C, D, t, u, x;

    A = pt[0];
    B = pt[1];
    C = pt[2];
    D = pt[3];
    B += S[0];
    D += S[1];
    for (int i = 2; i <= 2 * r; i += 2)
    {
        t = ROTL(B * (2 * B + 1), lgw);
        u = ROTL(D * (2 * D + 1), lgw);
        A = ROTL(A ^ t, u) + S[i];
        C = ROTL(C ^ u, t) + S[i + 1];
        x = A;
        A = B;
        B = C;
        C = D;
        D = x;
    }
    A += S[2 * r + 2];
    C += S[2 * r + 3];
    ct[0] = A;
    ct[1] = B;
    ct[2] = C;
    ct[3] = D;

    for (int i = 0; i < 4; i++)
    {
        cipher[4 * i] = ct[i] & 0xFF;
        cipher[4 * i + 1] = (ct[i] >> 8) & 0xFF;
        cipher[4 * i + 2] = (ct[i] >> 16) & 0xFF;
        cipher[4 * i + 3] = (ct[i] >> 24) & 0xFF;
    }
}
```

## 解密算法

解密过程同样是加密过程的逆运算。

```cpp
void rc6_decrypt(unsigned char *cipher, unsigned char *plain)
{
    WORD pt[4], ct[4];
    for (int i = 0; i < 4; i++)
    {
        ct[i] = cipher[4 * i] + (cipher[4 * i + 1] << 8) + (cipher[4 * i + 2] << 16) + (cipher[4 * i + 3] << 24);
    }

    WORD A, B, C, D, t, u, x;

    A = ct[0];
    B = ct[1];
    C = ct[2];
    D = ct[3];
    C -= S[2 * r + 3];
    A -= S[2 * r + 2];
    for (int i = 2 * r; i >= 2; i -= 2)
    {
        x = D;
        D = C;
        C = B;
        B = A;
        A = x;
        u = ROTL(D * (2 * D + 1), lgw);
        t = ROTL(B * (2 * B + 1), lgw);
        C = ROTR(C - S[i + 1], t) ^ u;
        A = ROTR(A - S[i], u) ^ t;
    }
    D -= S[1];
    B -= S[0];
    pt[0] = A;
    pt[1] = B;
    pt[2] = C;
    pt[3] = D;

    for (int i = 0; i < 4; i++)
    {
        plain[4 * i] = pt[i] & 0xFF;
        plain[4 * i + 1] = (pt[i] >> 8) & 0xFF;
        plain[4 * i + 2] = (pt[i] >> 16) & 0xFF;
        plain[4 * i + 3] = (pt[i] >> 24) & 0xFF;
    }
}
```

# References

[RC_algorithm](https://en.wikipedia.org/wiki/RC_algorithm)
[A Comparative Study of Rivest Cipher Algorithms](https://www.ripublication.com/irph/ijict_spl/ijictv4n17spl_13.pdf)
[现代密码学教程](http://113.209.194.153/ds_pdf/13711077.pdf)
[A Description of the RC2(r) Encryption Algorithm](https://tools.ietf.org/pdf/rfc2268.pdf)
[The RC5 Encryption Algorithm](http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf)
[The RC6 Block Cipher](http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf)
