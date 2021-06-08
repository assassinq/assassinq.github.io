---
title: Python实现Paillier加密解密算法
date: 2019-10-24 11:49:26
tags: [python, crypto]
---

Paillier 加密系统，是 1999 年 Paillier 发明的概率公钥加密系统。基于复合剩余类的困难问题。该加密算法是一种同态加密，满足加法和数乘同态。

<!-- more -->

# Introduction

## Keygen

首先选择两个大素数 $p$ 和 $q$，计算出 $n$ 为 $p$ 和 $q$ 的乘积。并取一个随机数 $g$（通常取 $n+1$）。$n$ 和 $g$ 作为公钥。

然后根据卡迈克尔函数计算私钥 $\lambda$ 为 $p-1$ 和 $q-1$ 的乘积。

## Encipher

加密时取一个随机数 $r$，计算出 $c \equiv g^m r^n(mod\ n^2)$。

## Decipher

解密有一点复杂。首先我们可以得到：

$$
c^\lambda \equiv (g^m r^n)^\lambda \equiv g^{m \lambda} r^{n \lambda}(mod\ n^2)
$$

根据卡迈克尔函数，即对于任何 $\omega \in Z^*_{n^2}$，必定存在以下结论：

$$
\omega^{n \lambda} \equiv 1(mod\ n^2)
$$

那么可以得到 $c^\lambda \equiv g^{m \lambda}(mod\ n^2)$。

然后看看生成元 $g$，实际上是通过 $g=(1+\alpha n)\beta^n$ 得到的，并且 $\alpha,\beta \in Z^*_n$。由此可得：

$$
c^\lambda \equiv (1+\alpha n)^{m \lambda}\beta^{n m \lambda} \equiv (1+\alpha n)^{m \lambda}(mod\ n^2)
$$

再根据公式 $(1+n)^x \equiv 1+xn(mod\ n^2)$，可以得到：

$$
c^\lambda \equiv (1+n)^{\alpha m \lambda} \equiv 1+n \alpha m \lambda(mod\ n^2)
$$

然后我们在此处定义一个函数 $L(x)=\frac{x-1}{n}$，则 $L(c^\lambda)=\alpha m \lambda$。

那么我们可以得到明文的计算公式为 $m \equiv \frac{L(c^\lambda)}{L(g^\lambda)} \equiv \frac{\alpha m \lambda}{\alpha \lambda} \equiv m(mod\ n)$。

# Getting started

通过 gmpy2 和 libnum 库实现。

```python
#!/usr/bin/env python
import gmpy2
import random
import time
import libnum

def get_prime(rs):
    p = gmpy2.mpz_urandomb(rs, 1024)
    while not gmpy2.is_prime(p):
        p = p + 1
    return p

def L(x, n):
    return (x - 1) / n

def keygen():
    rs = gmpy2.random_state(int(time.time()))
    p = get_prime(rs)
    q = get_prime(rs)
    n = p * q
    lmd = (p - 1) * (q - 1)
    #g = random.randint(1, n ** 2)
    g = n + 1
    if gmpy2.gcd(L(gmpy2.powmod(g, lmd, n ** 2), n), n) != 1:
        print '[!] g is not good enough'
        exit()
    pk = [n, g]
    sk = lmd
    return pk, sk

def encipher(plaintext, pk):
    m = libnum.s2n(plaintext)
    n, g = pk
    r = random.randint(1, n ** 2)
    c = gmpy2.powmod(g, m, n ** 2) * gmpy2.powmod(r, n, n ** 2) % (n ** 2)
    return c

def decipher(c, pk, sk):
    [n, g] = pk
    lmd = sk
    u = gmpy2.invert(L(gmpy2.powmod(g, lmd, n ** 2), n), n) % n
    m = L(gmpy2.powmod(c, lmd, n ** 2), n) * u % n
    plaintext = libnum.n2s(m)
    return plaintext

if __name__ == '__main__':
    pk, sk = keygen()
    #print 'pk:', pk
    #print 'sk:', sk
    plaintext = raw_input('Please input your message: ')
    ciphertext = encipher(plaintext, pk)
    print 'Ciphertext:', ciphertext
    plaintext = decipher(ciphertext, pk, sk)
    print 'Plaintext:', plaintext
```

# References

[The Paillier Cryptosystem](http://security.hsr.ch/msevote/docs/Paillier_Cryptosystem.pdf)
[卡迈克尔函数](https://zh.wikipedia.org/wiki/%E5%8D%A1%E9%82%81%E5%85%8B%E7%88%BE%E5%87%BD%E6%95%B8)
