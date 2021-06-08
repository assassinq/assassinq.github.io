---
title: Python实现TEA、XTEA、XXTEA加密解密算法
date: 2019-08-22 17:00:10
tags: [python, crypto]
---

闲来无事，喝杯茶冷静一下。

<!-- more -->

# [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm)

微型加密算法（`Tiny Encryption Algorithm`，`TEA`）是一种易于描述和执行的块密码，通常只需要很少的代码就可实现。`TEA` 操作处理在两个 `32` 位无符号整型上（可能源于一个 `64` 位数据），并且使用一个 `128` 位的密钥。设计者是 `Roger Needham` 和 `David Wheeler`。

加密过程：

![](/pics/Python实现TEA、XTEA、XXTEA加密解密算法/1.png)

Python 实现：

```python
#!/usr/bin/env python

def encrypt(v, k):
	v0 = v[0]
	v1 = v[1]
	x = 0
	delta = 0x9E3779B9
	k0 = k[0]
	k1 = k[1]
	k2 = k[2]
	k3 = k[3]
	for i in range(32):
		x += delta
		x = x & 0xFFFFFFFF
		v0 += ((v1 << 4) + k0) ^ (v1 + x) ^ ((v1 >> 5) + k1)
		v0 = v0 & 0xFFFFFFFF
		v1 += ((v0 << 4) + k2) ^ (v0 + x) ^ ((v0 >> 5) + k3)
		v1 = v1 & 0xFFFFFFFF
	v[0] = v0
	v[1] = v1
	return v

def decrypt(v, k):
	v0 = v[0]
	v1 = v[1]
	x = 0xC6EF3720
	delta = 0x9E3779B9
	k0 = k[0]
	k1 = k[1]
	k2 = k[2]
	k3 = k[3]
	for i in range(32):
		v1 -= ((v0 << 4) + k2) ^ (v0 + x) ^ ((v0 >> 5) + k3)
		v1 = v1 & 0xFFFFFFFF
		v0 -= ((v1 << 4) + k0) ^ (v1 + x) ^ ((v1 >> 5) + k1)
		v0 = v0 & 0xFFFFFFFF
		x -= delta
		x = x & 0xFFFFFFFF
	v[0] = v0
	v[1] = v1
	return v


if __name__ == '__main__':
	plain = [1, 2]
	key = [2, 2, 3, 4]
	encrypted = encrypt(plain, key)
	print encrypted
	decrypted = decrypt(encrypted, key)
	print decrypted
```

# [XTEA](https://en.wikipedia.org/wiki/XTEA)

`XTEA` 是 `TEA` 的升级版，增加了更多的密钥表，移位和异或操作等等。

加密过程：

![](/pics/Python实现TEA、XTEA、XXTEA加密解密算法/2.png)

Python 实现：

```python
#!/usr/bin/env python

def encrypt(rounds, v, k):
	v0 = v[0]
	v1 = v[1]
	x = 0
	delta = 0x9E3779B9
	for i in range(rounds):
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (x + k[x & 3])
		v0 = v0 & 0xFFFFFFFF
		x += delta
		x = x & 0xFFFFFFFF
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (x + k[(x >> 11) & 3])
		v1 = v1 & 0xFFFFFFFF
	v[0] = v0
	v[1] = v1
	return v

def decrypt(rounds, v, k):
	v0 = v[0]
	v1 = v[1]
	delta = 0x9E3779B9
	x = delta * rounds
	for i in range(rounds):
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (x + k[(x >> 11) & 3])
		v1 = v1 & 0xFFFFFFFF
		x -= delta
		x = x & 0xFFFFFFFF
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (x + k[x & 3])
		v0 = v0 & 0xFFFFFFFF
	v[0] = v0
	v[1] = v1
	return v

if __name__ == '__main__':
	plain = [1, 2]
	key = [2, 2, 3, 4]
	rounds = 32
	encrypted = encrypt(rounds, plain, key)
	print encrypted
	decrypted = decrypt(rounds, encrypted, key)
	print decrypted
```

# [XXTEA](https://en.wikipedia.org/wiki/XXTEA)

`XXTEA`，又称 `Corrected Block TEA`，是 `XTEA` 的升级版。

加密过程：

![](/pics/Python实现TEA、XTEA、XXTEA加密解密算法/3.png)

Python 实现：

```python
#!/usr/bin/env python

def shift(z, y, x, k, p, e):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((x ^ y) + (k[(p & 3) ^ e] ^ z)))

def encrypt(v, k):
    delta = 0x9E3779B9
    n = len(v)
    rounds = 6 + 52 / n
    x = 0
    z = v[n - 1]
    for i in range(rounds):
        x = (x + delta) & 0xFFFFFFFF
        e = (x >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + shift(z, y, x, k, p, e)) & 0xFFFFFFFF
            z = v[p]
        p += 1
        y = v[0]
        v[n - 1] = (v[n - 1] + shift(z, y, x, k, p, e)) & 0xFFFFFFFF
        z = v[n - 1]
    return v

def decrypt(v, k):
    delta = 0x9E3779B9
    n = len(v)
    rounds = 6 + 52 / n
    x = (rounds * delta) & 0xFFFFFFFF
    y = v[0]
    for i in range(rounds):
        e = (x >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - shift(z, y, x, k, p, e)) & 0xFFFFFFFF
            y = v[p]
        p -= 1
        z = v[n - 1]
        v[0] = (v[0] - shift(z, y, x, k, p, e)) & 0xFFFFFFFF
        y = v[0]
        x = (x - delta) & 0xFFFFFFFF
    return v

if __name__ == '__main__':
    plain = [1, 2]
    key = [2, 2, 3, 4]
    encrypted = encrypt(plain, key)
    print encrypted
    decrypted = decrypt(encrypted, key)
    print decrypted
```

# References

https://blog.csdn.net/gsls200808/article/details/48243019
