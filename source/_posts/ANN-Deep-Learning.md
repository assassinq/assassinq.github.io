---
title: ANN & Deep Learning
date: 2020-07-13 08:18:55
tags: [ann, dl]
---

人工神经网络和深度学习入门。

<!-- more -->

# Artificial Neural Network

人工神经网络（英语：Artificial Neural Network，ANN），简称神经网络（Neural Network，NN）或类神经网络，在机器学习和认知科学领域，是一种模仿生物神经网络（动物的中枢神经系统，特别是大脑）的结构和功能的数学模型或计算模型，用于对函数进行估计或近似。

## History of ANN

1943 年，心理学家 W.S.McCulloch 和数理逻辑学家 W.Pitts 基于神经元的生理特征，建立了单个神经元的数学模型（MP 模型）。

![](/pics/ANN-Deep-Learning/1.png)

对应的数学模型：

$$
y_k=\phi(\sum_{i=1}^m\omega_{ki}x_i+b_k)=\phi(\omega_k^Tx+b)
$$

## 感知器算法（Perceptron Algorithm）

1957 年，Frank Rosenblatt 从纯数学的角度重新考察这一模型，指出能够从一些输入输出对 $(x,y)$ 中通过学习算法获得权重 $\omega$ 和 $b$。输入 $\\{(x_i,y_i)\\}_{i=1\sim N}$：

1. 随机选择 $\omega$ 和 $b$；
2. 循环：取一个训练样本 $(x,y)$；
   1. 若 $\omega^T+b>0$ 且 $y=-1$，则：$\omega=\omega-x$、$b=b-1$；
   2. 若 $\omega^T+b<0$ 且 $y=+1$，则：$\omega=\omega+x$、$b=b+1$。
3. 终止条件：直到所有输入输出都不满足 2 中的两个条件之一，退出循环。

$$
\begin{array}{l}
\omega_{新}^Tx+b_{新}=(\omega-x)^Tx+(b-1)\\\
=(\omega^T+b)-(\lVert x\rVert^2+1)\\\
≤(\omega^T+b)-1
\end{array}
$$

证明：

- 定义一个增广向量 $\vec{x}$；
  1. 若 $y=+1$，则 $\vec{x}=\begin{bmatrix}x\\\ 1\end{bmatrix}$；
  2. 若 $y=-1$，则 $\vec{x}=\begin{bmatrix}-x\\\ -1\end{bmatrix}$。
- 定义增广 $\omega=\begin{bmatrix}\omega\\\ b\end{bmatrix}$。感知器算法定义可简化为输入 $\vec{x_i}$：
  1. 随机取 $\omega$；
  2. 循环：取一个 $\vec{x_i}$，若 $\omega^T\vec{x_i}<0$，则 $\omega=\omega+\vec{x_i}$；
  3. 终止条件：直到所有输入输出都不满足 2 中的条件，退出循环。

### 感知器算法的收敛定理

输入 $\\{\vec{x_i}\\}\_{i=1\sim N}$，若线性可分，即存在 $\omega_{opt}$，使：$\omega_{opt}^T\vec{x_i}>0(i=1\sim N)$，则利用上述感知器算法，经过有限步后，得到一个 $\omega$，使 $\omega^T\vec{x_i}>0(i=1\sim N)$。（$\omega$ 和 $\omega_{opt}$ 存在很小的概率相等）

证：不失一般性，设 $\lVert\omega_{opt}\rVert=1$（因为 $\omega_{opt}$ 与 $a\omega_{opt}(a>0)$ 是同一平面）。假设第 $k$ 步的 $\omega$ 是 $\omega(k)$，且有一个 $\vec{x_i}$，使 $\omega(k)^T\vec{x_i}<0$，根据感知器算法：

$$
\begin{array}{l}
\omega(k+1)=\omega(k)+\vec{x_i}\\\
\omega(k+1)-a\omega_{opt}=\omega(k)+\vec{x_i}-a\omega_{opt}\\\
\lVert\omega(k+1)-a\omega_{opt}\rVert^2=\lVert\omega(k)+\vec{x_i}-a\omega_{opt}\rVert^2\\\
=\lVert\omega(k)-a\omega_{opt}+\vec{x_i}\rVert^2\\\
=\lVert\omega(k)-a\omega_{opt}\rVert^2+\lVert\vec{x_i}\rVert^2+2\omega(k)^T\vec{x_i}-2a\omega_{opt}^T\vec{x_i}
\end{array}
$$

一定可以取到很大的 $a$，使 $\lVert\omega(k+1)-a\omega_{opt}\rVert^2<\lVert\omega(k)-a\omega_{opt}\rVert^2$。

定义：$\beta=\max_{i\sim N}\\{\lVert\vec{x_i}\rVert\\}$、$\gamma=\min_{i=1\sim N}(\omega_{opt}^Tx_i)$，取 $a=\frac{\beta^2+1}{2\gamma}$，则 $\lVert\omega(k+1)-a\omega_{opt}\rVert^2<\lVert\omega(k)-a\omega_{opt}\rVert^2-1$。

取 $D=\lVert\omega(0)-a\omega_{opt}\rVert$，则至多经过 $D^2$ 步，$\omega$ 将会收敛至 $a\omega_{opt}$。

$$
\begin{array}{l}
D^2=\lVert\omega(0)-a\omega_{opt}\rVert^2\\\
=\lVert\omega(0)\rVert^2+a^2\lVert\omega_{opt}\rVert^2-2a\omega(0)^T\omega_{opt}\\\
=\lVert\omega(0)\rVert^2+a^2\lVert\omega_{opt}\rVert^2-2a\lVert\omega(0)\rVert\lVert\omega_{opt}\rVert\cos\theta\\\
≤\lVert\omega(0)\rVert^2+a^2+2a\lVert\omega(0)\rVert
\end{array}
$$

## 人工智能的第一次冬天

Minsky 创造了线性可分（不可分）的概念（1969，《Perceptron》），提出日常生活中很多分类问题都是非线性可分的。

例：识别一个二值图像是否全连通。

## 多层神经网络（Multiple-layer Neural Network）

多层神经网络（多层前馈神经网络，Multi-layer Feedforward Neural Network）的出现让解决非线性可分的问题成为可能。

### 二层神经网络

给出输入数据 $x=\begin{bmatrix}x_1\\\ x_2\end{bmatrix}$，有二层神经网络如下：

![](/pics/ANN-Deep-Learning/2.png)

其中 $\phi(\cdot)$ 是一个非线性函数。

$$
\begin{cases}
a_1=\omega_{11}x_1+\omega_{12}x_2+b_1\\\
a_2=\omega_{21}x_1+\omega_{22}x_x+b_2\\\
z_1=\phi(a_1)\\\
z_2=\phi(a_2)\\\
y=\omega_1z_1+\omega_2z_2+b
\end{cases}
$$

即 $y=\omega_1\phi(\omega_{11}x_1+\omega_{12}x_2+b_1)+\omega_2\phi(\omega_{21}x_1+\omega_{22}x_2+b_2)+b$。若 $\phi(\cdot)$ 不做映射，可以证明与单个神经元模型完全相同：

$$
\begin{array}{l}
y=\omega_1(\omega_{11}x_1+\omega_{12}x_2+b_1)+\omega_2(\omega_{21}x_1+\omega_{22}x_2+b_2)+b\\\
=(\omega_1\omega_{11}+\omega_2\omega_{21})x_1+(\omega_1\omega_{12}+\omega_2\omega_{22})x_2+(\omega_1b_1+\omega_2b_2+b)
\end{array}
$$

故必须包含非线性函数 $\phi(\cdot)$，才能构成一个非线性问题。非线性函数 $\phi(x)$ 一般取阶跃函数或 Sigmoid 函数：

![](/pics/ANN-Deep-Learning/3.png)

阶跃函数可以被证明能够处理所有非线性问题。

### 三层神经网络

定理：三层神经网络可以模拟所有决策面。假设有以下非线性问题，灰色部分设为 $C_1$，其他部分设为 $C_2$：

![](/pics/ANN-Deep-Learning/4.png)

根据二层神经网络，构造如下三层神经网络：

![](/pics/ANN-Deep-Learning/5.png)

## 后向传播算法（Back Propagation，误差逆传播）

针对上面的的二层神经网络，进行梯度下降法求局部极值（Gradient Descent Method）：

1. 找一个 $\omega_0$；
2. 设 $k=0$，假设 $\frac{d f(\omega)}{d\omega}\vert_{\omega_k}=0$，退出。否则，$\omega_{k+1}=\omega_k-\alpha\frac{d f(\omega)}{d\omega}\vert_{\omega_k}$，其中 $\alpha>0$ 是学习率。

$$
\begin{array}{l}
f(\omega+\Delta\omega)=f(\omega)+\frac{d f(\omega)}{d\omega}\vert_\omega\cdot\Delta\omega+o(\Delta\omega)\\\
f(\omega_{k+1})=f(\omega_k)+(\frac{d f(\omega)}{d\omega}\vert_{\omega_k})\cdot(-\alpha\frac{d f(\omega)}{d\omega}\vert_{\omega_k})\\\
=f(\omega_k)-\alpha[\frac{d f(\omega)}{d\omega}\vert_{\omega_k}]^2+o(\Delta\omega)≤f(\omega_k)
\end{array}
$$

输入 $\\{(x_i,Y_i)\\}_{i=1\sim N}$。针对输入 $(X,Y)$，有 $E=\frac{1}{2}(y-Y)^2$（MSE，Mean Score Error）。推导过程：

1. 随机取变量（$\omega_{11}$、$\omega_{12}$、$\omega_{21}$、$\omega_{22}$、$b_1$、$b_2$、$\omega_1$、$\omega_2$、$b$）；
2. 对所有的 $\omega$，求 $\frac{\partial E}{\partial\omega}$；对所有的 $b$，求 $\frac{\partial E}{\partial b}$；
3. 有 $\omega^{(新)}=\omega^{(旧)}-\alpha\frac{\partial E}{\partial\omega}\vert_{\omega^{(旧)}}$，$b^{(新)}=b^{(旧)}-\alpha\frac{\partial E}{\partial b}\vert_{b^{(旧)}}$；
4. 当所有 $\frac{\partial E}{\partial\omega}$ 与 $\frac{\partial E}{\partial b}$ 都为 0 时，退出。

根据上面的式子计算所有偏导数的过程：

$$
\begin{array}{l}
\frac{dE}{dy}=(y-Y)\\\
\frac{\partial E}{\partial a_1}=\frac{dE}{dy}\frac{\partial y}{\partial z_1}\frac{dz_1}{da_1}=(y-Y)\omega_1\phi'(a_1)\\\
\frac{\partial E}{\partial a_2}=\frac{dE}{dy}\frac{\partial y}{\partial z_2}\frac{dz_2}{da_2}=(y-Y)\omega_2\phi'(a_2)\\\
\frac{\partial E}{\partial b}=\frac{dE}{dy}\frac{\partial y}{\partial b}=(y-Y)\\\
\frac{\partial E}{\partial\omega_1}=\frac{dE}{dy}\frac{\partial y}{\partial\omega_1}=(y-Y)z_1\\\
\frac{\partial E}{\partial\omega_2}=\frac{dE}{dy}\frac{\partial y}{\partial\omega_2}=(y-Y)z_2\\\
\frac{\partial E}{\partial\omega_{11}}=\frac{\partial E}{\partial a_1}\frac{\partial a_1}{\partial\omega_{11}}=(y-Y)\omega_1\phi'(a_1)x_1\\\
\frac{\partial E}{\partial\omega_{12}}=\frac{\partial E}{\partial a_1}\frac{\partial a_1}{\partial\omega_{12}}=(y-Y)\omega_1\phi'(a_1)x_2\\\
\frac{\partial E}{\partial b_1}=\frac{\partial E}{\partial a_1}\frac{\partial a_1}{\partial b_1}=(y-Y)\omega_1\phi'(a_1)\\\
\frac{\partial E}{\partial\omega_{21}}=\frac{\partial E}{\partial a_2}\frac{\partial a_2}{\partial\omega_{21}}=(y-Y)\omega_1\phi'(a_2)x_1\\\
\frac{\partial E}{\partial\omega_{22}}=\frac{\partial E}{\partial a_2}\frac{\partial a_2}{\partial\omega_{22}}=(y-Y)\omega_1\phi'(a_2)x_2\\\
\frac{\partial E}{\partial b_2}=\frac{\partial E}{\partial a_2}\frac{\partial a_2}{\partial b_2}=(y-Y)\omega_2\phi'(a_2)
\end{array}
$$

$\phi(x)$ 不能取阶跃函数，因为阶跃函数中除了 $x=0$ 时，其他地方 $\phi'(x)=0$，导致不能进行后向传播。BP 神经网络中通常采用如下的函数：

- Sigmoid 函数：$\phi(x)=\frac{1}{1+e^{-x}}$；
  - $\phi'(x)=\phi(x)[1-\phi(x)]$。
- 双曲正切函数：$\phi(x)=\tanh(x)=\frac{e^x-e^{-x}}{e^x+e^{-x}}$；
  - $\phi'(x)=1-[\phi(x)]^2$。
- 线性整流函数（Rectified Linear Units）：$\phi(x)=ReLu(x)=\begin{cases}x,x>0\\\ 0,x≤0\end{cases}=\max(0,x)$；
  - $\phi'(x)=\begin{cases}1,x>0\\\ 0,x≤0\end{cases}$。
- 带泄漏的线性整流函数（Leak ReLu）：$\phi(x)=\begin{cases}x,x>0\\\ \beta x,x≤0\end{cases}$。
  - $\phi'(x)=\begin{cases}1,x>0\\\ \beta,x≤0\end{cases}$。

### Summary

将 BP 算法放在一个更具有普适性的情况下实现。定义：

1. 网络共 $l$ 层；
2. $z^{(k)}$、$a^{(k)}$、$b^{(k)}$ 是第 $k$ 层的向量，与第 $k$ 层神经元个数一致；
3. $z_i^{(k)}$、$a_i^{(k)}$、$b_i^{(k)}$ 表示 $z^{(k)}$、$a^{(k)}$、$b^{(k)}$ 的第 $i$ 个分量；
4. 用 $y_i$ 表示 $y$ 的第 $i$ 个分量。

![](/pics/ANN-Deep-Learning/6.jpg)

求偏导的过程如下。设 $\delta_i^{(m)}=\frac{\partial E}{\partial z_i^{(m)}}$：

1. $\delta_i^{(l)}=\frac{\partial E}{\partial z_i^{(l)}}=\frac{\partial E}{\partial y_i}\frac{\partial y_i}{\partial z_i^{(l)}}=(y_i-Y_i)\phi'(z_i^{(l)})$；
2. $\delta_i^{(m)}=\frac{\partial E}{\partial z_i^{(m)}}=\frac{\partial E}{\partial a_i^{(m)}}\frac{\partial a_i^{(m)}}{\partial z_i^{(m)}}=\phi(z_i^{(m)})'(\sum_{j=1}^{S_{m+1}}\delta_j^{(m+1)}\omega_{ji})$，其中 $S_m$ 为第 $m$ 层上 $z$ 的个数且 $1≤m≤(l-1)$；
3. $\begin{cases}\frac{\partial E}{\partial\omega_{ij}^{(m)}}=\delta_j^{(m)}a_i^{(m-1)}\\\ \frac{\partial E}{\partial b_i^{(m)}}=\delta_i^{(m)}\end{cases}$；

BP 算法流程：

1. 随机初始化 $(\omega,b)$；
2. 训练样本 $(X,Y)$ 代入网络，可求出所有的 $(z,a,y)$（前向计算）；
3. 链式法则求偏导。最小化 $E=\frac{1}{2}\lVert y-Y\rVert^2=\frac{1}{2}\sum_{i=1}^M(y_i-Y_i)^2$，求 $\frac{\partial E}{\partial\omega},\frac{\partial E}{\partial b}$（后向传播）；
4. 更新参数：$\omega^{(新)}=\omega^{(旧)}-\alpha\frac{\partial E}{\partial\omega}\vert_{\omega^{(旧)}}$，$b^{(新)}=b^{(旧)}-\alpha\frac{\partial E}{\partial b}\vert_{b^{(旧)}}$。

### 参数设置

参数设置：

1. 随机梯度下降（Stochastic Gradient Descent，SGD）；
   - 不用每输入一个样本就去变换参数，而是输入一批样本（一个 BATCH 或 MINI-BATCH），求出这些样本的梯度平均值后，根据这个平均值改变参数。
2. 激活函数选择；
   - Sigmoid、tanh、ReLU、Leaky ReLU、Maxout、ELU。
3. 训练数据初始化；
   - 做均值和方差的归一化：$newX=\frac{X-mean(X)}{std(X)}$。
4. $(\omega,b)$ 的初始化；
   - 梯度消失现象：如果 $\omega^Tx+b$ 一开始很大或很小，那么梯度将趋近于 0，反向传播后前面与之相关的梯度也趋近于 0，导致训练缓慢。因此，要使 $\omega^Tx+b$ 一开始就在 0 附近；
   - 一种简单有效的方法：$(\omega,b)$ 初始化从区间 $(-\frac{1}{\sqrt{d}},\frac{1}{\sqrt{d}})$ 均匀随机取值。其中 $d$ 为 $(\omega,b)$ 所在层的神经元个数。可以证明，如果 $x$ 服从正态分布，均值 0，方差 1，且各个维度无关，而 $(\omega,b)$ 是 $(-\frac{1}{\sqrt{d}},\frac{1}{\sqrt{d}})$ 的均匀分布，则 $\omega^Tx+b$ 是均值为 0，方差为 $\frac{1}{3}$ 的正态分布。
5. [Batch Normalization](http://proceedings.mlr.press/v37/ioffe15.pdf)；
   - 既然希望每一层获得的值都在 0 附近，从而避免梯度消失现象，那么为什么不直接把每一层的值做基于均值和方差的归一化？
   - 每一层 FC（Fully Connected Layer）接一个 BN（Batch Normalization）；
   - $\hat{x}^{(k)}=\frac{x^{(k)}-E[x^{(k)}]}{\sqrt{Var[x^{(k)}]}}$。
6. 目标函数选择；
   - 可加正则项（Regulation Term）：$\begin{array}{l}L(\omega)=F(\omega)+R(\omega)\\\ =\frac{1}{2}(\sum_{i=1}^{batch\_size}\lVert y_i-Y_i\rVert^2+\beta\sum_k\sum_l\omega_{k,l}^2)\end{array}$；
   - 如果是分类问题，$F(\omega)$ 可以采用 SOFTMAX 函数和交叉熵的组合；
     - SOFTMAX 函数（归一化指数函数）：$q_i=\frac{e^{z_i}}{\sum_{j=1}^Ne^{z_j}}$；
     - 交叉熵（Cross Entropy）：$E=-\sum_{i=1}^Np_i\log(q_i)$；
     - 如果 $F(\omega)$ 是 SOFTMAX 函数和交叉熵的组合，那么求导的形式为 $\frac{\partial E}{\partial z_i}=q_i-p_i$。
7. 参数更新策略。
   - SGD 的问题；
     1. $(\omega,b)$ 的每一个分量获得的梯度绝对值有大有小，一些情况下，将会迫使优化路径变成 Z 字形状；
     2. SGD 求梯度的策略过于随机，由于上一次和下一次用的是完全不同的 BATCH 数据，将会出现优化的方向随机的情况；
   - 解决各个方向梯度不一致的方法；
     - AdaFrad；
     - RMSProp。
   - 解决梯度随机性的问题；
     - Momentum。
   - 同时解决两个问题。
     - Adam。

训练建议：

1. 一般情况下，在训练集上的目标函数的平均值（Cost）会随着训练的深入而不断减小，如果这个指标有增大的情况，停下来。有两种情况：第一是采用的模型不够复杂，以致于不能在训练集上完全拟合；第二是已经训练很好了；
2. 分出一些验证集（Validation Set），训练的本质是在验证集上获取最大的识别率。因此训练一段时间后，必须在验证集上测试识别率，保存使验证集在识别率最大的模型参数，作为最后结果；
3. 注意调整学习率（Learning Rate），如果刚训练几步 Cost 就增加，一般来说是学习率太高了；如果每次 Cost 变化很小，说明学习率太低；
4. Batch Normalization 比较好用，对学习率、参数更新策略等不敏感。如果采用其他方法，合理变换各种参数组合也可以达到目的；
5. 由于梯度累积效应，AdaGrad、RMSProp、Adam 三种更新策略到了训练后期会很慢，可以通过提高学习率来补偿。

# Deep Learning

深度学习是机器学习的分支，是一种以人工神经网络为架构，对数据进行表征学习的算法。

## 从多层神经网络说起

多层神经网络的优势：

1. 基本单元简单，多个基本单元可扩展为非常复杂的非线性函数。因此易于构建，同时模型有很强的表达能力；
2. 训练和测试的计算并行性非常好，有利于在分布式系统上的应用；
3. 模型构建来源于对人脑的仿生，话题丰富，各种领域的研究人员都有兴趣，都能做贡献。

多层神经网络的劣势：

1. 数学不漂亮，优化算法只能获得局部极值，算法性能与初始值有关；
2. 不可解释。训练神经网络获得的参数与实际任务的关联性非常模糊；
3. 模型可调整的参数很多（网络层数、每层神经元的个数、非线性函数、学习率、优化方法、终止条件等等），使得训练神经网络变成了一门“艺术”；
4. 如果要训练相对复杂的网络，需要大量的训练样本。

## 数据库介绍

### Mnist

手写数字数据库（LeCun 在 1998 年创造）：

1. 手写数字 0-9 共 10 类；
2. 训练样本 60000 个，测试样本 10000 个；
3. 图像大小 28\*28 二值图像。

### ImageNet

Fei-fei Li 等在 2007 年创造：

1. 1000 类，100 多万张（2009 年的规模）；
2. 图片大小：正常图片大学，像素几百\*几百；
3. WORDNET 结构，拥有多个 Node（节点）。一个 Node（目前）含有至少 500 个对应物体的可供训练的图片/图像。

## 自编码器（Auto Encoder）

2003 年，人工神经网络进入了沉寂期，因为在样本量少的情况下人工神经网络相对于 SVM 等算法几乎没有优势。自编码器算法为人工神经网络带来了转机和并促进了深度学习的出现。

自编码器是一种利用 BP 算法使得输入值等于输出值的神经网络，部分解决了 $(\omega,b)$ 参数初始化问题。从本质上来讲，自编码器是一种数据压缩算法，其压缩和解压缩算法都是通过神经网络来实现的。例如训练如下网络：

![](/pics/ANN-Deep-Learning/7.png)

- 步骤 1：先训练这个网络；

![](/pics/ANN-Deep-Learning/8.png)

- 步骤 2：定义一个自编码器，使第一层的输入和输出都是 $X$。训练好第 1 层后，接着训练第 2 层（固定第一层参数不动）；

![](/pics/ANN-Deep-Learning/9.png)

- 步骤 M：以此类推，训练好第 M-1 层后，接着训练第 M 层（固定第 M-1 层参数不动）；

![](/pics/ANN-Deep-Learning/10.png)

- 最后用 BP 对网络进行微调。

![](/pics/ANN-Deep-Learning/11.png)

### Programming

这里用 Python 下的 TensorFlow 库实现自编码器。使用 MNIST 数据集进行训练和测试：

```python
#!/usr/bin/env python3
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()
import numpy as np
import matplotlib.pyplot as plt

# Import MNIST data
from tensorflow.examples.tutorials.mnist import input_data
mnist = input_data.read_data_sets('/tmp/data/', one_hot=False)

# Visualize decoder setting
# Parameters
learningRate = 0.01 # 学习率为0.01
trainingEpochs = 5 # 训练5组
batchSize = 256 # 一组Batch共256个数据
examplesToShow = 10 # 展示10个样例

# Network Parameters
nInput = 784 # MNIST data input (img shape: 28 * 28)

# tf Graph input (only pictures)
X = tf.placeholder('float', [None, nInput])

# hidden layer settings
nHidden1 = 256 # 1st layer num features
nHidden2 = 128 # 2nd layer num features
weights = { # 权重w
    'encoderH1': tf.Variable(tf.random_normal([nInput, nHidden1])),
    'encoderH2': tf.Variable(tf.random_normal([nHidden1, nHidden2])),
    'decoderH1': tf.Variable(tf.random_normal([nHidden2, nHidden1])),
    'decoderH2': tf.Variable(tf.random_normal([nHidden1, nInput])),
}
biases = { # 偏置b
    'encoderB1': tf.Variable(tf.random_normal([nHidden1])),
    'encoderB2': tf.Variable(tf.random_normal([nHidden2])),
    'decoderB1': tf.Variable(tf.random_normal([nHidden1])),
    'decoderB2': tf.Variable(tf.random_normal([nInput])),
}

# Building the encoder
def encoder(x):
    # Encoder Hidden layer with sigmoid activation # 1
    layer1 = tf.nn.sigmoid(tf.add(tf.matmul(x, weights['encoderH1']), biases['encoderB1']))
    # Decoder Hidden layer with sigmoid activation # 2
    layer2 = tf.nn.sigmoid(tf.add(tf.matmul(layer1, weights['encoderH2']), biases['encoderB2']))
    return layer2

# Building the decoder
def decoder(x):
    # Encoder Hidden layer with sigmoid activation # 1
    layer1 = tf.nn.sigmoid(tf.add(tf.matmul(x, weights['decoderH1']), biases['decoderB1']))
    # Decoder Hidden layer with sigmoid activation # 2
    layer2 = tf.nn.sigmoid(tf.add(tf.matmul(layer1, weights['decoderH2']), biases['decoderB2']))
    return layer2

# Construct model
encoderOp = encoder(X)
decoderOp = decoder(encoderOp)

# 因为自编码器中输入和输出相同，都设为X
# Prediction
yPred = decoderOp # 预测的结果
# Targets (Labels) are the input data.
yTrue = X # 真实的结果

# Define loss and optimizer, minimize the squared error
cost = tf.reduce_mean(tf.pow(yTrue - yPred, 2)) # 计算MSE
optimizer = tf.train.AdamOptimizer(learningRate).minimize(cost) # 使用Adam算法优化

# Initializing the variables
init = tf.initialize_all_variables()

# Launch the graph
with tf.Session() as sess:
    sess.run(init)
    totalBatch = int(mnist.train.num_examples / batchSize) # 计算Batch的数量
    # Training cycle
    for epoch in range(trainingEpochs):
        # Loop over all batches
        for i in range(totalBatch):
            batchXs, batchYs = mnist.train.next_batch(batchSize) # max(x) = 1, min(x) = 0
            # Run optimization op (backprop) and cost op (to get loss value)
            _, c = sess.run([optimizer, cost], feed_dict={X: batchXs}) # 优化本层参数
        # Display logs per epoch step
        print('Epoch: {}, cost = {:.9f}'.format((epoch + 1), c))
    print('Optimization Finished!')

    # Applying encode and decode over test set
    decodeImages = sess.run(yPred, feed_dict={X:mnist.test.images[:examplesToShow]}) # 获取解压缩得到的图片
    # Compare original images with their reconstructions
    f, a = plt.subplots(2, 10, figsize=(10, 2))
    for i in range(examplesToShow):
        a[0][i].imshow(np.reshape(mnist.test.images[i], (28, 28)))
        a[1][i].imshow(np.reshape(decodeImages[i], (28, 28)))
    plt.show()
```

训练的过程中 cost 逐渐减小：

```bash
$ ./Auto-encoder.py
...
Epoch: 1, cost = 0.097858049
Epoch: 2, cost = 0.091431484
Epoch: 3, cost = 0.083604947
Epoch: 4, cost = 0.078279205
Epoch: 5, cost = 0.075574301
Optimization Finished!
```

识别效果：

![](/pics/ANN-Deep-Learning/12.png)

## Convolutional Neural Network

深度学习主要依赖于卷积神经网络。卷积神经网络（CNN）是一种前馈神经网络，它的人工神经元可以响应一部分覆盖范围内的周围单元，对于大型图像处理有出色表现。卷积神经网络将原本由手工设计卷积核变成自动学习卷积核。

傅立叶变换：

$$
F(j\omega)=\int_{-\infty}^{+\infty}f(t)e^{-j\omega t}dt
$$

其中 $e^{-j\omega t}$ 为卷积核。

### LeNet

由 LeCun 在上世纪 90 年代提出。

![](/pics/ANN-Deep-Learning/13.png)

LeNet 中主要有卷积（Convolution）、降采样（Subsampling）、全连接（Full connection）三种不同的神经网络层。

#### Convolution

假设有 `32x32x3` 的彩色图像（3 个通道），定义一个卷积核大小为 `5x5x3`，步长为 `[1,1]`。若不能全部卷积，可以选择对原图像进行补 0。通过卷积后生成一个 `28x28x1` 的特征图（Feature Map）：

![](/pics/ANN-Deep-Learning/14.png)

若图像为 $(M,N)$，卷积核大小为 $(m,n)$，步长为 $(u,v)$，那么最后得到的特征图（Feature Map）大小为 $(K,L)$，其中 $K≤\frac{M-m}{u}+1$、$L≤\frac{N-n}{v}+1$。可以将图像卷积看成全连接网络的权值共享（Weight Sharing，权值共享网络）：

![](/pics/ANN-Deep-Learning/15.png)

$$
\begin{array}{l}
p_1=\omega_1\*x_1+\omega_2\*x_2+\omega_3\*x_4+\omega_4\*x5+b_1\\\
p_2=\omega_1\*x_2+\omega_2\*x_3+\omega_3\*x_5+\omega_4\*x6+b_2\\\
p_3=\omega_1\*x_4+\omega_2\*x_5+\omega_3\*x_7+\omega_4\*x8+b_3\\\
p_4=\omega_1\*x_5+\omega_2\*x_6+\omega_3\*x_8+\omega_4\*x9+b_4
\end{array}
$$

如果使用 6 个卷积核 就能获得 6 个特征图。若无偏置，共有 $5\times5\times3\times6=450$ 个数；若有偏置，共有 $(5\times5\times5+1)\times6=456$ 个数。做完卷积后，还需要调用 ReLU 等函数进行非线性处理：

![](/pics/ANN-Deep-Learning/16.png)

#### Subsampling

每取一个小方阵，取平均值作为新的数。

![](/pics/ANN-Deep-Learning/17.png)

#### Full connection

将特征值完全展开，两层之间每两个神经元互相连接，和多层神经网络基本一致：

![](/pics/ANN-Deep-Learning/18.png)

其中 MSE 采用 Softmax 函数和交叉熵合用的形式：

$\begin{cases}Softmax(z)=p\\\ E=-\sum_{i=1}^{10}Y_i\log(p_i)\end{cases}$

### AlexNet

2013 年，Alex Krizhevsky 构建了一个包含 65 万个神经元、超过 6000 万个参数的大规模网络 AlexNet，在 ImageNet 的测试集上获得了非常好的成绩，遥遥领先于第二名。

![](/pics/ANN-Deep-Learning/19.png)

AlexNet 在网络结构上和 LeNet 基本一致。主要有一些改进之处：

1. 以 ReLU 函数替代 Sigmoid 或 tanh 函数：$ReLU(x)=\max(0,x)$，使网络训练更快速度收敛；
2. 为降采样操作起了一个新的名字——池化（Pooling），即将邻近的像素作为一个“池子”来重新考虑；
   - AlexNet 中提出了最大池化（Max Pooling）的概念，即对每一个邻近像素组成的“池子”，选取像素的最大值作为输出；
   - 有重叠的最大池化能够很好地克服过拟合问题，提升系统性能。
3. 随机丢弃（Dropout）。为了避免系统参数更新过快导致过拟合，每次利用训练样本更新参数的时候，随机“丢弃”一定比例的神经元，被丢弃的神经元将不参加训练过程，输入和输出该神经元的权重系数也不做更新，每次训练时的网络架构不一样，但是分享共同的权重系数；
   - 减缓了网络收敛速度，也以大概率避免了过拟合的发生。
4. 增加训练样本；
   - 将原图水平翻转；
   - 将 256x256 的图像随机选取 224x224 的片段作为输入图像；
   - 对每幅图片引入一定的噪声，构成新的图像。
5. 用 GPU 加速训练过程（使用两个 GPU 并行运算）。

## 工具

- Caffe（UC Berkeley） -> Caffe2（Facebook）
- Torch（NYU/Facebook） -> PyTorch（Facebook）
- Theano（U Montreal） -> TensorFlow（Google）
- Paddle（Baidu）
- CNTK（Microsoft）
- MXNet（Amazon）

### TensorFlow

实现 LeNet：

```python
#!/usr/bin/env python3
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()

def weight_variable(shape): # 设置权重w
    initial = tf.truncated_normal(shape, stddev=0.1)
    return tf.Variable(initial)

def bias_variable(shape): # 设置偏置b
    initial = tf.constant(0.1, shape=shape)
    return tf.Variable(initial)

def conv2d(x, W, padding_method='SAME'): # 卷积函数
    return tf.nn.conv2d(x, W, strides=[1, 1, 1, 1], padding=padding_method)

def max_pool_2x2(x): # 最大池化
    return tf.nn.max_pool(x, ksize=[1, 2, 2, 1], strides=[1, 2, 2, 1], padding='SAME')

def average_pool_2x2(x): # 平均池化
    return tf.nn.avg_pool(x, ksize=[1, 2, 2, 1], strides=[1, 2, 2, 1], padding='SAME')

from tensorflow.examples.tutorials.mnist import input_data
mnist = input_data.read_data_sets('/tmp/data/', one_hot=True)

sess = tf.InteractiveSession()
x = tf.placeholder('float', shape=[None, 784]) # 输入图像大小为28*28
y_ = tf.placeholder('float', shape=[None, 10]) # 输出结果为10个数字

# 第一层卷积
W_conv1 = weight_variable([5, 5, 1, 6])
b_conv1 = bias_variable([6])
# 第二层降采样
x_image = tf.reshape(x, [-1, 28, 28, 1])
h_conv1 = tf.nn.relu(conv2d(x_image, W_conv1) + b_conv1) # 非线性化
h_pool1 = average_pool_2x2(h_conv1) # 平均池化
# 第三层卷积
W_conv2 = weight_variable([5, 5, 6, 16])
b_conv2 = bias_variable([16])
# 第四层降采样
h_conv2 = tf.nn.relu(conv2d(h_pool1, W_conv2, 'VALID') + b_conv2) # 非线性化
h_pool2 = average_pool_2x2(h_conv2) # 平均池化
# 第五层全连接网络
W_fc1 = weight_variable([5 * 5 * 16, 120])
b_fc1 = bias_variable([120])
h_pool2_flat = tf.reshape(h_pool2, [-1, 5 * 5 * 16])
h_fc1 = tf.nn.relu(tf.matmul(h_pool2_flat, W_fc1) + b_fc1) # 非线性化
keep_prob = tf.placeholder('float')
h_fc1_drop = tf.nn.dropout(h_fc1, keep_prob) # 随机丢弃
# 第六层全连接网络
W_fc2 = weight_variable([120, 84])
b_fc2 = bias_variable([84])
h_fc2 = tf.nn.relu(tf.matmul(h_fc1_drop, W_fc2) + b_fc2) # 非线性化
h_fc2_drop = tf.nn.dropout(h_fc2, keep_prob) # 随机丢弃
# 第七层全连接网络
W_fc3 = weight_variable([84, 10])
b_fc3 = bias_variable([10])

y_conv = tf.nn.softmax(tf.matmul(h_fc2_drop, W_fc3) + b_fc3) # MSE

cross_entropy = -tf.reduce_sum(y_ * tf.log(y_conv))
train_step = tf.train.AdamOptimizer(1e-4).minimize(cross_entropy) # Adam优化算法
correct_prediction = tf.equal(tf.argmax(y_conv, 1), tf.argmax(y_, 1))
accuracy = tf.reduce_mean(tf.cast(correct_prediction, 'float')) # 准确率
sess.run(tf.global_variables_initializer())
for i in range(10000):
    batch = mnist.train.next_batch(50)
    if i % 100 == 0:
        train_accuracy = accuracy.eval(feed_dict={x:batch[0], y_:batch[1], keep_prob:1.0})
        print('step %d, training accuracy %g' % (i, train_accuracy))
    train_step.run(feed_dict={x: batch[0], y_: batch[1], keep_prob: 0.5})

print('test accuracy %g' % accuracy.eval(feed_dict={x:mnist.test.images, y_:mnist.test.labels, keep_prob:1.0}))
```

测试的准确率大致为 95.77%：

```bash
$ ./classfication.py
...
step 0, training accuracy 0.1
step 100, training accuracy 0.38
step 200, training accuracy 0.48
step 300, training accuracy 0.72
step 400, training accuracy 0.72
step 500, training accuracy 0.72
step 600, training accuracy 0.78
step 700, training accuracy 0.7
step 800, training accuracy 0.9
step 900, training accuracy 0.82
step 1000, training accuracy 0.9
step 1100, training accuracy 0.9
...
step 8500, training accuracy 0.92
step 8600, training accuracy 0.96
step 8700, training accuracy 0.98
step 8800, training accuracy 0.96
step 8900, training accuracy 0.98
step 9000, training accuracy 0.98
step 9100, training accuracy 0.98
step 9200, training accuracy 0.9
step 9300, training accuracy 0.96
step 9400, training accuracy 0.92
step 9500, training accuracy 0.94
step 9600, training accuracy 0.92
step 9700, training accuracy 0.98
step 9800, training accuracy 0.96
step 9900, training accuracy 0.92
...
test accuracy 0.9577
```

### Caffe

> 使用 Caffe 时务必将所有相对路径改为绝对路径。

以 MNIST 上的数据集为例（这里略过安装 Caffe 和下载 MNIST 数据集的过程）。首先通过下载得到的数据创建 lmdb 文件：

```bash
#!/bin/sh
set -e

DATA="$HOME/caffe/examples/mnist"
BUILD="$HOME/caffe/build/tools"

rm -rf $DATA/mean.binaryproto

$BUILD/compute_image_mean $DATA/mnist_train_lmdb $DATA/mean.binaryproto $@
```

将 `lenet_solver.prototxt` 设置如下，一组 Batch 设为 100 个样本，学习率设置为 0.01，每 100 次迭代训练输出一次，每 5000 组存一次快照，最后使用 CPU 进行运算：

```bash
# The train/test net protocol buffer definition
net: "/root/caffe/examples/mnist/lenet_train_test.prototxt"
# test_iter specifies how many forward passes the test should carry out.
# In the case of MNIST, we have test batch size 100 and 100 test iterations,
# covering the full 10,000 testing images.
test_iter: 100
# Carry out testing every 500 training iterations.
test_interval: 500
# The base learning rate, momentum and the weight decay of the network.
base_lr: 0.01
momentum: 0.0
weight_decay: 0.0005
# The learning rate policy
lr_policy: "inv"
gamma: 0.0001
power: 0.75
# Display every 100 iterations
display: 100
# The maximum number of iterations
max_iter: 10000
# snapshot intermediate results
snapshot: 5000
snapshot_prefix: "/root/caffe/examples/mnist/lenet"
# solver mode: CPU or GPU
solver_mode: CPU
```

训练脚本中设置好 Solver 的路径：

```bash
#!/bin/sh
set -e

DATA="$HOME/caffe/examples/mnist"
BUILD="$HOME/caffe/build/tools"

$BUILD/caffe train --solver=$DATA/lenet_solver.prototxt $@
```

训练得到的准确率为 98.35%：

```bash
$ ./train_lenet.sh
I0719 09:13:32.369788  3384 caffe.cpp:197] Use CPU.
I0719 09:13:32.370246  3384 solver.cpp:45] Initializing solver from parameters:
test_iter: 100
test_interval: 500
base_lr: 0.01
display: 100
max_iter: 10000
lr_policy: "inv"
gamma: 0.0001
power: 0.75
momentum: 0
weight_decay: 0.0005
snapshot: 5000
snapshot_prefix: "/root/caffe/examples/mnist/lenet"
solver_mode: CPU
net: "/root/caffe/examples/mnist/lenet_train_test.prototxt"
train_state {
  level: 0
  stage: ""
}
I0719 09:13:32.371068  3384 solver.cpp:102] Creating training net from net file: /root/caffe/examples/mnist/lenet_train_test.prototxt
I0719 09:13:32.371302  3384 net.cpp:296] The NetState phase (0) differed from the phase (1) specified by a rule in layer mnist
I0719 09:13:32.371356  3384 net.cpp:296] The NetState phase (0) differed from the phase (1) specified by a rule in layer accuracy
I0719 09:13:32.371500  3384 net.cpp:53] Initializing net from parameters:
name: "LeNet"
state {
  phase: TRAIN
  level: 0
  stage: ""
}
layer {
  name: "mnist"
  type: "Data"
  top: "data"
  top: "label"
  include {
    phase: TRAIN
  }
  transform_param {
    scale: 0.00390625
  }
  data_param {
    source: "/root/caffe/examples/mnist/mnist_train_lmdb"
    batch_size: 64
    backend: LMDB
  }
}
...
layer {
  name: "loss"
  type: "SoftmaxWithLoss"
  bottom: "ip2"
  bottom: "label"
  top: "loss"
}
I0719 09:13:32.375864  3384 layer_factory.hpp:77] Creating layer mnist
I0719 09:13:32.378401  3384 db_lmdb.cpp:35] Opened lmdb /root/caffe/examples/mnist/mnist_train_lmdb
...
I0719 09:13:32.389917  3384 net.cpp:257] Network initialization done.
I0719 09:13:32.390131  3384 solver.cpp:190] Creating test net (#0) specified by net file: /root/caffe/examples/mnist/lenet_train_test.prototxt
I0719 09:13:32.390213  3384 net.cpp:296] The NetState phase (1) differed from the phase (0) specified by a rule in layer mnist
I0719 09:13:32.390334  3384 net.cpp:53] Initializing net from parameters:
name: "LeNet"
state {
  phase: TEST
}
layer {
  name: "mnist"
  type: "Data"
  top: "data"
  top: "label"
  include {
    phase: TEST
  }
  transform_param {
    scale: 0.00390625
  }
  data_param {
    source: "/root/caffe/examples/mnist/mnist_test_lmdb"
    batch_size: 100
    backend: LMDB
  }
}
...
layer {
  name: "loss"
  type: "SoftmaxWithLoss"
  bottom: "ip2"
  bottom: "label"
  top: "loss"
}
I0719 09:13:32.394325  3384 layer_factory.hpp:77] Creating layer mnist
I0719 09:13:32.396040  3384 db_lmdb.cpp:35] Opened lmdb /root/caffe/examples/mnist/mnist_test_lmdb
I0719 09:13:32.399293  3384 net.cpp:86] Creating Layer mnist
...
I0719 09:13:32.408589  3384 net.cpp:257] Network initialization done.
I0719 09:13:32.408671  3384 solver.cpp:57] Solver scaffolding done.
I0719 09:13:32.408725  3384 caffe.cpp:239] Starting Optimization
I0719 09:13:32.408758  3384 solver.cpp:289] Solving LeNet
I0719 09:13:32.408789  3384 solver.cpp:290] Learning Rate Policy: inv
I0719 09:13:32.409927  3384 solver.cpp:347] Iteration 0, Testing net (#0)
I0719 09:13:37.804333  3387 data_layer.cpp:73] Restarting data prefetching from start.
I0719 09:13:38.027662  3384 solver.cpp:414]     Test net output #0: accuracy = 0.1248
I0719 09:13:38.027835  3384 solver.cpp:414]     Test net output #1: loss = 2.39762 (* 1 = 2.39762 loss)
I0719 09:13:38.118224  3384 solver.cpp:239] Iteration 0 (-6.72623e-44 iter/s, 5.709s/100 iters), loss = 2.36513
I0719 09:13:38.118404  3384 solver.cpp:258]     Train net output #0: loss = 2.36513 (* 1 = 2.36513 loss)
I0719 09:13:38.118474  3384 sgd_solver.cpp:112] Iteration 0, lr = 0.01
I0719 09:13:47.032905  3384 solver.cpp:239] Iteration 100 (11.2183 iter/s, 8.914s/100 iters), loss = 0.696854
I0719 09:13:47.033085  3384 solver.cpp:258]     Train net output #0: loss = 0.696854 (* 1 = 0.696854 loss)
I0719 09:13:47.033146  3384 sgd_solver.cpp:112] Iteration 100, lr = 0.00992565
I0719 09:13:55.957051  3384 solver.cpp:239] Iteration 200 (11.207 iter/s, 8.923s/100 iters), loss = 0.349362
I0719 09:13:55.957224  3384 solver.cpp:258]     Train net output #0: loss = 0.349362 (* 1 = 0.349362 loss)
I0719 09:13:55.957285  3384 sgd_solver.cpp:112] Iteration 200, lr = 0.00985258
I0719 09:14:04.869757  3384 solver.cpp:239] Iteration 300 (11.2208 iter/s, 8.912s/100 iters), loss = 0.329913
I0719 09:14:04.870034  3384 solver.cpp:258]     Train net output #0: loss = 0.329913 (* 1 = 0.329913 loss)
I0719 09:14:04.870095  3384 sgd_solver.cpp:112] Iteration 300, lr = 0.00978075
...
I0719 09:21:36.396572  3384 solver.cpp:239] Iteration 4800 (11.2309 iter/s, 8.904s/100 iters), loss = 0.132899
I0719 09:21:36.396747  3384 solver.cpp:258]     Train net output #0: loss = 0.132899 (* 1 = 0.132899 loss)
I0719 09:21:36.396808  3384 sgd_solver.cpp:112] Iteration 4800, lr = 0.00745253
I0719 09:21:45.291420  3384 solver.cpp:239] Iteration 4900 (11.2435 iter/s, 8.894s/100 iters), loss = 0.0251573
I0719 09:21:45.291604  3384 solver.cpp:258]     Train net output #0: loss = 0.0251575 (* 1 = 0.0251575 loss)
I0719 09:21:45.291664  3384 sgd_solver.cpp:112] Iteration 4900, lr = 0.00741498
I0719 09:21:54.117733  3384 solver.cpp:464] Snapshotting to binary proto file /root/caffe/examples/mnist/lenet_iter_5000.caffemodel
I0719 09:21:54.126977  3384 sgd_solver.cpp:284] Snapshotting solver state to binary proto file /root/caffe/examples/mnist/lenet_iter_5000.solverstate
I0719 09:21:54.130437  3384 solver.cpp:347] Iteration 5000, Testing net (#0)
I0719 09:21:59.522549  3387 data_layer.cpp:73] Restarting data prefetching from start.
I0719 09:21:59.746923  3384 solver.cpp:414]     Test net output #0: accuracy = 0.9807
I0719 09:21:59.747100  3384 solver.cpp:414]     Test net output #1: loss = 0.0614721 (* 1 = 0.0614721 loss)
I0719 09:21:59.833456  3384 solver.cpp:239] Iteration 5000 (6.87711 iter/s, 14.541s/100 iters), loss = 0.0629105
I0719 09:21:59.833653  3384 solver.cpp:258]     Train net output #0: loss = 0.0629108 (* 1 = 0.0629108 loss)
I0719 09:21:59.833714  3384 sgd_solver.cpp:112] Iteration 5000, lr = 0.00737788
I0719 09:22:08.751772  3384 solver.cpp:239] Iteration 5100 (11.2133 iter/s, 8.918s/100 iters), loss = 0.134128
I0719 09:22:08.751960  3384 solver.cpp:258]     Train net output #0: loss = 0.134128 (* 1 = 0.134128 loss)
I0719 09:22:08.752022  3384 sgd_solver.cpp:112] Iteration 5100, lr = 0.0073412
...
I0719 09:29:50.077375  3384 solver.cpp:239] Iteration 9700 (11.2309 iter/s, 8.904s/100 iters), loss = 0.0202741
I0719 09:29:50.077550  3384 solver.cpp:258]     Train net output #0: loss = 0.0202745 (* 1 = 0.0202745 loss)
I0719 09:29:50.077612  3384 sgd_solver.cpp:112] Iteration 9700, lr = 0.00601382
I0719 09:29:58.986270  3384 solver.cpp:239] Iteration 9800 (11.2259 iter/s, 8.908s/100 iters), loss = 0.158889
I0719 09:29:58.986459  3384 solver.cpp:258]     Train net output #0: loss = 0.15889 (* 1 = 0.15889 loss)
I0719 09:29:58.986519  3384 sgd_solver.cpp:112] Iteration 9800, lr = 0.00599102
I0719 09:30:07.907111  3384 solver.cpp:239] Iteration 9900 (11.2108 iter/s, 8.92s/100 iters), loss = 0.0175776
I0719 09:30:07.907289  3384 solver.cpp:258]     Train net output #0: loss = 0.0175779 (* 1 = 0.0175779 loss)
I0719 09:30:07.907397  3384 sgd_solver.cpp:112] Iteration 9900, lr = 0.00596843
I0719 09:30:16.723201  3384 solver.cpp:464] Snapshotting to binary proto file /root/caffe/examples/mnist/lenet_iter_10000.caffemodel
I0719 09:30:16.732036  3384 sgd_solver.cpp:284] Snapshotting solver state to binary proto file /root/caffe/examples/mnist/lenet_iter_10000.solverstate
I0719 09:30:16.772199  3384 solver.cpp:327] Iteration 10000, loss = 0.041269
I0719 09:30:16.772374  3384 solver.cpp:347] Iteration 10000, Testing net (#0)
I0719 09:30:22.153097  3387 data_layer.cpp:73] Restarting data prefetching from start.
I0719 09:30:22.376965  3384 solver.cpp:414]     Test net output #0: accuracy = 0.9835
I0719 09:30:22.377146  3384 solver.cpp:414]     Test net output #1: loss = 0.0502197 (* 1 = 0.0502197 loss)
I0719 09:30:22.377204  3384 solver.cpp:332] Optimization Done.
I0719 09:30:22.377256  3384 caffe.cpp:250] Optimization Done.
```

使用快照存下的权重系数进行测试：

```bash
#!/bin/sh
set -e

DATA="$HOME/caffe/examples/mnist"
BUILD="$HOME/caffe/build/tools"

$BUILD/caffe test -model $DATA/lenet_train_test.prototxt -weights $DATA/lenet_iter_10000.caffemodel -iterations 100 $@
```

测试得到的结果也是 98.35%：

```bash
$ ./test_lenet.sh
I0719 09:54:00.532202  3750 caffe.cpp:275] Use CPU.
I0719 09:54:00.534042  3750 net.cpp:296] The NetState phase (1) differed from the phase (0) specified by a rule in layer mnist
I0719 09:54:00.534274  3750 net.cpp:53] Initializing net from parameters:
name: "LeNet"
state {
  phase: TEST
  level: 0
  stage: ""
}
layer {
  name: "mnist"
  type: "Data"
  top: "data"
  top: "label"
  include {
    phase: TEST
  }
  transform_param {
    scale: 0.00390625
  }
  data_param {
    source: "/root/caffe/examples/mnist/mnist_test_lmdb"
    batch_size: 100
    backend: LMDB
  }
}
...
layer {
  name: "loss"
  type: "SoftmaxWithLoss"
  bottom: "ip2"
  bottom: "label"
  top: "loss"
}
I0719 09:54:00.539016  3750 layer_factory.hpp:77] Creating layer mnist
I0719 09:54:00.539180  3750 db_lmdb.cpp:35] Opened lmdb /root/caffe/examples/mnist/mnist_test_lmdb
I0719 09:54:00.539252  3750 net.cpp:86] Creating Layer mnist
...
I0719 09:54:00.549928  3750 net.cpp:257] Network initialization done.
I0719 09:54:00.578881  3750 caffe.cpp:281] Running for 100 iterations.
I0719 09:54:00.638658  3750 caffe.cpp:304] Batch 0, accuracy = 1
I0719 09:54:00.638818  3750 caffe.cpp:304] Batch 0, loss = 0.0125258
I0719 09:54:00.695282  3750 caffe.cpp:304] Batch 1, accuracy = 1
I0719 09:54:00.695446  3750 caffe.cpp:304] Batch 1, loss = 0.014934
I0719 09:54:00.751154  3750 caffe.cpp:304] Batch 2, accuracy = 0.97
I0719 09:54:00.751315  3750 caffe.cpp:304] Batch 2, loss = 0.0793383
I0719 09:54:00.807118  3750 caffe.cpp:304] Batch 3, accuracy = 0.99
I0719 09:54:00.807282  3750 caffe.cpp:304] Batch 3, loss = 0.0438309
I0719 09:54:00.867218  3750 caffe.cpp:304] Batch 4, accuracy = 0.98
I0719 09:54:00.868525  3750 caffe.cpp:304] Batch 4, loss = 0.0713425
I0719 09:54:00.924510  3750 caffe.cpp:304] Batch 5, accuracy = 0.99
I0719 09:54:00.924670  3750 caffe.cpp:304] Batch 5, loss = 0.0617221
I0719 09:54:00.980692  3750 caffe.cpp:304] Batch 6, accuracy = 0.97
I0719 09:54:00.980855  3750 caffe.cpp:304] Batch 6, loss = 0.0743186
I0719 09:54:01.036712  3750 caffe.cpp:304] Batch 7, accuracy = 0.96
I0719 09:54:01.036875  3750 caffe.cpp:304] Batch 7, loss = 0.0618587
I0719 09:54:01.093209  3750 caffe.cpp:304] Batch 8, accuracy = 1
I0719 09:54:01.093359  3750 caffe.cpp:304] Batch 8, loss = 0.0243737
...
I0719 09:54:05.863339  3750 caffe.cpp:304] Batch 93, accuracy = 1
I0719 09:54:05.863505  3750 caffe.cpp:304] Batch 93, loss = 0.0035342
I0719 09:54:05.919293  3750 caffe.cpp:304] Batch 94, accuracy = 1
I0719 09:54:05.919464  3750 caffe.cpp:304] Batch 94, loss = 0.00404837
I0719 09:54:05.975389  3750 caffe.cpp:304] Batch 95, accuracy = 1
I0719 09:54:05.975559  3750 caffe.cpp:304] Batch 95, loss = 0.00803444
I0719 09:54:05.975966  3752 data_layer.cpp:73] Restarting data prefetching from start.
I0719 09:54:06.031582  3750 caffe.cpp:304] Batch 96, accuracy = 0.97
I0719 09:54:06.031741  3750 caffe.cpp:304] Batch 96, loss = 0.101935
I0719 09:54:06.087718  3750 caffe.cpp:304] Batch 97, accuracy = 0.94
I0719 09:54:06.087873  3750 caffe.cpp:304] Batch 97, loss = 0.169228
I0719 09:54:06.143560  3750 caffe.cpp:304] Batch 98, accuracy = 0.99
I0719 09:54:06.143725  3750 caffe.cpp:304] Batch 98, loss = 0.0384616
I0719 09:54:06.199724  3750 caffe.cpp:304] Batch 99, accuracy = 0.99
I0719 09:54:06.199882  3750 caffe.cpp:304] Batch 99, loss = 0.023861
I0719 09:54:06.199935  3750 caffe.cpp:309] Loss: 0.0502197
I0719 09:54:06.200014  3750 caffe.cpp:321] accuracy = 0.9835
I0719 09:54:06.200079  3750 caffe.cpp:321] loss = 0.0502197 (* 1 = 0.0502197 loss)
```

## 流行的卷积神经网络结构

- LeNet
- AlexNet
- VGGNet
- GooglLeNet
- ResNet（Residual Net）

# References

浙江大学信电学院《机器学习》课程
《机器学习》——周志华
[莫烦 Python——搭建自己的神经网络](https://morvanzhou.github.io/tutorials/machine-learning/tensorflow/)
