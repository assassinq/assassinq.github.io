---
title: Reiforcement Learning
date: 2020-07-20 15:15:45
tags: [rl, ml]
---

无监督的强化学习。

<!-- more -->

# 强化学习与监督学习的区别

1. 训练数据中没有标签，只有奖励函数（Reward Function）；
2. 训练数据不是现成给定的，而是由行为（Action）获得；
3. 现在的行为（Action）不仅影响后续训练数据的获得，也影响奖励函数（Reward Function）的取值；
4. 训练的目的是构建一个“状态->行为”的函数，其中状态（State）描述了目前内部和外部的环境，在此情况下，要使一个智能体（Agent）在某个特定的状态下，通过这个函数决定此时应该采取的行为。希望采取这些行为后，最终获得最大的奖励函数值。

## 强化学习相关算法

- 通过价值选行为（Model-Free）；
  - Q learning（基于价值）
  - Sarsa（基于价值）
  - Deep Q Network
- 直接选行为；
  - Policy Gradients（基于概率）
- 想象环境并从中学习。
  - Model based RL

# [Q Learning](https://blog.csdn.net/qq_30615903/article/details/80739243)

Q Learning 是强化学习算法中基于价值的算法。

$$
\begin{array}{l}
Initialize\ Q(s,a)\ arbitrarily\\\
Repeat\ (for\ each\ episode):\\\
\quad Initialize\ S\\\
\quad Repeat\ (for\ each\ step\ of\ episode):\\\
\quad\quad Choose\ A\ from\ S\ using\ policy\ derived\ from\ Q\ (e.g.,\varepsilon-greedy)\\\
\quad\quad Take\ action\ A,\ observe E,\ S'\\\
\quad\quad Q(S,A)\leftarrow Q(S,A)+\alpha[R+\gamma\max_aQ(S',a)-Q(S,A)]\\\
\quad\quad S\leftarrow S';\\\
\quad until\ S\ is\ terminal
\end{array}
$$

## 马尔可夫假设

假设状态数有限，行为数有限：

- $R_t$：$t$ 时刻的奖励函数值；
- $S_t$：$t$ 时刻的状态；
- $A_t$：$t$ 时刻的行为。
- 下一时刻的状态只与当前时刻状态有关，与其他状态无关：$\mathbb{P}[S_{t+1}\vert S_t]=\mathbb{P}[S_{t+1}\vert S_1,\cdots,S_t]$；
- 下一个时刻的状态只与这一时刻的状态以及这一时刻的行为有关：$P_{ss'}^a=\mathbb{P}[S_{t+1}=s'\vert S_t=s,A_t=a]$；
- 下一时刻的奖励函数值只与这一时刻的状态及这一时刻的行为有关：$R_s^a=\mathbb{E}[R_{t+1}\vert S_t=s,A_t=a]$。

## Markov Decision Process（MDP）

1. 在 $t=0$ 的时候，环境给出一个初始状态 $s_0\sim p(s_0)$；
2. 需要学习一个策略（Policy）$\pi^\*$，这是一个从状态到行为的映射函数，使得最大化累积的奖励。
   - 智能体选择行为 $a_t$；
   - 环境采样奖励函数 $r_t\sim E(r_t\vert s_t,a_t)$；
   - 环境产生下一个状态 $s_{t+1}\sim P(s_{t+1}\vert s_t,a_t)$；
   - 智能体获得奖励函数 $r_t$ 和下一个状态 $s_{t+1}$。

## 待优化目标函数

增强学习中的待优化目标函数是累计奖励，即一段时间内的奖励函数加权平均值（$\gamma$ 是一个衰减项，$0<\gamma<1$）：

$$
G_t=R_{t+1}+\gamma R_{t+2}+\cdots=\sum_{k=0}^\infty\gamma^kR_{t+k+1}
$$

需要学习的函数只有 $\pi^\*$，即一个状态->行为的映射：

$$
\pi(s_t,a_t)=p(a_t\vert s_t)
$$

根据一个决策机制（Policy），可以获得一条路径：

$$
s_0,a_0,r_0,s_1,a_1,r_1,\cdots
$$

估值函数（Value Function）是衡量某个状态最终能获得多少累计奖励的函数：

$$
V^\pi(s)=\mathbb{E}[\sum_{t=0}^{+\infty}\gamma^tr_t\vert s_0=s,\pi]
$$

Q 函数是衡量某个状态下采取某个行为后，最终能获得多少积累奖励的函数：

$$
Q^\pi(s,a)=\mathbb{E}[\sum_{t=0}^{+\infty}\gamma^tr_t\vert s_0=s,a_0=a,\pi]
$$

有以下公式：

$$
\begin{array}{cc}
\pi(s,a)=p(a\vert s)\\\
Q^\pi(s,a)=\sum_{S'\in S}P_{SS'}^a(R_S^a+\gamma V^\pi(S'))\\\
\pi(S,a)=\begin{cases}1, & 若a=\max_{a\in A}\ Q(S,a)\\\ 2, &其他\end{cases}
\end{array}
$$

得出估值函数和 Q 函数之间的关系：

$$
\begin{array}{l}
V^\pi(s)=E_\pi(\sum_{t=0}^{+\infty}\gamma^tr_t\vert s_0=s,\pi)\\\
\quad\quad=E_\pi(r_0+\gamma\sum_{t=0}^{+\infty}\gamma^tr_{t+1}\vert s_0=s,\pi)\\\
\quad\quad=\sum_{a\in A}\pi(s,a)\sum_{s'\in s}P_{ss'}^a(R_s^a+\gamma V^\pi(s'))\\\
\quad\quad=\sum_{a\in A}p(a\vert s)Q^\pi(s,a)
\end{array}
$$

即：

$$
V^\pi(s)=\sum_{a\in A}\pi(s,a)Q^\pi(s,a)
$$

通过上式，并使用迭代的方式每次对 Q 值（$\pi(s,a)$，即在状态 $s$ 下执行动作 $a$ 的概率）进行更新，最终可以求出最佳策略 $\pi$。

## Shortcomings

对于状态数和行为数很多的时候，这种做法不现实。

## Programming

下面模拟一下 Q Learning 的学习过程：

```python
#!/usr/bin/env python3
import numpy as np
import pandas as pd
import time
import sys

if len(sys.argv) == 2 and sys.argv[1] == 'SET_SEED':
    seed = int(input('Input seed: '))
    np.random.seed(seed)

NSTATES = 6
ACTIONS = ['left', 'right']
EPSILON = 0.9 # greedy policy
ALPHA = 0.1 # learning rate
LAMBDA = 0.9 # discount factor
MAX_EPSODES = 13
FRESH_TIME = 0.01

def buildQTable(nStates, actions): # 创建Q表
    table = pd.DataFrame(
        np.zeros((nStates, len(actions))),
        columns=actions, # 纵坐标为Actions
    )
    print(table)
    return table

def chooseAction(state, qTable): # 随机选择Action
    stateActions = qTable.iloc[state, :]
    if np.random.rand() > EPSILON or stateActions.all() == False: # 命中了10%的概率或是表中所有Actions的值都为0，随机选择下一个Action
        actionName = np.random.choice(ACTIONS)
    else: # 反之取值最大的Action作为下一个选择
        actionName = stateActions.idxmax()
    return actionName

def getEnvFeedback(S, A): # 通过当前状态和行为获取下一状态和奖励函数值
    if A == 'right': # 如果Action为向右走
        if S == NSTATES - 2: # 如果当前状态在目的地左侧1个位置
            S_ = 'terminate' # 下一个状态设为终止
            R = 1 # 奖励函数值设为1
        else:
            S_ = S + 1 # 下一状态设为当前状态+1
            R = 0 # 奖励函数值为0
    else: # 如果Action为向左走
        R = 0 # 向左走不会到目的地，奖励函数值设为0
        if S == 0: # 如果已经在最左侧
            S_ = S # 下一状态不变
        else:
            S_ = S - 1 # 下一状态设为当前状态-1
    return S_, R

def updateEnv(S, episode, stepCounter): # 更新环境
    envList = ['-'] * (NSTATES - 1) + ['T'] # 初始化环境
    if S == 'terminate': # 如果状态为终止
        interaction = 'Episode %s: total_steps = %s' % (episode + 1, stepCounter)
        print('\r{}'.format(interaction))
        time.sleep(0.5)
    else:
        envList[S] = 'M' # 更新当前位置
        interaction = ''.join(envList)
        print('\r{}'.format(interaction), end='')
        time.sleep(FRESH_TIME)

def rl(): # 增强学习训练函数
    qTable = buildQTable(NSTATES, ACTIONS) # 创建Q表
    for episode in range(MAX_EPSODES): # 循环训练
        stepCounter = 0
        S = 0
        isTerminated = False
        updateEnv(S, episode, stepCounter) # 初始化环境
        while not isTerminated:
            A = chooseAction(S, qTable) # 选择Action
            S_, R = getEnvFeedback(S, A) # 获取下一个状态和当前奖励函数值
            qPred = qTable.loc[S, A] # 获取预测的Q值
            if S_ != 'terminate': # 如果没有到达目的地
                qTarget = R + LAMBDA * qTable.iloc[S_, :].max() # 计算实际的Q值
            else:
                qTarget = R
                isTerminated = True
            qTable.loc[S, A] += ALPHA * (qTarget - qPred) # 更新Q值
            S = S_ # 更新当前状态
            updateEnv(S, episode, stepCounter + 1) # 更新环境
            stepCounter += 1
    return qTable

if __name__ == '__main__':
    qTable = rl()
    print(qTable)
```

因为存在贪婪系数（Greedy Policy），在实际测试时可能有 10% 的概率随机选择行为，导致最后的结果有一些浮动：

```bash
$ ./Q-Learning-1.py
   left  right
0   0.0    0.0
1   0.0    0.0
2   0.0    0.0
3   0.0    0.0
4   0.0    0.0
5   0.0    0.0
Episode 1: total_steps = 34
Episode 2: total_steps = 7
Episode 3: total_steps = 7
Episode 4: total_steps = 5
Episode 5: total_steps = 6
Episode 6: total_steps = 8
Episode 7: total_steps = 7
Episode 8: total_steps = 5
Episode 9: total_steps = 5
Episode 10: total_steps = 5
Episode 11: total_steps = 5
Episode 12: total_steps = 5
Episode 13: total_steps = 5
       left     right
0  0.000002  0.005213
1  0.000026  0.027133
2  0.000139  0.111724
3  0.000139  0.343331
4  0.000810  0.745813
5  0.000000  0.000000
```

## Off-policy

Q Learning 是典型的 Off-policy 算法，其生成样本的 Policy（Value Function）跟网络更新参数时使用的 Policy（Value Function）不同，计算下一状态的预期收益时通过 MAX 函数直接选择最优动作，而当前 Policy 并不一定能选择到最优动作。先产生某概率分布下的大量行为数据（Behavior Policy），意在探索。从这些偏离（Off）最优策略的数据中寻求 Target Policy。

劣势是曲折，收敛慢，但优势是确保了数据全面性，所有行为都能覆盖。

# [Sarsa](https://zhuanlan.zhihu.com/p/29283927)

Sarsa 算法和 Q Learning 很像，也是基于 Q 表实现。

$$
\begin{array}{l}
Initialize\ Q(s,a)\ arbitrarily\\\
Repeat\ (for\ each\ episode):\\\
\quad Initialize\ S\\\
\quad Choose\ A\ from\ S\ using\ policy\ derived\ from\ Q\ (e.g.,\varepsilon-greedy)\\\
\quad Repeat\ (for\ each\ step\ of\ episode):\\\
\quad\quad Take\ action\ A,\ observe\ E,\ S'\\\
\quad\quad Choose\ A'\ from\ S'\ using\ policy\ derived\ from\ Q\ (e.g.,\varepsilon-greedy)\\\
\quad\quad Q(S,A)\leftarrow Q(S,A)+\alpha[R+\gamma Q(S',A')-Q(S,A)]\\\
\quad\quad S\leftarrow S';\ A\leftarrow A';\\\
\quad until\ S\ is\ terminal
\end{array}
$$

在更新 Q 表的时候，Sarsa 选择的策略与上一个策略一样，执行完当前行为 Action 后，再更新 Q 值。

## Programming

测试由 tkinter 库实现的走迷宫小程序，使用 Sarsa 算法在避开陷阱的同时找到最优路径：

```python
#!/usr/bin/env python3
import numpy as np
import pandas as pd
import tkinter as tk
import time

UNIT = 40 # pixels
MAZE_H = 4 # grid height
MAZE_W = 4 # grid width

class Maze(tk.Tk, object): # 环境类
    def __init__(self):
        super(Maze, self).__init__()
        self.actionSpace = ['up', 'down', 'left', 'right']
        self.nActions = len(self.actionSpace)
        self.title('maze')
        self.geometry('{0}x{1}'.format(MAZE_H * UNIT, MAZE_W * UNIT))
        self.buildMaze()

    def buildMaze(self):
        self.canvas = tk.Canvas(self, bg='white', height=MAZE_H * UNIT, width=MAZE_W * UNIT)
        for c in range(0, MAZE_W * UNIT, UNIT):
            x0, y0, x1, y1 = c, 0, c, MAZE_H * UNIT
            self.canvas.create_line(x0, y0, x1, y1)
        for r in range(0, MAZE_H * UNIT, UNIT):
            x0, y0, x1, y1 = 0, r, MAZE_W * UNIT, r
            self.canvas.create_line(x0, y0, x1, y1)
        origin = np.array([20, 20])
        # hell
        hell1Center = origin + np.array([UNIT * 2, UNIT])
        self.hell1 = self.canvas.create_rectangle(hell1Center[0] - 15, hell1Center[1] - 15, hell1Center[0] + 15, hell1Center[1] + 15, fill='black')
        # hell
        hell2Center = origin + np.array([UNIT, UNIT * 2])
        self.hell2 = self.canvas.create_rectangle(hell2Center[0] - 15, hell2Center[1] - 15, hell2Center[0] + 15, hell2Center[1] + 15, fill='black')
        # oval
        ovalCenter = origin + UNIT * 2
        self.oval = self.canvas.create_rectangle(ovalCenter[0] - 15, ovalCenter[1] - 15, ovalCenter[0] + 15, ovalCenter[1] + 15, fill='yellow')
        # rect
        self.rect = self.canvas.create_rectangle(origin[0] - 15, origin[1] - 15, origin[0] + 15, origin[1] + 15, fill='red')
        self.canvas.pack()

    def reset(self):
        self.update()
        time.sleep(0.5)
        self.canvas.delete(self.rect)
        origin = np.array([20, 20])
        self.rect = self.canvas.create_rectangle(origin[0] - 15, origin[0] - 15, origin[0] + 15, origin[0] + 15, fill='red')
        return self.canvas.coords(self.rect)

    def step(self, action):
        s = self.canvas.coords(self.rect)
        baseAction = np.array([0, 0])
        if action == 0:
            if s[1] > UNIT:
                baseAction[1] -= UNIT
        elif action == 1:
            if s[1] < (MAZE_H - 1) * UNIT:
                baseAction[1] += UNIT
        elif action == 2:
            if s[0] < (MAZE_W - 1) * UNIT:
                baseAction[0] += UNIT
        elif action == 3:
            if s[0] > UNIT:
                baseAction[0] -= UNIT
        self.canvas.move(self.rect, baseAction[0], baseAction[1])
        s_ = self.canvas.coords(self.rect)
        if s_ == self.canvas.coords(self.oval):
            reward = 1
            isDone = True
            s_ = 'terminated'
        elif s_ in [self.canvas.coords(self.hell1), self.canvas.coords(self.hell2)]:
            reward = -1
            isDone = True
            s_ = 'terminated'
        else:
            reward = 0
            isDone = False
        return s_, reward, isDone

    def render(self):
        time.sleep(0.1)
        self.update()

class RL(object): # 增强学习类
    def __init__(self, actions, learningRate=0.01, rewardDecay=0.9, greedyPolicy=0.9):
        self.actions = actions
        self.lr = learningRate # 学习率
        self.gamma = rewardDecay # 衰减项
        self.epsilon = greedyPolicy # 贪婪系数
        self.qTable = pd.DataFrame(columns=self.actions, dtype=np.float64)

    def checkStateExists(self, state): # 检查状态State是否存在
        if state not in self.qTable.index:
            self.qTable = self.qTable.append(pd.Series([0] * len(self.actions), index=self.qTable.columns, name=state))

    def chooseAction(self, observation): # 选择行为Action
        self.checkStateExists(observation)
        if np.random.rand() < self.epsilon:
            stateAction = self.qTable.loc[observation, :]
            action = np.random.choice(stateAction[stateAction == np.max(stateAction)].index) # 选择Q值最大的行为Action
        else: # 10%的概率随机选择行为Action
            action = np.random.choice(self.actions)
        return action

    def learn(self, *args): # 学习函数
        pass

class SarsaTable(RL):
    def __init__(self, actions, learningRate=0.01, rewardDecay=0.9, greedyPolicy=0.9):
        super(SarsaTable, self).__init__(actions, learningRate, rewardDecay, greedyPolicy)

    def learn(self, s, a, r, s_, a_):
        self.checkStateExists(s_) # 检测得到的下一个状态State是否存在
        qPred = self.qTable.loc[s, a]
        if s_ != 'terminated': # 如果没有终止
            qTarget = r + self.gamma * self.qTable.loc[s_, a_] # 计算新的Q值
        else: # 状态终止
            qTarget = r
        self.qTable.loc[s, a] += self.lr * (qTarget - qPred) # 更新Q值

def update(): # 更新环境函数
    for episode in range(100):
        stepCounter = 0
        state = env.reset() # 获取初始状态
        action = RL.chooseAction(str(state)) # 获取初始行为
        while True:
            env.render() # 更新环境
            state_, reward, isDone = env.step(action) # 执行当前行为并获取下一状态
            action_ = RL.chooseAction(str(state_)) # 选择下一个行为Action
            RL.learn(str(state), action, reward, str(state_), action_) # 学习并更新Q表
            state = state_ # 更新下一个状态State
            action = action_ # 更新下一个行为Action
            stepCounter += 1
            if isDone:
                break
        if reward == 1:
            print('[+] Success! Episode %s: total_steps = %s' % (episode + 1, stepCounter))
        elif reward == -1:
            print('[!] Failed... Episode %s: total_steps = %s' % (episode + 1, stepCounter))
    print('[*] Done')
    env.destroy()

if __name__ == '__main__':
    env = Maze()
    RL = SarsaTable(actions=list(range(env.nActions)))
    env.after(100, update)
    env.mainloop()
```

学习效果：

```bash
$ $ ./Sarsa.py
[!] Failed... Episode 1: total_steps = 7
[!] Failed... Episode 2: total_steps = 11
[!] Failed... Episode 3: total_steps = 31
[!] Failed... Episode 4: total_steps = 45
[+] Success! Episode 5: total_steps = 84
[!] Failed... Episode 6: total_steps = 73
[+] Success! Episode 7: total_steps = 36
[+] Success! Episode 8: total_steps = 82
[+] Success! Episode 9: total_steps = 33
[+] Success! Episode 10: total_steps = 48
[+] Success! Episode 11: total_steps = 61
[+] Success! Episode 12: total_steps = 8
[+] Success! Episode 13: total_steps = 8
[+] Success! Episode 14: total_steps = 6
[+] Success! Episode 15: total_steps = 6
[+] Success! Episode 16: total_steps = 6
[+] Success! Episode 17: total_steps = 11
[!] Failed... Episode 18: total_steps = 6
[+] Success! Episode 19: total_steps = 7
[+] Success! Episode 20: total_steps = 6
[+] Success! Episode 21: total_steps = 6
[+] Success! Episode 22: total_steps = 6
[+] Success! Episode 23: total_steps = 8
[+] Success! Episode 24: total_steps = 6
[+] Success! Episode 25: total_steps = 6
[+] Success! Episode 26: total_steps = 6
[+] Success! Episode 27: total_steps = 6
[+] Success! Episode 28: total_steps = 6
...
```

## Off-policy

生成样本的 Policy（Value Function）跟网络更新参数时使用的 Policy（Value Function）相同。典型为 SARAS 算法，基于当前的 Policy 直接执行一次动作选择，然后用这个样本更新当前的 Policy。

该方法会遭遇探索-利用的矛盾，光利用目前已知的最优选择，可能学不到最优解，收敛到局部最优，而加入探索又降低了学习效率。epsilon-greedy 算法是这种矛盾下的折衷。优点是直接了当，速度快，劣势是不一定找到最优策略。

## [Sarsa-lambda](https://blog.csdn.net/u010089444/article/details/80516345)

Sarsa-lambda 算法是 Sarsa 的改进版。在每次获得 Reward 后，Sarsa 只对前一步的 Q 值进行更新，Sarsa-lambda 则会对获得 Reward 之前所有的 Q 值进行更新。

$$
\begin{array}{l}
Initialize\ Q(s,a)\ arbitrarily,for\ all\ s\in S,a\in A(s)\\\
Repeat\ (for\ each\ episode):\\\
\quad E(s,a)=0,for\ all\ s\in S,a\in A(s)\\\
\quad Initialize\ S,A\\\
\quad Repeat\ (for\ each\ step\ of\ episode):\\\
\quad\quad Choose\ A'\ from\ S'\ using\ policy\ derived\ from\ Q\ (e.g.,\varepsilon-greedy)\\\
\quad\quad \delta\leftarrow R+\gamma Q(S',A')-Q(S,A)\\\
\quad\quad E(S,A)\leftarrow E(S,A)+1\\\
\quad\quad For\ all\ s\in S,a\in A(s):\\\
\quad\quad\quad Q(s,a)\leftarrow Q(s,a)+\alpha\delta E(s,a)\\\
\quad\quad\quad E(s,a)\leftarrow \gamma\lambda E(s,a)\\\
\quad\quad S\leftarrow S';\ A\leftarrow A';\\\
\quad until\ S\ is\ terminal
\end{array}
$$

Sarsa-lambda 中新增了一个矩阵 Eligibility Trace，用于保存在路径中的每一步，这样就能更新前面的每一步的 Q 值。其中 $\lambda\in[0,1]$，如果 $\lambda=0$，就会退化为 Sarsa 算法；如果 $\lambda=1$，每次更新就会完全考虑到前面的每一步。

### Programming

对 Sarsa 进行一定的修改：

```python
...

class SarsaLambdaTable(RL):
    def __init__(self, actions, learningRate=0.01, rewardDecay=0.9, greedyPolicy=0.9, traceDecay=0.9):
        super(SarsaLambdaTable, self).__init__(actions, learningRate, rewardDecay, greedyPolicy)
        self.lambda_ = traceDecay # 步数的衰减值
        self.eligibilityTrace = self.qTable.copy() # 矩阵Eligibility Trace

    def checkStateExists(self, state): # 检查状态State是否存在
        if state not in self.qTable.index:
            toBeAppend = pd.Series([0] * len(self.actions), index=self.qTable.columns, name=state) # 若不存在，新增一列
            self.qTable = self.qTable.append(toBeAppend) # 更新Q表
            self.eligibilityTrace = self.eligibilityTrace.append(toBeAppend) # 更新E表

    def learn(self, s, a, r, s_, a_):
        self.checkStateExists(s_)
        qPred = self.qTable.loc[s, a] # 预测Q值
        if s_ != 'terminated':
            qTarget = r + self.gamma * self.qTable.loc[s_, a_] # 计算实际Q值
        else:
            qTarget = r
        error = qTarget - qPred # 计算实际值和预测值的差值
        # Method 1
        #self.eligibilityTrace.loc[s, a] += 1
        # Method 2
        self.eligibilityTrace.loc[s, :] *= 0
        self.eligibilityTrace.loc[s, a] = 1
        self.qTable += self.lr * error * self.eligibilityTrace # 更新Q表
        self.eligibilityTrace *= self.gamma * self.lambda_ # 更新E表

def update():
    for episode in range(100):
        stepCounter = 0
        observation = env.reset()
        action = RL.chooseAction(str(observation))
        while True:
            env.render()
            observation_, reward, isDone = env.step(action)
            action_ = RL.chooseAction(str(observation_))
            RL.learn(str(observation), action, reward, str(observation_), action_)
            observation = observation_
            action = action_
            stepCounter += 1
            if isDone:
                break
        if reward == 1:
            print('[+] Success! Episode %s: total_steps = %s' % (episode + 1, stepCounter))
        elif reward == -1:
            print('[!] Failed... Episode %s: total_steps = %s' % (episode + 1, stepCounter))
    print('[*] Done')
    env.destroy()
...
```

学习效果（收敛较慢）：

```bash
$ ./Sarsa-lambda.py
[!] Failed... Episode 1: total_steps = 6
[!] Failed... Episode 2: total_steps = 27
[!] Failed... Episode 3: total_steps = 43
[+] Success! Episode 4: total_steps = 230
[!] Failed... Episode 5: total_steps = 190
[+] Success! Episode 6: total_steps = 40
[+] Success! Episode 7: total_steps = 52
[+] Success! Episode 8: total_steps = 155
[+] Success! Episode 9: total_steps = 46
[+] Success! Episode 10: total_steps = 44
[+] Success! Episode 11: total_steps = 32
[+] Success! Episode 12: total_steps = 21
...
[+] Success! Episode 64: total_steps = 8
[+] Success! Episode 65: total_steps = 8
[+] Success! Episode 66: total_steps = 6
[+] Success! Episode 67: total_steps = 6
...
```

# [Deep Q Network（DQN）](https://blog.csdn.net/qq_30615903/article/details/80744083)

由于在大量状态和行为的情况下，Q Learning 等一系列基于价值的算法不能很好地进行学习，衍生出了一种和神经网络结合的算法。

$$
\begin{array}{l}
Initialize\ replay\ memory\ D\ to\ capacity\ N\\\
Initialize\ action-value\ function\ Q\ with\ random\ weights\ \theta\\\
Initialize\ target\ action-value\ function\ \hat{Q}\ with\ weights\ \theta^-=\theta\\\
For\ episode=1,M\ do\\\
\quad Initialize\ sequence\ s_1=\{x_1\}\ and\ preprocessed\ sequence\ \phi_1=\phi(s_1)\\\
\quad For\ t=1,T\ do\\\
\quad\quad With\ probability\ \varepsilon\ select\ a\ random\ action\ a_t\\\
\quad\quad otherwise\ select\ a_t=argmax_aQ(\phi(s_t),a;\theta)\\\
\quad\quad Execute\ action\ a_t\ in\ emulator\ and\ observe\ reward\ r_t\ and image\ x_{t+1}\\\
\quad\quad Set\ s_{t+1}=s_t,a_t,x_{t+1}\ and\ preprocess\ \phi_{t+1}=\phi(s_{t+1})\\\
\quad\quad Store\ transition\ (\phi_t,a_t,r_t,\phi_{t+1})\ in\ D\\\
\quad\quad Sample\ random\ minibatch\ of\ transitions\ (\phi_j,a_j,r_j,\phi_{j+1})\ from\ D\\\
\quad\quad Set\ y_j=\begin{cases}r_j, & if\ episode\ terminates\ at\ step\ j+1\\\ r_j+\gamma max_{a'}\hat{Q}(\phi_{j+1},a';\phi^-), & otherwise\end{cases}\\\
\quad\quad Perform\ a\ gradient\ descent\ step\ on\ (y_j-Q(\phi(j),a_j;\theta))^2\ with\ respect\ to\ the\\\
\quad\quad network\ paramters\ \theta\\\
\quad\quad Every\ C\ steps\ reset\ \hat{Q}=Q\\\
\quad End\ For\\\
End\ For
\end{array}
$$

> PS：下面公式中的 $max_a$ 均表示 $max_{a'}$，不知道为什么 MathJax 不能正常显示下面带单引号的公式（在中括号 $[]$ 之间的部分）。有了解的师傅欢迎联系我。

定义：

$$
Q^*=\max_{\pi}\mathbb{E}[\sum_{t=0}^{+\infty}\vert\gamma^tr_t\vert s_0=s,a_0=a,\pi]
$$

则有 Bellman Equation：

$$
Q^\*(s,a)=\mathbb{E}_{s'\sim\varepsilon}[r+\gamma max_aQ^*(s',a')\vert s,a]
$$

用深度神经网络来模拟 $Q^\*(s,a)$，其中 $\theta$ 为权重：

$$
Q(s,a;\theta)\approx Q^\*(s,a)
$$

根据 Bellman Equation 得出以下神经网络：

- 前向计算：$L_i(\theta_i)=\mathbb{E}_{s,a\sim\rho(\cdot)}[(y_i-Q(s,a;\theta_i))^2]$，其中 $y_i=\mathbb{E}_{s'\sim\epsilon}[r+\gamma max_aQ(s',a';\theta_{i-1})\vert s,a]$；
- 后向传播：$\nabla_{\theta_i}L_i(\theta_i)=\mathbb{E}_{s,a\sim\rho(\cdot);s'\sim\varepsilon}[r+\gamma max_aQ(s',a';\theta_{i-1})-Q(s,a;\theta_i)\nabla_{\theta_i}Q(s,a;\theta_i)]$。

TODO

![](/pics/Reinforcement-Learning/1.png)

## Programming

利用 OpenAI 的 gym 库对 DQN 进行测试：

```python
#!/usr/bin/env python3
import numpy as np
import pandas as pd
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()
import gym
import matplotlib.pyplot as plt

class DeepQNetwork:
    def __init__(self, nActions, nFeatures, learningRate=0.01, rewardDecay=0.9, eGreedy=0.9, replaceTargetIter=300, memorySize=500, batchSize=32, eGreedyIncrement=None, outputGraph=False):
        self.nActions = nActions # 动作数
        self.nFeatures = nFeatures # 神经网络的特征数
        self.lr = learningRate # 学习率
        self.gamma = rewardDecay # 奖励衰减项
        self.epsilonMax = eGreedy # 贪婪系数最大值
        self.replaceTargetIter = replaceTargetIter # 更新targetNet的步数
        self.memorySize = memorySize # 用于记忆的数据数量
        self.batchSize = batchSize # Batch大小
        self.epsilonIncrement = eGreedyIncrement # 贪婪系数变化率
        self.epsilon = 0 if eGreedyIncrement is not None else self.epsilonMax # 贪婪系数
        self.learnStepCounter = 0 # 记录学习的步数
        self.memory = np.zeros((self.memorySize, nFeatures * 2 + 2)) # 创建存储空间
        self.buildNet() # 建立网络
        tParams = tf.get_collection('targetNetParams') # 获取targetNet中的参数
        eParams = tf.get_collection('evalNetParams') # 获取evalNet中的参数
        self.replaceTargetOp = [tf.assign(t, e) for t, e in zip(tParams, eParams)] # 将targetNet中的参数替换为evalNet中的参数
        self.sess = tf.Session()
        if outputGraph:
            tf.summary.FileWriter('log/', self.sess.graph)
        self.sess.run(tf.global_variables_initializer()) # 激活变量
        self.costHis = [] # 记录误差

    def buildNet(self):
        # Build evalNet
        self.s = tf.placeholder(tf.float32, [None, self.nFeatures], name='s') # 输入1：当前的状态State
        self.qTarget = tf.placeholder(tf.float32, [None, self.nActions], name='qTarget') # 输入2：现实Q值
        with tf.variable_scope('evalNet'):
            cNames = ['evalNetParams', tf.GraphKeys.GLOBAL_VARIABLES] # 用于收集evalNet中所有的参数
            nL1 = 10 # 第一层神经元个数
            wInitializer = tf.random_normal_initializer(0., 0.3) # 随机生成权重
            bInitializer = tf.constant_initializer(0.1) # 随机生成偏置

            with tf.variable_scope('l1'): # 第一层
                w1 = tf.get_variable('w1', [self.nFeatures, nL1], initializer=wInitializer, collections=cNames) # 权重
                b1 = tf.get_variable('b1', [1, nL1], initializer=bInitializer, collections=cNames) # 偏置
                l1 = tf.nn.relu(tf.matmul(self.s, w1) + b1) # 激励函数使用ReLU

            with tf.variable_scope('l2'): # 第二层
                w2 = tf.get_variable('w2', [nL1, self.nActions], initializer=wInitializer, collections=cNames) # 权重
                b2 = tf.get_variable('b2', [1, self.nActions], initializer=bInitializer, collections=cNames) # 偏置
                self.qEval = tf.matmul(l1, w2) + b2 # 估计的Q值
        with tf.variable_scope('loss'):
            self.loss = tf.reduce_mean(tf.squared_difference(self.qTarget, self.qEval))
        with tf.variable_scope('train'):
            self.trainOp = tf.train.RMSPropOptimizer(self.lr).minimize(self.loss)

        # Build targetNet
        self.s_ = tf.placeholder(tf.float32, [None, self.nFeatures], name='s_') # 输入1：下一个状态State
        with tf.variable_scope('targetNet'):
            cNames = ['targetNetParams', tf.GraphKeys.GLOBAL_VARIABLES] # 用于收集targetNet中所有的参数

            with tf.variable_scope('l1'): # 第一层
                w1 = tf.get_variable('w1', [self.nFeatures, nL1], initializer=wInitializer, collections=cNames) # 权重
                b1 = tf.get_variable('b1', [1, nL1], initializer=bInitializer, collections=cNames) # 偏置
                l1 = tf.nn.relu(tf.matmul(self.s_, w1) + b1) # 激励函数使用ReLU

            with tf.variable_scope('l2'): # 第二层
                w2 = tf.get_variable('w2', [nL1, self.nActions], initializer=wInitializer, collections=cNames) # 权重
                b2 = tf.get_variable('b2', [1, self.nActions], initializer=bInitializer, collections=cNames) # 偏置
                self.qNext = tf.matmul(l1, w2) + b2 # 估计的Q值

    def storeTransition(self, s, a, r, s_):
        if not hasattr(self, 'memoryCounter'):
            self.memoryCounter = 0
        transition = np.hstack((s, [a, r], s_))
        idx = self.memoryCounter % self.memorySize
        self.memory[idx, :] = transition
        self.memoryCounter += 1

    def chooseAction(self, observation): # 选择行为Action
        observation = observation[np.newaxis, :] # 变成二维矩阵便于处理
        if np.random.rand() < self.epsilon:
            actionsValue = self.sess.run(self.qEval, feed_dict={self.s: observation}) # 放入evalNet中分析计算行为的值
            action = np.argmax(actionsValue) # 选择值最大的行为Action
        else:
            action = np.random.randint(0, self.nActions) # 10%的概率随机选择行为Action
        return action

    def learn(self):
        if self.learnStepCounter % self.replaceTargetIter == 0: # 判断学习之前是否需要替换参数
            self.sess.run(self.replaceTargetOp)
            print('[+] Target params replaced.')
        if self.memoryCounter > self.memorySize: # 判断存储空间中的数据数量
            sampleIdx = np.random.choice(self.memorySize, size=self.batchSize)
        else:
            sampleIdx = np.random.choice(self.memoryCounter, size=self.batchSize)
        batchMemory = self.memory[sampleIdx, :] # 获取一部分数据作为Batch
        qNext, qEval = self.sess.run([self.qNext, self.qEval], feed_dict={self.s_: batchMemory[:, -self.nFeatures:], self.s: batchMemory[:, :self.nFeatures]}) # 分别计算当前状态和下一状态的Q值
        qTarget = qEval.copy() #
        batchIdx = np.arange(self.batchSize, dtype=np.int32)
        evalActIdx = batchMemory[:, self.nFeatures].astype(int)
        reward = batchMemory[:, self.nFeatures + 1]
        qTarget[batchIdx, evalActIdx] = reward + self.gamma * np.max(qNext, axis=1)
        _, self.cost = self.sess.run([self.trainOp, self.loss], feed_dict={self.s: batchMemory[:, :self.nFeatures], self.qTarget: qTarget}) # 计算误差值
        self.costHis.append(self.cost) # 存储误差值
        self.epsilon = self.epsilon + self.epsilonIncrement if self.epsilon < self.epsilonMax else self.epsilonMax # 更新贪婪系数
        self.learnStepCounter += 1

    def plotCost(self): # 展示误差
        plt.plot(np.arange(len(self.costHis)), self.costHis)
        plt.ylabel('Cost')
        plt.xlabel('Training Steps')
        plt.show()

if __name__ == '__main__':
    env = gym.make('CartPole-v0')
    print(env.action_space)
    print(env.observation_space)
    print(env.observation_space.high)
    print(env.observation_space.low)
    totalStep = 0
    RL = DeepQNetwork(nActions=env.action_space.n, nFeatures=env.observation_space.shape[0], learningRate=0.01, eGreedy=0.9, replaceTargetIter=100, memorySize=2000, eGreedyIncrement=0.001)
    for episode in range(100):
        observation = env.reset() # 获取第一个状态
        episodeReward = 0
        while True:
            env.render()
            action = RL.chooseAction(observation) # 选择行为Actor
            observation_, reward, isDone, info = env.step(action) # 获取执行行为后得到的相关信息
            x, xDot, theta, thetaDot = observation_
            r1 = (env.x_threshold - abs(x)) / env.x_threshold - 0.8 # 根据离画面中心距离判断奖励值
            r2 = (env.theta_threshold_radians - abs(theta)) / env.theta_threshold_radians - 0.5 # 根据杆子偏离度判断奖励值
            reward = r1 + r2 # 替换奖励值
            RL.storeTransition(observation, action, reward, observation_) # 存储步骤
            episodeReward += reward # 更新奖励值
            if totalStep > 1000:
                RL.learn() # 学习
            if isDone:
                print('[+] episode: {}, episodeReward: {}, epsilon: {}'.format(episode, episodeReward, RL.epsilon)) # 输出
                break
            observation = observation_
            totalStep += 1
    RL.plotCost() # 绘制误差图
```

学习效果，最终会收敛到最合适的 $\varepsilon$ 对应的值：

```bash
$ ./DQN.py
...
Discrete(2)
Box(4,)
[4.8000002e+00 3.4028235e+38 4.1887903e-01 3.4028235e+38]
[-4.8000002e+00 -3.4028235e+38 -4.1887903e-01 -3.4028235e+38]
...
[+] episode: 0, episodeReward: 8.962128355556148, epsilon: 0
[+] episode: 1, episodeReward: 5.262074725675638, epsilon: 0
[+] episode: 2, episodeReward: 4.771817696346831, epsilon: 0
[+] episode: 3, episodeReward: 3.6815099553712423, epsilon: 0
[+] episode: 4, episodeReward: 2.0117216279281562, epsilon: 0
[+] episode: 5, episodeReward: 14.986124067404067, epsilon: 0
[+] episode: 6, episodeReward: 5.049683281727361, epsilon: 0
...
[+] episode: 50, episodeReward: 7.6161165056296385, epsilon: 0
[+] episode: 51, episodeReward: 7.366432746086161, epsilon: 0
[+] Target params replaced.
[+] episode: 52, episodeReward: 12.517630447631952, epsilon: 0.009000000000000001
[+] episode: 53, episodeReward: 3.090222284801366, epsilon: 0.022000000000000013
[+] episode: 54, episodeReward: 4.435946584693391, epsilon: 0.04300000000000003
[+] episode: 55, episodeReward: 5.469698721962921, epsilon: 0.07000000000000005
[+] episode: 56, episodeReward: 2.2975027875220384, epsilon: 0.08500000000000006
[+] Target params replaced.
[+] episode: 57, episodeReward: 3.042176076066822, epsilon: 0.10700000000000008
[+] episode: 58, episodeReward: 18.75897216435803, epsilon: 0.1480000000000001
...
[+] Target params replaced.
[+] episode: 97, episodeReward: 112.18733630622428, epsilon: 0.9
[+] Target params replaced.
[+] Target params replaced.
[+] episode: 98, episodeReward: 126.81607918996532, epsilon: 0.9
[+] Target params replaced.
[+] Target params replaced.
[+] episode: 99, episodeReward: 126.65358872838634, epsilon: 0.9
```

误差趋势图：

![](/pics/Reinforcement-Learning/2.png)

# [Policy Gradience](https://blog.csdn.net/qq_30615903/article/details/80747380)

$$
\begin{array}{l}
Initialize\ \theta\ arbitrarily\\\
For\ each\ episode\ \{s_1,a_1,r_2,\cdots,s_{T-1},a_{T-1},r_T\}\sim\pi do\\\
\quad For\ t=1\ to\ T-1\ do\\\
\quad\quad \theta\leftarrow+\alpha\nabla_\theta\log\pi_\theta(s_t,a_t)v_t\\\
\quad End\ For\\\
End\ For
\end{array}
$$

Policy Gradience 主要思想：在每一个状态下，根据现有 $P(a_t,s_t)$ 采样 $a_t$，如此往复，获得一组状态-行为对：$s_1,a_1,s_2,a_2,\cdots,s_T$，此时获得最终的奖励函数 $r_T$，这里我们假设 $r_T$ 可取正负值，其中正值表示获得奖励，负值表示获得惩罚。最终可以根据 $r_T$ 去修改每一步的 $P(a_t,s_t)$：

$$
P(a_t\vert s_t)=P(a_t\vert s_t)+\alpha r_T
$$

如果 $P(a_t\vert s_t)\sim Q(s_t,a_t,\theta)$，则有：

$$
\theta=\theta+\alpha r_t\nabla_\theta Q(s_t,a_t,\theta)
$$

Policy Gradience 的改进：上述算法的缺点是，我们需要非常精确地设置 $r_T$ 的值，否则很可能出现 $P$ 一直上涨或一直下降。一个主要的改进如下：

$$
\begin{array}{cc}
P(a_t\vert s_t)=P(a_t\vert s_t)+\alpha(r_T-V(s_t))\\\
\theta=\theta+\alpha(r_T-V(s_t))\nabla_\theta Q(s_t,a_t,\theta)
\end{array}
$$

$V(s)$ 是估值函数：

$$
V(s)=\mathbb{E}[\sum_{t≥0}\gamma^tr_t\vert s_0=s,\pi]
$$

它代表了在 $t$ 时刻对最终 Reward 的估计（可以采用深度神经网络求 $V(s)=V(s,\theta)$）。

![](/pics/Reinforcement-Learning/3.png)

## Programming

利用 Policy Gradient 实现对 GYM 库中 CartPole 游戏的学习：

```python
#!/usr/bin/env python3
import numpy as np
import pandas as pd
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()
import gym
import matplotlib.pyplot as plt

DISPLAY_REWARD_THRESHOLD = 400 # renders environment if total episode reward is greater then this threshold
RENDER = False # rendering wastes time

class PolicyGradient:
    def __init__(self, nActions, nFeatures, learningRate=0.01, rewardDecay=0.95, outputGraph=False):
        self.nActions = nActions
        self.nFeatures = nFeatures
        self.lr = learningRate
        self.gamma = rewardDecay
        self.episodeObs, self.episodeAs, self.episodeRs = [], [], []
        self.buildNet()
        self.sess = tf.Session()
        if outputGraph:
            tf.summary.FileWriter('log/', self.sess.graph)
            print('[+] TensorBoard built successfully')
        self.sess.run(tf.global_variables_initializer())

    def buildNet(self): # 建立神经网络
        with tf.name_scope('inputs'):
            self.tfObs = tf.placeholder(tf.float32, [None, self.nFeatures], name='observations')
            self.tfActs = tf.placeholder(tf.int32, [None], name='actionsNum')
            self.tfVt = tf.placeholder(tf.float32, [None], name='actionsValue')
        # fc1
        layer = tf.layers.dense(inputs=self.tfObs, units=10, activation=tf.nn.tanh, kernel_initializer=tf.random_normal_initializer(mean=0, stddev=0.3), bias_initializer=tf.constant_initializer(0.1), name='fc1') # 全连接层
        allAct = tf.layers.dense(inputs=layer, units=self.nActions, activation=None, kernel_initializer=tf.random_normal_initializer(mean=0, stddev=0.3), bias_initializer=tf.constant_initializer(0.1), name='fc2') # 全连接层
        self.allActProb = tf.nn.softmax(allAct, name='actProb') # 求出行为对应的概率

        with tf.name_scope('loss'): # 计算误差
            negLogProb = tf.nn.sparse_softmax_cross_entropy_with_logits(logits=allAct, labels=self.tfActs)
            #negLogProb = tf.reduce_sum(-tf.log(self.allActProb) * tf.one_hot(self.tfActs, self.tfActs), axis=1) # 将目标函数修改为对最小值的求解
            loss = tf.reduce_mean(negLogProb * self.tfVt)

        with tf.name_scope('train'):
            self.trainOp = tf.train.AdamOptimizer(self.lr).minimize(loss)

    def chooseAction(self, observation): # 选择行为
        probWeights = self.sess.run(self.allActProb, feed_dict={self.tfObs: observation[np.newaxis, :]}) # 获取概率
        action = np.random.choice(range(probWeights.shape[1]), p=probWeights.ravel()) # 通过概率选择行为
        return action

    def storeTransition(self, s, a, r): # 存储回合
        self.episodeObs.append(s)
        self.episodeAs.append(a)
        self.episodeRs.append(r)

    def learn(self): # 学习更新参数
        discountedEpRsNorm = self.discountAndNormRewards()
        self.sess.run(self.trainOp, feed_dict={self.tfObs: np.vstack(self.episodeObs), self.tfActs: np.array(self.episodeAs), self.tfVt: discountedEpRsNorm}) # 训练
        self.episodeObs, self.episodeAs, self.episodeRs = [], [], [] # 清空存储空间
        return discountedEpRsNorm

    def discountAndNormRewards(self): # 衰减回合奖励
        discountedEpRs = np.zeros_like(self.episodeRs)
        runningAdd = 0
        for t in reversed(range(len(self.episodeRs))):
            runningAdd = runningAdd * self.gamma + self.episodeRs[t]
            discountedEpRs[t] = runningAdd
        # 数据归一化
        discountedEpRs -= np.mean(discountedEpRs)
        discountedEpRs /= np.std(discountedEpRs)
        return discountedEpRs

if __name__ == '__main__':
    env = gym.make('CartPole-v0')
    env.seed(1) # reproducible, general Policy gradient has high variance
    env = env.unwrapped
    RL = PolicyGradient(nActions=env.action_space.n, nFeatures=env.observation_space.shape[0], learningRate=0.02, rewardDecay=0.99)
    for episode in range(3000):
        observation = env.reset()
        while True:
            if RENDER:
                env.render()
            action = RL.chooseAction(observation)
            observation_, reward, isDone, info = env.step(action)
            RL.storeTransition(observation, action, reward) # 存储当前回合
            if isDone:
                episodeRsSum = sum(RL.episodeRs)
                if 'runningReward' not in globals():
                    runningReward = episodeRsSum
                else:
                    runningReward = runningReward * 0.99 + episodeRsSum * 0.01 # 更新奖励
                if runningReward > DISPLAY_REWARD_THRESHOLD: # 训练到一定程度
                    RENDER = True
                print('[+] episode: {}, reward: {}'.format(episode, runningReward))
                vt = RL.learn()
                if episode == 0:
                    plt.plot(vt) # 绘制回合奖励图
                    plt.xlabel('Episode Steps')
                    plt.ylabel('Normalized State-action value')
                    plt.show()
                break
            observation = observation_
```

学习效果：

```bash
$ $ ./Policy-Gradient.py
...
[+] episode: 0, reward: 20.0
[+] episode: 1, reward: 19.990000000000002
[+] episode: 2, reward: 20.210100000000004
[+] episode: 3, reward: 20.127999000000006
[+] episode: 4, reward: 20.116719010000008
[+] episode: 5, reward: 20.105551819900008
[+] episode: 6, reward: 20.214496301701008
[+] episode: 7, reward: 20.142351338683998
...
[+] episode: 107, reward: 332.15535489983097
[+] episode: 108, reward: 341.05380135083266
[+] episode: 109, reward: 388.9932633373243
[+] episode: 110, reward: 390.75333070395106
[+] episode: 111, reward: 446.6457973969116
...
```

![](/pics/Reinforcement-Learning/4.png)

# [Actor-Critic（基于概率和价值）](https://blog.csdn.net/qq_30615903/article/details/80774384)

$$
\begin{array}{l}
Input:\ a\ differentiable\ policy\ parameterization\ \pi(a\vert s,\theta)\\\
Input:\ a\ differentiable\ policy\ parameterization\ \hat{v}(s,\omega)\\\
Algorithm\ parameters:\ trace-decay\ rates\ \gamma^\theta\in[0,1],\gamma^\omega\in[0,1];\ step\ sizes\ \alpha^\theta>0,\alpha^\omega>0\\\
Initialize\ policy\ parameter\ \theta\in\mathbb{R}^{d'}\ and\ state-value\ weights\ \omega\in\mathbb{R}^d\ (e.g.,\ to\ 0)\\\
Loop\ forever\ (for\ each\ episode):\\\
\quad Initialize\ S\ (first\ state\ of\ episode)\\\
\quad z^\theta\leftarrow0(d'-component\ eligibility\ trace\ vector)\\\
\quad z^\omega\leftarrow0(d-component\ eligibility\ trace\ vector)\\\
\quad I\leftarrow0\\\
Loop\ while\ S\ is\ not\ terminal\ (for\ each\ time\ step):\\\
\quad\quad A\sim\pi(\cdot\vert S,\theta)\\\
\quad\quad Take\ action\ A,\ observe\ S',R\\\
\quad\quad \delta\leftarrow R+\gamma\hat{v}(S',\omega)-\hat{v}(S,\omega)\\\
\quad\quad z^\omega\leftarrow\gamma\lambda^\omega z^\omega+I\nabla_\omega\hat{v}(S,\omega)\\\
\quad\quad z^\theta\leftarrow\gamma\lambda^\theta z^\theta+I\nabla_\theta\ln\pi(A\vert S,\theta) \\\
\quad\quad \omega\leftarrow\omega+\alpha^\omega\delta z^\omega \\\
\quad\quad \theta\leftarrow\theta+\alpha^\theta\delta z^\theta \\\
\quad\quad I\leftarrow\gamma I \\\
\quad\quad S\leftarrow S' \\\
\end{array}
$$

Actor-Critic 算法分为两部分，Actor 的前身是 Policy Gradient，可以在连续动作空间内选择合适的动作，由于 Actor 基于回合更新的所以学习效率比较慢；基于价值的 Q Learning 作为 Critic 的算法实现单步更新，对 Actor 的行为进行评分，Actor 再根据评分修改行为的概率。

## Shortcomings

Actor 的行为取决于 Critic 的 Value，但因为 Critic 本身就很难收敛和 Actor 一起更新的话就更难收敛了。

## Programming

使用 Actor-Critic 算法对游戏 CartPole 进行学习：

```python
#!/usr/bin/env python3
import numpy as np
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()
import gym

OUTPUT_GRAPH = False
MAX_EPISODE = 3000
DISPLAY_REWARD_THRESHOLD = 200
MAX_EP_STEPS = 1000
RENDER = False
GAMMA = 0.9 # 贪婪系数
LR_A = 0.001 # Learning Rate of Actor
LR_C = 0.01 # Learning Rate of Critic

class Actor(object):
    def __init__(self, sess, nFeatures, nActions, lr=0.001):
        self.sess = sess
        self.s = tf.placeholder(tf.float32, [1, nFeatures], 'state') # 输入1：状态
        self.a = tf.placeholder(tf.int32, None, 'act') # 输入2：动作
        self.tdError = tf.placeholder(tf.float32, None, 'tdError') # 输入3：奖励

        with tf.variable_scope('Actor'):
            l1 = tf.layers.dense(inputs=self.s, units=20, activation=tf.nn.relu, kernel_initializer=tf.random_normal_initializer(0., .1), bias_initializer=tf.constant_initializer(0.1), name='l1') # 第一层
            self.actsProb = tf.layers.dense(inputs=l1, units=nActions, activation=tf.nn.softmax, kernel_initializer=tf.random_normal_initializer(0., .1), bias_initializer=tf.constant_initializer(0.1), name='actsProb') # 第二层输出每个动作的概率

        with tf.variable_scope('expV'):
            logProb = tf.log(self.actsProb[0, self.a])
            self.expV = tf.reduce_mean(logProb * self.tdError) # loss

        with tf.variable_scope('train'):
            self.trainOp = tf.train.AdamOptimizer(lr).minimize(-self.expV) # min(expV) = max(-expV)

    def learn(self, s, a, td): # 学习
        s = s[np.newaxis, :]
        feed_dict = {self.s: s, self.a: a, self.tdError: td}
        _, expV = self.sess.run([self.trainOp, self.expV], feed_dict)
        return expV

    def chooseAction(self, s): # 选择行为
        s = s[np.newaxis, :]
        probs = self.sess.run(self.actsProb, {self.s: s})
        return np.random.choice(np.arange(probs.shape[1]), p=probs.ravel())

class Critic(object):
    def __init__(self, sess, nFeatures, lr=0.01):
        self.sess = sess
        self.s = tf.placeholder(tf.float32, [1, nFeatures], 'state') # 输入1：当前状态
        self.v_ = tf.placeholder(tf.float32, [1, 1], 'vNext') # 输入2：下一个奖励折现值
        self.r = tf.placeholder(tf.float32, None, 'r') # 输入3：当前奖励

        with tf.variable_scope('Critic'):
            l1 = tf.layers.dense(inputs=self.s, units=20, activation=tf.nn.relu, kernel_initializer=tf.random_normal_initializer(0., .1), bias_initializer=tf.constant_initializer(0.1), name='l1') # 第一层
            self.v = tf.layers.dense(inputs=l1, units=1, activation=None, kernel_initializer=tf.random_normal_initializer(0., .1), bias_initializer=tf.constant_initializer(0.1), name='V') # 第二层

        with tf.variable_scope('squaredTDError'):
            self.tdError = self.r + GAMMA * self.v_ - self.v # 时间差分值的平方
            self.loss = tf.square(self.tdError) # loss

        with tf.variable_scope('train'):
            self.trainOp = tf.train.AdamOptimizer(lr).minimize(self.loss)

    def learn(self, s, r, s_): # 学习奖励机制
        s, s_ = s[np.newaxis, :], s_[np.newaxis, :]
        v_ = self.sess.run(self.v, {self.s: s_})
        tdError, _ = self.sess.run([self.tdError, self.trainOp], {self.s: s, self.v_: v_, self.r: r})
        return tdError # 返回给Actor

if __name__ == '__main__':
    env = gym.make('CartPole-v0')
    env.seed(1)
    env = env.unwrapped
    N_F = env.observation_space.shape[0]
    N_A = env.action_space.n
    sess = tf.Session()
    actor = Actor(sess, nFeatures=N_F, nActions=N_A, lr=LR_A)
    critic = Critic(sess, nFeatures=N_F, lr=LR_C)
    sess.run(tf.global_variables_initializer())
    if OUTPUT_GRAPH:
        tf.summary.FileWriter('log/', sess.graph)
    for episode in range(MAX_EPISODE):
        s = env.reset()
        t = 0
        trackR = []
        while True:
            if RENDER:
                env.render()
            a = actor.chooseAction(s) # 获取动作
            s_, r, isDone, info = env.step(a) # 执行动作
            if isDone:
                r = -20
            trackR.append(r) # 保存奖励值
            tdError = critic.learn(s, r, s_) # Critic学习奖励值
            actor.learn(s, a, tdError) # Actor根据tdError更新状态
            s = s_
            t += 1
            if isDone or t >= MAX_EP_STEPS:
                episodeRsSum = sum(trackR)
                if 'runningReward' not in globals():
                    runningReward = episodeRsSum
                else:
                    runningReward = runningReward * 0.95 + episodeRsSum * 0.05 # 更新此轮奖励
                if runningReward > DISPLAY_REWARD_THRESHOLD:
                    RENDER = True
                print('[+] episode: {}, reward: {}'.format(episode, runningReward))
                break
```

Actor-Critic 涉及到了两个神经网络，而且每次都是在连续状态中更新参数，每次参数更新前后都存在相关性，会导致神经网络只能片面的看待问题，甚至导致神经网络学不到东西。所以这里学习的速度不是很快，而且起伏较大，很难收敛：

```bash
$ ./Actor-Critic.py
...
[+] episode: 0, reward: -7.0
[+] episode: 1, reward: -6.8
[+] episode: 2, reward: -6.01
[+] episode: 3, reward: -6.059499999999999
[+] episode: 4, reward: -6.156524999999999
[+] episode: 5, reward: -6.1486987499999985
[+] episode: 6, reward: -6.0912638124999985
[+] episode: 7, reward: -6.336700621874998
[+] episode: 8, reward: -6.569865590781248
...
[+] episode: 169, reward: 153.89380890618554
[+] episode: 170, reward: 152.09911846087627
[+] episode: 171, reward: 151.84416253783243
[+] episode: 172, reward: 160.05195441094082
[+] episode: 173, reward: 202.04935669039378
```

# References

浙江大学信电学院《机器学习》课程
[Deep Reinforcement Learning: Pong from Pixels](http://karpathy.github.io/2016/05/31/rl/?_utm_source=1-2-2)
[Reiforcement Learning - 莫烦 Python](https://mofanpy.com/tutorials/machine-learning/reinforcement-learning/)
