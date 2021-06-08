---
title: Windows下使用Hexo和Github搭建博客
date: 2017-11-18 22:12:54
tags: [windows, hexo, github]
---

记录下在 Windows 下搭建博客的步骤。

<!-- more -->

# 下载安装 git

[git 下载地址](https://gitforwindows.org/)

# 下载安装 node.js

[node.js 下载地址](https://nodejs.org/en/download/)

# github 账号注册和新建仓库

仓库名必须为“账户名.github.io”，勾选“Initialize this repository with a README”

# 安装 hexo

通过命令行输入

```
npm install hexo -g
# 可以加上 --registry=https://registry.npm.taobao.org
```

注：-g 是指全局安装 Hexo。

再输入

```
hexo -v
```

检测是否安装成功

# 初始化 Hexo

## 创建文件夹

根据个人爱好在本地创建博客文件夹，用于保存博客的本地文件

## 初始化

在 Hexo 文件下，右键运行 Git Bash，输入命令：

```
hexo init
```

初始化成功后生成的一系列文件，再输入：

```
npm install
# 可以加上 --registry=https://registry.npm.taobao.org
```

安装所需要的组件。

# 配置

在 `_config.yml`，进行基础配置。

# 本地浏览博客

分别输入如下命令：

```
hexo g
hexo s
```

在浏览器输入：`localhost:4000`，就可以对本地的博客进行访问。

# 写文章

在博客文件夹下输入：

```
hexo new post "xxx"
```

即能创建新博文，声称在 `_posts` 文件夹下，或是在 `_posts` 文件夹下，新建 `.md` 文件就可以写文章。

# ssh 设置

在博客文件夹下打开 Git Bash 后，分别输入：

```
git config --global user.name "你的名字"
```

和：

```
git config --global user.email "你的邮箱"
```

输入：

```
cd ~/.ssh
```

再输入：

```
ssh-keygen -t rsa -C "你的邮箱"
```

连续三个回车，生成密钥。再输入：

```
eval "$(ssh-agent -s)"
```

以添加密钥到 ssh-agent。再输入：

```
ssh-add ~/.ssh/id_rsa
```

添加生成的 SSH key 到 ssh-agent。然后登陆 github，点击头像下的 settings，添加一个新的 ssh，将 id_rsa.pub 文件里的内容复制上去。输入：

```
ssh -T git@github.com
```

如果出现“Hi 你的名字”，说明成功了。

## 假如 ssh-key 配置失败

首先，清除所有的 key-pair：

```
ssh-add -D
rm -r ~/.ssh
```

删除你在 github 中的 public-key。重新生成 ssh 密钥对：

```
ssh-keygen -t rsa -C "xxx@xxx.com"
```

# 部署到 Github

## 在 `_config.yml` 进行配置

···yml
type: git
repository: https://github.com/你的名字/你的名字.github.io
branch: master
···

## 安装 hexo-deployer-git 自动部署发布工具

```
npm install hexo-deployer-git --save
# 可以加上 --registry=https://registry.npm.taobao.org
```

# 发布到 Github

输入如下命令：

```
hexo clean && hexo g && hexo d
```

第一次发布需要验证 github 账号。浏览器打开“你的名字.github.io”，就是你的博客了。这样就完成了简单的搭建。
