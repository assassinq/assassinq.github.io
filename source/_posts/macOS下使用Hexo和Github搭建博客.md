---
title: macOS下使用Hexo和Github搭建博客
date: 2018-04-17 20:50:09
tags: [hexo, github, macos]
---

把双系统的 Win10 删了，改用 macOS。发现自己的博客忘记备份了，只好在 macOS 上重新搭建一个。

<!-- more -->

安装流程：

1. Hexo 是基于 Nodejs 的，需安装 Nodejs，安装 Nodejs 最好选择 Homebrew
2. 首先查看电脑是否安装 Ruby，因为 Homebrew 安装依赖 Ruby
3. 安装顺序：Homebrew->Nodejs->Hexo

# 安装 homebrew

```
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

# 安装 nodejs

```
brew install node
```

# 安装 hexo

```
sudo npm install -g hexo
# 可以加上 --registry=https://registry.npm.taobao.org
```

# 创建文件夹

```
mkdir blog
cd blog
hexo init
```

# 生成一套静态网页

```
hexo generate
hexo server
```

在 localhost 的 4000 端口上就能看到本地搭建的博客

# 撰写博客

```
hexo new post "balabala"
```

'balabala'即为博文的名字。

# 修改配置

```
deploy:
  type: git
  repo: https://github.com/xxx/xxx.github.io
  branch: master
```

直接在\_config.yml 中修改配置（xxx 为 github 的 name）

# 安装 hexo-deployer-git

```
npm install hexo-deployer-git --save
# 可以加上 --registry=https://registry.npm.taobao.org
```

# 同步 Github

```
hexo clean && hexo generate && hexo deploy
```

这样基础的搭建就完成啦！
