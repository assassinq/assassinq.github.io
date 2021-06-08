---
title: 使用Termux在Android上打造小型Linux服务器
date: 2020-03-01 10:50:30
tags: [android]
---

使用 Termux 可以在 Android 上获得极佳的终端体验。

<!-- more -->

一些基础按键就不记录了。然后在 Termux 上的包管理工具有 pkg 和 apt，和 Debian 的基本一样，对我们来说已经很熟悉了。下面只是做一些简短的记录，用于备份。

# oh-my-zsh

在 Termux 手机界面上可以完美实现 oh-my-zsh 的 agnoster 主题，在 Github 上已经有人实现了对应的安装脚本：

```bash
sh -c "$(curl -fsSL https://github.com/Cabbagec/termux-ohmyzsh/raw/master/install.sh)"
```

具体的安装过程也不列举了，装完后会让我们选主题和字体。成功之后根目录下会有一个 storage 目录，映射了手机系统上的一些文件夹，方便文件传输：

```bash
$ ls -l storage
total 24
lrwxrwxrwx 1 u0_a146 u0_a146 26 Mar  1 12:45 dcim -> /storage/emulated/0/DCIM
lrwxrwxrwx 1 u0_a146 u0_a146 30 Mar  1 12:45 downloads -> /storage/emulated/0/Download
lrwxrwxrwx 1 u0_a146 u0_a146 30 Mar  1 12:45 movies -> /storage/emulated/0/Movies
lrwxrwxrwx 1 u0_a146 u0_a146 30 Mar  1 12:45 music -> /storage/emulated/0/Music
lrwxrwxrwx 1 u0_a146 u0_a146 30 Mar  1 12:45 pictures -> /storage/emulated/0/Pictures
lrwxrwxrwx 1 u0_a146 u0_a146 22 Mar  1 12:45 shared -> /storage/emulated/0
```

同样，我们可以给 QQ 的文件传输整一个软链接：

```bash
ln -s /data/data/com.termux/files/home/storage/shared/tencent/QQfile_recv QQ
```

如此一来，传输文件就方便了很多：

```bash
$ ls -al
...
lrwxrwxrwx 1 u0_a146 u0_a146   70 Mar  1 16:05 QQ -> /data/data/com.termux/files/home/storage/shared/tencent/QQfile_recv
...
```

还能修改启动时的问候语：

```bash
cp $PREFIX/etc/motd $PREFIX/etc/motd.bak
vim $PREFIX/etc/motd
```

![](/pics/使用Termux在Android上打造小型Linux服务器/1.png)

# Change apt-sources

给 apt 换个清华源：

```bash
export EDITOR=vi
apt edit-sources
```

修改为以下内容：

```txt
# The termux repository mirror from TUNA:
deb https://mirrors.tuna.tsinghua.edu.cn/termux stable main
```

# SSH

接下来装个 SSH，用电脑连上更方便地进行后续的安装。

```bash
apt update
apt upgrade
apt install openssh
```

将电脑的公钥 push 到手机上：

```bash
adb push ~/.ssh/id_rsa.pub /sdcard/authorized_keys
```

在 Termux 中把电脑公钥放在 `.ssh` 目录下，并设置 authorized_keys 文件为拥有者只读。最后启动服务：

```bash
cd .ssh
mv /sdcard/authorized_keys .
chmod 400 authorized_keys
sshd
```

在电脑上转发 adb 端口并连接：

```bash
adb forward tcp:8022 tcp:8022
ssh localhost -p 8022
```

# Python

Python 必不可少。默认 Python 指 Python3，Python2 指 Python2：

```bash
apt install python2
apt install python # python3
```

# IPython

IPython 的安装必须有 clang 的依赖，否则会报错：

```bash
apt install clang
pip install ipython
pip3.6 install ipython
```

# tsu

用 tsu 替代 su 可以完美实现 root 转换：

```bash
apt install tsu
```

![](/pics/使用Termux在Android上打造小型Linux服务器/2.png)

# MSF

需要联（ke）网（xue）下载：

```bash
apt install unstable-repo
apt install metasploit
```

输入 msfconsole 可以查看效果：

![](/pics/使用Termux在Android上打造小型Linux服务器/3.png)

这个版本也已经有 CVE-2019-0708 的 EXP 了：

![](/pics/使用Termux在Android上打造小型Linux服务器/4.png)

# Termux-API

其它很多软件像是 Nmap、SQLMap 等等，还有 Github 上的项目都基本和 Linux 中一模一样，可以用 apt 还有 pip 等管理器进行安装。下面记录一下 Termux-API 这一工具。首先要安装一下 [Termux:API](https://play.google.com/store/apps/details?id=com.termux.api) 这一 APP，然后用 apt 安装命令行：

```bash
apt install termux-api
```

获取电池信息：

```bash
$ termux-battery-status
{
  "health": "GOOD",
  "percentage": 100,
  "plugged": "PLUGGED_USB",
  "status": "FULL",
  "temperature": 22.700000762939453,
  "current": -38757
}
```

获取相机信息：

```bash
$ termux-camera-info
```

获取与设置剪切板：

```bash
$ termux-clipboard-set thisisassassinq
$ termux-clipboard-get
thisisassassinq
```

获取通讯录列表：

```bash
$ termux-contact-list
```

拨打电话：

```bash
$ termux-telephony-call 10001
```

获取当前 Wi-Fi 连接信息：

```bash
$ termux-wifi-connectioninfo
{
  "bssid": "02:00:00:00:00:00",
  "frequency_mhz": 2412,
  "ip": "192.168.101.68",
  "link_speed_mbps": 144,
  "mac_address": "02:00:00:00:00:00",
  "network_id": 0,
  "rssi": -53,
  "ssid": "<unknown ssid>",
  "ssid_hidden": true,
  "supplicant_state": "COMPLETED"
}
```

获取最近一次 Wi-Fi 扫描信息：

```bash
$ termux-wifi-scaninfo
```

# nyancat

彩虹猫是在 2011 年 4 月上传在 YouTube 的视频，并且迅速爆红于网络，并在 2011 年 YouTube 浏览量最高的视频中排名第五。这个视频内容为一只卡通的猫咪飞翔在宇宙中，身后拖出一条彩虹，并且配上了 UTAU 虚拟歌手桃音モモ所演唱的背景音乐。终端版本下载：

```bash
apt install nyancat
```

![](/pics/使用Termux在Android上打造小型Linux服务器/5.png)

# 终端二维码

生成终端二维码（字体没选好，效果不太好）：

```bash
echo "https://qianfei11.github.io" | curl -F-=\<- qrenco.de
```

![](/pics/使用Termux在Android上打造小型Linux服务器/6.png)

# References

https://mushuichuan.com/2017/12/10/termux/
http://blackwolfsec.cc/2016/12/10/termux/
https://www.sqlsec.com/2018/05/termux.html
