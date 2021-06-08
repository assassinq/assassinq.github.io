---
title: 解决VMware下Ubuntu的一些问题
date: 2019-03-06 10:57:51
tags: [solution, linux]
---

记录一些在虚拟机上的问题。

<!-- more -->

# 0x0 更新出错（Sub-process returned an error code）

装了个优麒麟（Ubuntu Kylin），更新的时候居然报错了。

在 `sudo apt-get update` 后出现：

```shell
Aborted (core dumped)
Reading package lists... Done
E: Problem executing scripts APT::Update::Post-Invoke-Success 'if /usr/bin/test -w /var/cache/app-info -a -e /usr/bin/appstreamcli; then appstreamcli refresh > /dev/null; fi'
E: Sub-process returned an error code
```

大概跟一个安装包 `libappstream3` 有关，remove 掉就行了：

```shell
sudo apt-get remove libappstream3
```

# 0x1 无法显示图形化界面

```
**The system is running in low-graphics mode**
Your screen, graphics cards, and input device settings could not be detected correctly. You will need to configure these yourself.
```

装一下 vm 桌面，再更新一下磁盘：

```shell
sudo apt-get update
sudo apt-get install open-vm-tools
sudo apt-get install open-vm-tools-desktop
sudo reboot
sudo apt-get dist-upgrade
```

# 0x2 无法开机

```
intel_rapl: no valid rapl domains found in package 0
```

在 vmware 的 `.vmx` 文件中添加 `paevm = "TRUE"`。如果还不能解决，说明电脑的 cpu 不支持 PAE。直接在文件 `/etc/modprobe.d/blacklist.conf` 中添加 `blacklist intel_rapl` 后重启。

# 0x3 开机显示异常

```
piix4_smbus ****host smbus controller not enabled
```

在文件 `/etc/modprobe.d/blacklist.conf` 中添加 `blacklist piix4_smbus` 后重启。

# 0x4 开启后跳出提示框（Could not apply the stored configuration for monitors）

这个弹出窗口的意思是，不能应用当前显示器的设置，也就是显示器的设置有错误。在关机的时候，系统会保存上一次的设置，在 `$HOME/.config` 下生成一个 `monitors.xml` 的文件。只需要把这个文件删除即可：

```
sudo rm -rf ~/.config/monitors.xml
```

# 参考网站

https://blog.csdn.net/xiaxuesong666/article/details/77072770
https://askubuntu.com/questions/998318/the-system-is-running-in-low-graphics-mode-error-after-installing-vmware-tools
http://www.it610.com/article/3346432.htm
https://blog.csdn.net/think_embed/article/details/8805510
