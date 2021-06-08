---
title: 不同版本Android动态调试前打开调试开关简述
date: 2020-02-29 10:13:37
tags: [re, android]
---

手上有两台谷歌儿子，系统版本不同，开启动态调试的方法也不同。

<!-- more -->

# Intro

众所周知，最常规的方法就是在 AndroidManifest.xml 中的 application 标签中添加 `android:debuggable="true"` 字段，然后再回编译、签名、安装、然后进行动态调试。但这种方法实在太麻烦了。

网上还有另外一种修改 Android prop 的工具 [mprop](https://github.com/wpvsyou/mprop)，用来修改 `default.prop` 中的 `ro.debuggable` 字段为 1（默认为 0）。因为 Android 系统初始化时，init 进程会解析系统属性文件，然后将其保存到内存中去，以便给所有应用提供服务（这种方法可以直接调试所有应用），所以在 init 进程的内存块中是存在这些属性的。在修改完成后要重启 adbd 进程，但这种方法的缺点是在每次开关机后需要重新修改。

最好的方法是能够直接安装一个程序，能够直接开启所有程序的调试，并且在开关机后也不需要重新设置。

# Android 4

设备：Nexus 5

开启动态调试的要求是已 root，并且安装了 Xposed 框架。

## BDOpener

[BDOpener 下载链接](https://github.com/riusksk/BDOpener)

这里使用的是 BDOpener，这是一款 Xposed 的模块，用于修改程序的 debugable 选项，同时也支持开启备份选项，方便数据转移。只需要安装程序后，启用并重启手机，就能调试，可以用 monitor 来查看效果。

![](/pics/不同版本Android动态调试前打开调试开关简述/1.png)

# Android 9

设备：Pixel XL

开启动态调试的要求是安装了 Magisk 框架（安装后默认 root）。因为 Xposed 的作者在 Android 6 后没有再更新，后来 Android 7 只出了非官方版本，尝试采用了 Magisk+Taichi 的方式来使用上面的 Xposed 模块，但安装了之后发现 Android UI 会在开机之后崩溃，所以尝试了另外一种方法。

## [MagiskHidePropsConf](https://forum.xda-developers.com/apps/magisk/module-magiskhide-props-config-t3789228)

[MagiskHidePropsConf 下载链接](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf)

[Busybox 下载链接](https://github.com/osm0sis/android-busybox-ndk)

MagiskHidePropsConf 是 Magisk 下的一个模块，可以用来修改系统中内存里的 props 值，并且永久生效，那么就可以用来修改 `ro.debuggable` 字段了。同时要求安装 Busybox for Android NDK 才能运行。操作如下：

```sh
marlin:/ # props

Loading... Please wait.


MagiskHide Props Config v5.2.2
by Didgeridoohan @ XDA Developers

=====================================
 Updating fingerprints list
=====================================

Checking connection.
No connection.

MagiskHide Props Config v5.2.2
by Didgeridoohan @ XDA Developers

=====================================
 Select an option below.
=====================================

1 - Edit device fingerprint
2 - Device simulation (disabled)
3 - Edit MagiskHide props
4 - Add/edit custom props
5 - Delete prop values
6 - Script settings
7 - Collect logs
r - Reset all options/settings
b - Reboot device
e - Exit

See the module readme or the
support thread @ XDA for details.

Enter your desired option: 3

MagiskHide Props Config v5.2.2
by Didgeridoohan @ XDA Developers

=====================================
 MagiskHide props (active)
 Select an option below:
=====================================

Change the sensitive props set by MagiskHide.

1 - ro.debuggable
2 - ro.secure
3 - ro.build.type
4 - ro.build.tags
5 - ro.build.selinux
a - Change all props
b - Go back to main menu
e - Exit

Pick several options at once by
separating inputs with a comma.
Example: 1,5,6

See the module readme or the
support thread @ XDA for details.

Enter your desired option: 1

MagiskHide Props Config v5.2.2
by Didgeridoohan @ XDA Developers

=====================================
 ro.debuggable
=====================================

Currently set to 0.

You currently have the safe value set.
Are you sure you want to change it to 1?

Enter y(es), n(o) or e(xit): y

MagiskHide Props Config v5.2.2
by Didgeridoohan @ XDA Developers

=====================================
 Reboot - ro.debuggable
=====================================

Reboot for changes to take effect.

Do you want to reboot now (y/n)?

Enter y(es), n(o) or e(xit): y

Rebooting...
```

重启后也可以动态调了，同样可以用 monitor 来验证有没有成功。

## Magisk 命令

使用 Magisk 的命令也可以实现：

```bash
magisk resetprop ro.debuggable 1
stop; start; # 必须用这种方式重启
```

在调试的过程中发现在 Pixel 下如果开了调试会出现开发者选项无法打开的问题，暂时没有解决方法。

# References

https://ai-sewell.me/2018/%E6%89%93%E5%BC%80%E8%B0%83%E8%AF%95%E5%BC%80%E5%85%B3%E7%9A%84%E4%B8%89%E7%A7%8D%E6%96%B9%E6%B3%95/
https://bbs.pediy.com/thread-248322.htm
https://www.renyiwei.com/archives/1704.html
