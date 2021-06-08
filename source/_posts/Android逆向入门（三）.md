---
title: Android逆向入门（三）
date: 2020-02-12 14:06:59
tags: [re, android]
---

记录 Jeb 插件编写、简单 Hook 以及 Android 系统结构简述。

<!-- more -->

# JEB 插件扩展

## 插件帮助文件

```
$JEB/doc/apidoc
```

## 插件编写

语言：Java/Python

```java
import jeb.api.IScript;
public class decJebString implemants IScript {
    private JebInstance jeb = null;
    @Override
    public void run(JebInstance jebInstance) {
        jeb = jebInstance;
        jeb.print("Hello World!!!");
    }
}
```

强制反编译结果，相当于 Ctrl+F5：

```java
import jeb.api.IScript;
public class decJebString implemants IScript {
    private static String targetSignature = "Lcom/pnfsoftware/jebglobal/decStr;->decodeString([BII)Ljava/lang/String;";
    private JebInstance jeb = null;
    @Override
    public void run(JebInstance jebInstance) {
        jeb = jebInstance;
        Dex dex = jeb.getDex();
        List<String> classSignatures = dex.getClassSignatures(true);
        int methodCount = dex.getMethodCount();
        String methodSig;
        for(int i = 0; i < methodCount; i++) {
            DexMethod dexMethod = dex.getMethod(i);
            int idx = dexMethod.getIndex();
            methodSig = dexMethod.getSignature(true);
            if(methodSig.equals(targetSignature)) {
                List<Integer> methodReferences = dex.getMethodReferences(idx); // 获取交叉引用
                for(Integer refIdx : methodReferences) {
                    DexMethod refDexMethod = dex.getMethod(refIdx);
                    jeb.decompileMethod(refDexMethod.getSignature(true));
                    ...
                }
            }
        }
        ...
    }
    ...
}
```

# Android 快速定位关键代码

- 字符串、特征字
- 关键 API 监控
- Hook 解密函数
- Monitor
- 插 Log 信息
  - `invoke-static {v0}, Lcom/android/killer/Log;->LogStr(Ljava/lang/String;)V`
- 动态调试

# 快速 Hook 代码

对函数进行挂钩，可以影响整个函数的执行。挂钩后，注入的代码可以接管整个函数，修改函数的参数，返回值，甚至整个函数的行为等。

## [Cydia Substrate](http://www.cydiasubstrate.com/)

只要知道类名就可以 Hook，而且属于系统全局属性，软件基本上不能检测到。

### Hook Java

1. 新建空项目
2. 导入 lib 文件 substrate-api.jar
3. 修改 AndroidManifest.xml 文件
4. 编写入口类
5. 安装激活插件，重启后可以看到插件效果

#### Example

修改 AndroidManifest.xml 文件：

```xml
<manifest>
    <application>
        ...
        <meta-data android:name="com.saurik.substrate.main" android:value="com.assassinq.cydiajavahook.CydiaMain"/>
        ...
    </application>
    <uses-permission android:name="cydia.permission.SUBSTRATE"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"></uses-permission>
</manifest>
```

编写入口类

```java
package com.assassinq.cydiajavahook;

import com.saurik.substrate.MS;

import java.lang.reflect.Method;

public class CydiaMain {
    static void initialize() {
        MS.hookClassLoad("android.content.res.Resources", new MS.ClassLoadHook() {
            @Override
            public void classLoaded(Class<?> resources) {
                Method getColor;
                try {
                    getColor = resources.getDeclaredMethod("getColor", Integer.TYPE);
                } catch (Exception e) {
                    getColor = null;
                }
                if (getColor != null) {
                    final MS.MethodPointer old = new MS.MethodPointer();
                    MS.hookMethod(resources, getColor, new MS.MethodHook() {
                        @Override
                        public Object invoked(Object res, Object... args) throws Throwable {
                            int color = (Integer) old.invoke(res, args);
                            return color & ~0xFFFFFF | 0x00AAAA;
                        }
                    }, old);
                }
            }
        });
    }
}
```

编写完成后，将程序安装到手机上，会弹出 Substrate extentions updated：

![](/pics/Android逆向入门/三/1.png)

点击进入 Cydia Substrate，点击 Restart System (Soft) 来重启系统：

![](/pics/Android逆向入门/三/2.png)

重启后发现系统某些部分的颜色已经被我们 Hook 成了其他颜色：

![](/pics/Android逆向入门/三/3.png)

在设置中打开更加明显：

![](/pics/Android逆向入门/三/4.png)

#### Java 反射

Java 可以通过反射方法去获取类以及它的成员。反射相当于提供一些函数，让我们在不知道原始累的定义的情况下，去修改类中相关的成员的属性、值等。

所有类都是继承自 Object 类的，所以都可以使用 Object 的方法。也可以强制转换为 Object。所有，遇到无法表示出来的对象时，直接用 Object 即可。

获取对象的类：

```java
Object obj = "123";
Class clazz = obj.getClass();
```

获取类中的方法（使用对应的不是以 s 为后缀的函数可以获取特定的函数或 field）：

```java
Method[] mPubMethods = clazz.getMethods(); // 获取公有可直接调用的方法
Method[] mDeclareMethods = clazz.getDeclareMethods(); // 获取类中声明的所有方法
Field[] mPubFields = clazz.getFields(); // 获取public的field
Field[] mDeclareFields = clazz.getDeclaredFields(); // 获取声明的所有field
```

方法调用：

```java
method.invoke(obj, arg)
```

域操作：

```java
field.set(obj, "1");
field.get(obj);
```

访问权限设置（域与方法都一样，控制是否可以直接访问，其实就是相当于 public 属性）：

```java
field.isAccessible();
field.setAccessible(true);
```

其余的函数，可以获取函数的名称，还有其他种种信息：

```java
field.getName();
field.toString();
Class.forName("android.view.Menu"); // 寻找类，必须是一个classloader下的才能使用
```

## Xposed

Xposed 是在程序启动的时候同时加载的，因此他的 Hook 是区分进程的。对于程序的类和参数可以通过名字来进行 Hook。Xposed 的 Hook 分为函数执行前和执行后两个位置，可以分别进行参数修改和结果修改。如果不想进行调用的话，可以在执行前使用 `setResult(NULL)` 函数。比起 Cydia 使用范围更加广泛，各种插件都是基于 Xposed 的，并且是开源的。

1. 新建基础项目
2. 导入 lib 文件 XposedBridgeApi-54.jar（compileOnly 模式，也就是不参与编译到最终文件中）
3. 修改 AndroidManifest.xml 文件
4. 入口类编写
5. 设置启动入口：在 assets 文件夹中，新建 xposed_init 文件，写入入口类的信息 com.assassinq.xposedjavahook.XposedMain
6. 安装激活插件，重启后可以看到插件效果

修改 app 下的 build.gradle 文件，将对应 lib/XposedBridgeApi-54.jar 的操作 implementation 修改成 compileOnly：

```gradle
...
dependencies {
    ...
    compileOnly files('lib/XposedBridgeApi-54.jar')
}
```

### Hook Java

修改 AndroidManifest.xml 文件：

```xml
<manifest>
    <application>
        ...
        <meta-data android:name="xposedmodule" android:value="true"/>
        <meta-data android:name="xposeddescription" android:value="Hook getColor"/>
        <meta-data android:name="xposedminversion" android:value="54"/>
    </application>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"></uses-permission>
</manifest>
```

入口类编写，新建一个类文件：

```java
public class XposedMain implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) throws Throwable {
//        if (param.packageName.equals("apk")) {
            try {
                findAndHookMethod("android.content.res.Resources", param.classLoader, "getColor", int.class, new myGetColor());
//                waitForDebugger();
            } catch (Exception e) {
                XposedBridge.log(e);
            }
//        }
    }
}

class myGetColor extends XC_MethodHook {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        Log.d("DEBUG", "Before Method Hook");
    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        Log.d("DEBUG", "After Method Hook");
        int res = (int) param.getResult();
        res = res & ~0xFFFFFF | 0x00AAAA;
        param.setResult(res);
    }
}
```

同样，编写完成后会弹出一个 Xposed module is not activated：

![](/pics/Android逆向入门/三/5.png)

点击后勾选我们编写的模块，并在 Framework 界面点击 Soft Reboot 以激活插件：

![](/pics/Android逆向入门/三/6.png)

重启后系统部分颜色同样被改变，但效果没有 Cydia 的好：

![](/pics/Android逆向入门/三/7.png)

### classLoader

与 Java 上的类似，就是一个类装载器。与 Java 不同的是，classLoader 所加载的就是 dex 文件本身。所以通过程序的 classLoader，可以取得程序的 dex 中所定义的所有类及其成员函数。同理，如果一个程序有多个 dex，那么会对应着多个 classLoader，特别是使用动态加载的 dex，则需要传递想要的 classLoader 才可以进行数据获取。

# Android 源码浅析

## Environment

Ubuntu 14.04

## 编译

首先搭建好 JDK 6 的环境：

```bash
cd && wget https://repo.huaweicloud.com/java/jdk/6u45-b06/jdk-6u45-linux-x64.bin
chmod +x jdk-6u45-linux-x64.bin && ./jdk-6u45-linux-x64.bin
cd /usr && sudo mkdir java
cd java && sudo mv ~/jdk1.6.0_45 .
vim ~/.bashrc
# export JAVA_HOME="/usr/java/jdk1.6.0_45"
# export JRE_HOME="$JAVA_HOME/jre"
# export CLASSPATH="$CLASSPATH:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar"
# export PATH="$PATH:$JAVA_HOME/bin"
source ~/.bashrc
java -version
```

然后安装一些编译时需要用到的依赖文件：

```bash
sudo apt-get update
sudo apt-get install git-core gnupg flex bison gperf build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev ccache libgl1-mesa-dev libxml2-utils xsltproc unzip
```

添加 51-android.rules，使得手机 USB 连接到 Ubuntu 能够被识别：

```bash
cd && wget https://raw.githubusercontent.com/M0Rf30/android-udev-rules/master/51-android.rules
sudo mv 51-android.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

接下来使用 repo 工具同步下载 Android 源码：

```bash
cd && mkdir bin # export PATH="$HOME/bin:$PATH"
curl https://mirrors.tuna.tsinghua.edu.cn/git/git-repo > ~/bin/repo
# curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo
export WORKING_DIRECTORY="android-4.4.3_r1"
mkdir $WORKING_DIRECTORY && cd $WORKING_DIRECTORY
git config --global user.name "Your Name"
git config --global user.email "your@example.com"
# export REPO_URL="https://aosp.tuna.tsinghua.edu.cn/android/git-repo"
# vim ~/bin/repo # REPO_URL = 'https://aosp.tuna.tsinghua.edu.cn/android/git-repo'
repo init -u https://aosp.tuna.tsinghua.edu.cn/platform/manifest -b android-4.4.3_r1
# repo init -u https://android.googlesource.com/platform/manifest -b android-4.4.3_r1
repo sync # Takes a very long time
# repo sync -c --no-clone-bundle --no-tags --prune -j4
```

同步完成后进行编译：

```bash
source build/envsetup.sh # Setup environment
lunch aosp_arm-eng # Setup choices
export USE_CCACHE=1 # Enable ccache
prebuilts/misc/linux-x86/ccache/ccache -M 100G # Set ccache memory = 100G
# export CCACHE_DIR=$YOUR_PATH/.ccache # Set ccache dir # Default in $HOME/.ccache
make -j4
```

## 目录结构

安装一下 Android Studio，用来作为查看源码的编辑器：

```bash
sudo apt-get update
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1 libbz2-1.0:i386
wget https://dl.google.com/dl/android/studio/ide-zips/3.5.3.0/android-studio-ide-191.6010548-linux.tar.gz
tar zxvf android-studio-ide-191.6010548-linux.tar.gz
sudo mv android-studio /usr/local
cd /usr/local/android-studio/bin
./studio.sh
```

PS：[谷歌在国内有服务器，用 ping.chinaz.com 解析出 dl.google.com 最快的 ip，在 hosts 里写死就行了，直接满速下载。](https://www.v2ex.com/t/455266)

生成 Android Studio 文件：

```bash
cd $HOME/$WORKING_DIRECTORY && source build/envsetup.sh
lunch aosp_arm-eng
cd development/tools/idegen && mm
cd $HOME/$WORKING_DIRECTORY && ./development/tools/idegen/idegen.sh
```

运行完后，将根目录下的 android.ipr 导入 Android Studio 即可。目录结构：

|   文件夹/文件   |                          包含内容                           |
| :-------------: | :---------------------------------------------------------: |
|       abi       |
|       art       |                     art 模式相关的代码                      |
|     bionic      |                     各种 so 库的源代码                      |
|    bootable     |             recovery、bootloader、diskinstaller             |
|      build      |                   源码编译生成的规则代码                    |
|       cts       |                 Android 兼容性测试套件标准                  |
|     dalvik      |                    Dalvik 模式相关的代码                    |
|   developers    |                  一些开发上用来参考的资料                   |
|   development   |             Android 开发相关的代码，makekey 等              |
|     device      |                       手机驱动的源码                        |
|      docs       |                          doc 文档                           |
|    external     |                Android 使用的一些开源的模块                 |
|   frameworks    |                            框架                             |
|    hardware     |                     部分开源的 HAL 代码                     |
|     libcore     |                    一些核心的 lib 文件库                    |
| libnativehelper | jni 相关的代码，包括如何通过 jni 来获取 Dalvik 中的某些函数 |
|    Makefile     |
|       ndk       |                          ndk 代码                           |
|       out       |
|    packages     |                        应用程序源码                         |
|       pdk       |
|    prebuilts    |          镜像生成依赖的一些文件，如 gcc、kernel 等          |
|       sdk       |                    sdk 源码，模拟器源码                     |
|     system      |            底层文件系统库、应用及组件（C 语言）             |
|      tools      |

## 内核代码

编译内核代码

```bash
git clone https://aosp.tuna.tsinghua.edu.cn/kernel/msm
# git clone https://android.googlesource.com/kernel/msm
cd msm
git branch -a
git checkout remotes/origin/android-msm-hammerhead-3.4-kitkat-mr1
sudo -i # 在root下进行编译
export PATH="$PATH:$WORKING_DIRECTORY/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6/bin"
export ARCH=arm
export SUBARCH=arm
export CROSS_COMPILE=arm-eabi-
make hammerhead_defconfig
make -j4
```

完成后将输出的 zImage-dtb 文件覆盖到之前的安卓源码中。重新编译手机镜像：

```bash
source build/envsetup.sh
lunch aosp_hammerhead-userdebug
make -j4
```

刷机：

```
adb reboot bootloader
fastboot -w flashall
```

| 编译命令  |                         作用                         |
| :-------: | :--------------------------------------------------: |
|     m     |                    编译所有的模块                    |
|    mm     | 编译当前目录下的模块，当前目录下要有 Android.mk 文件 |
|    mmm    | 编译指定路径下的模块，指定路径下要有 Android.mk 文件 |
| make snod |   部分编译完后，使用该命令来编译的结果整合到镜像中   |

## 使用 Docker 进行编译 Android 源码

源码编译的时候在不同环境中可能会有不同的问题，但在有了 docker 之后，环境的问题就可以很轻松地解决了。命令如下：

```bash
cd && mkdir build
export AOSP_VOL="$HOME/build"
wget https://raw.githubusercontent.com/tiann/docker-aosp/master/tests/build-kitkat.sh # 连接不上的话改一下hosts
bash build-kitkat.sh
```

# References

https://www.bilibili.com/video/av45424886
https://source.android.com/setup?hl=en
https://jingyan.baidu.com/article/d621e8dae805272865913fa7.html
https://www.cnblogs.com/yyangblog/archive/2011/03/02/1968880.html
https://blog.csdn.net/u012417380/article/details/72809141
https://blog.csdn.net/u012417380/article/details/73196722
https://blog.csdn.net/u012417380/article/details/73353670
https://blog.csdn.net/sergeycao/article/details/46459419
https://www.jianshu.com/p/3bdf6e9f9dfe
http://shxi.me/posts/7b82cd68.html
