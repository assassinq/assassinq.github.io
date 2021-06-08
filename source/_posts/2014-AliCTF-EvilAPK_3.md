---
title: 2014-AliCTF-EvilAPK_3
date: 2020-02-15 19:41:35
tags: [re, android]
---

接触了一段时间的安卓后复现一下经典的题目，具体审计还有分析的步骤不做记录。

<!-- more -->

# Analysis（classes.dex）

这道题目是阿里 14 年出的，先导入 jadx 看看反编译后大概的内容。在 AndroidManifest.xml 中，可以看到先设置了入口点为 com.ali.mobisecenhance.StubApplication，猜测这里可能是阿里加固自己添加的一个入口，用来执行一些初始化的操作，比如解密 dex，反调试，检测模拟器等等之类的。调用完 StubApplication 后，才会调用 MainActivity：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ali.tg.testapp" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="8" android:targetSdkVersion="9" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_launcher" android:name="com.ali.mobisecenhance.StubApplication" android:debuggable="true" android:allowBackup="true">
        <activity android:label="@string/app_name" android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".WebViewActivity" />
    </application>
</manifest>
```

在反编译出来的 Java 文件中，只能找到一个 StubApplication 类，其中的函数都是在 Native 层所实现，且加载了一个 mobisec 库。一般程序中是先执行 onCreate 函数，但 attachBaseContext 函数会早于 onCreate 函数执行：

```java
package com.ali.mobisecenhance;

import android.app.Application;
import android.content.Context;

public class StubApplication extends Application {
    private native void b(ClassLoader classLoader, Context context);

    protected native void attachBaseContext(Context context);

    public native void onCreate();

    static {
        System.loadLibrary("mobisec");
    }
}
```

可以在 lib 文件夹下看到 libmobisec.so 库，同时还可以看到在 assets 文件夹中有两个 jar 文件：

```bash
$ tree .
.
├── AndroidManifest.xml
├── META-INF
│   ├── MANIFEST.MF
│   ├── TEST.RSA
│   └── TEST.SF
├── assets
│   ├── cls.jar
│   └── fak.jar
├── classes.dex
├── lib
│   ├── armeabi
│   │   ├── libhack.so
│   │   ├── libmobisec.so
│   │   └── libtranslate.so
│   ├── armeabi-v7a
│   │   ├── libhack.so
│   │   ├── libmobisec.so
│   │   └── libtranslate.so
│   └── x86
│       ├── libhack.so
│       ├── libmobisec.so
│       └── libtranslate.so
├── res
│   ├── drawable-hdpi
│   │   ├── android.jpg
│   │   └── android1.jpg
│   ├── drawable-mdpi
│   │   └── ic_launcher.png
│   ├── drawable-xhdpi
│   │   └── ic_launcher.png
│   ├── drawable-xxhdpi
│   │   └── ic_launcher.png
│   └── layout
│       ├── activity_main.xml
│       └── webviewlayout.xml
└── resources.arsc

12 directories, 24 files
```

file 一下，发现是 cls.jar 是一段不可识别的数据，fak.jar 判断出来是个 zip 文件：

```bash
$ file cls.jar
cls.jar: data

$ file fak.jar
fak.jar: Zip archive data, at least v?[0x314] to extract
```

经过以上粗略的审计，可以猜测可能是在 libmobisec.so 实现了 StubApplication 中的函数，并对 assets 文件夹下的两个文件进行操作来还原出 MainActivity 中的函数。

# Analysis（libmobisec.so）

打开 IDA，最先定位到 JNI_OnLoad 函数，查看一下注册了哪些函数：

```cpp
signed int __fastcall JNI_OnLoad(_JavaVM *vm, int a2)
{
  const char *v2; // r2
  jclass v3; // r1
  signed int result; // r0
  bool v5; // zf
  _JNIEnv *env; // [sp+4h] [bp-Ch]

  env = (_JNIEnv *)a2;
  if ( vm->functions->GetEnv(&vm->functions, (void **)&env, 65542) )
  {
    v2 = "Failed to get the environment";
LABEL_5:
    _android_log_print(6, "debug", v2);
    return -1;
  }
  v3 = env->functions->FindClass(&env->functions, "com/ali/mobisecenhance/StubApplication");// locate class
  if ( !v3 )
  {
    v2 = "failed to get class reference";
    goto LABEL_5;
  }
  v5 = env->functions->RegisterNatives(&env->functions, v3, (const JNINativeMethod *)gMethods, 2) == 0;// register 2 methods
  result = 65542;
  if ( !v5 )
    result = -1;
  return result;
}
```

在 RegisterNatives 函数的参数中可以看到注册了两个函数，分别为 attachBaseContext 和 onCreate。在内存中可以找到两个函数对应的指针：

```
.data:00054010 gMethods        DCD aAttachbasecont_0   ; DATA XREF: JNI_OnLoad+44↑o
.data:00054010                                         ; .text:off_24784↑o
.data:00054010                                         ; "attachBaseContext"
.data:00054014                 DCD aLandroidConten_1   ; "(Landroid/content/Context;)V"
.data:00054018                 DCD sub_24D3C+1
.data:0005401C                 DCD aOncreate           ; "onCreate"
.data:00054020                 DCD aV                  ; "()V"
.data:00054024                 DCD sub_24498+1
```

因为 attachBaseContext 先于 onCreate 函数执行，这里先看一下 attachBaseContext。跟着 log 可以对函数有一个大体的了解，在一处 log 里有“enter new application”的信息，猜测可能是完成了解码进入 MainActivity。在该处上下看看可以发现一个 parse_dex 函数，很有可能是解析出真正的 dex 文件的函数：

```cpp
int __fastcall attachBaseContext(_JNIEnv *a1, jobject *a2, jobject *a3)
{
  jobject *v3; // r8
  jobject *v4; // r10
  _JNIEnv *env; // r4
  _JNIEnv *v6; // r1
  int v7; // r2
  int result; // r0
  ali *v9; // r0
  int v10; // r0
  int v11; // r0
  int v12; // r0
  int v13; // r5
  int v14; // r0
  int v15; // r0
  int v16; // r0
  int v17; // r0
  int v18; // r0
  char *v19; // r0
  int v20; // r0
  int v21; // r0
  void *v22; // r0
  void *v23; // r8
  const char *v24; // r0
  const char *v25; // r5
  size_t v26; // r0
  int v27; // r5
  int v28; // r8
  int v29; // r0
  int v30; // r5
  const char *v31; // r2
  int v32; // r0
  ali *v33; // r0
  int v34; // r4
  unsigned __int64 v35; // r2
  int v36; // [sp+8h] [bp-78h]
  __int64 v37; // [sp+18h] [bp-68h]
  char v38; // [sp+24h] [bp-5Ch]
  char v39; // [sp+3Ch] [bp-44h]
  char *v40; // [sp+4Ch] [bp-34h]
  char *v41; // [sp+50h] [bp-30h]

  v3 = a2;
  v4 = a3;
  env = a1;
  _android_log_print(6, "debug", "in...");
  result = ali::init_classes(env, v6, v7);      // init classes
  if ( result )
    return result;
  v9 = (ali *)_JNIEnv::CallNonvirtualVoidMethod(env, v3, ali::ContextWrapper, dword_54128, v4);
  v36 = ali::NanoTime(v9);
  v10 = _JNIEnv::GetObjectClass(env, v3);
  v11 = _JNIEnv::GetMethodID(env, v10, "getFilesDir", "()Ljava/io/File;");
  v12 = _JNIEnv::CallObjectMethod(env, v3, v11);
  v13 = v12;
  v14 = _JNIEnv::GetObjectClass(env, v12);
  v15 = _JNIEnv::GetMethodID(env, v14, "getAbsolutePath", "()Ljava/lang/String;");
  v16 = _JNIEnv::CallObjectMethod(env, v13, v15);
  sub_247D8(&v39, env, v16);
  if ( &v39 != (char *)&ali::g_filePath )
    std::string::_M_assign((std::string *)&ali::g_filePath, v41, v40);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v39);
  _android_log_print(3, "debug", "global files path is %s", dword_540E8);
  v17 = _JNIEnv::CallObjectMethod(env, v3, dword_541A4);
  if ( ali::sdk_int <= 8 )
  {
    v20 = _JNIEnv::GetObjectField(env, v17, dword_5416C);
    sub_247D8(&v38, env, v20);
    std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v39, &v38, "/lib");
    if ( &v39 != (char *)&ali::g_libPath )
      std::string::_M_assign((std::string *)&ali::g_libPath, v41, v40);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v39);
    v19 = &v38;
  }
  else
  {
    v18 = _JNIEnv::GetObjectField(env, v17, dword_54170);
    sub_247D8(&v39, env, v18);
    if ( &v39 != (char *)&ali::g_libPath )
      std::string::_M_assign((std::string *)&ali::g_libPath, v41, v40);
    v19 = &v39;
  }
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(v19);
  _android_log_print(3, "debug", "global native path is %s", dword_540D0);
  v21 = _JNIEnv::CallObjectMethod(env, v3, dword_541B0);
  sub_247D8(&v39, env, v21);
  if ( &v39 != (char *)&ali::g_apkPath )
    std::string::_M_assign((std::string *)&ali::g_apkPath, v41, v40);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v39);
  setenv("APKPATH", (const char *)dword_540B8, 1);
  _android_log_print(3, "debug", "global apk path is %s", dword_540B8);
  sub_24A64(env, v3);
  v22 = (void *)_JNIEnv::CallObjectMethod(env, v4, dword_541A0);
  v23 = v22;
  if ( v22 )
  {
    v24 = env->functions->GetStringUTFChars(&env->functions, v22, 0);
    v25 = v24;
    v26 = strlen(v24);
    std::string::_M_assign((std::string *)&ali::g_pkgName, v25, &v25[v26]);
    env->functions->ReleaseStringUTFChars(&env->functions, v23, v25);
  }
  v37 = 0LL;
  v27 = _JNIEnv::CallObjectMethod(env, v4, dword_541A8);
  parse_dex(env, &v37);                         // parse dex?
  replace_classloader_cookie(env, v27, v37, HIDWORD(v37));
  _android_log_print(3, "debug", "enter new application");// enter MainActivity?
  v28 = dword_54120;
  _JNIEnv::NewStringUTF(env, "android.app.Application");
  v29 = _JNIEnv::CallObjectMethod(env, v27, v28);
  v30 = v29;
  if ( v29 )
  {
    v32 = _JNIEnv::GetMethodID(env, v29, "<init>", "()V");
    dword_540A0 = _JNIEnv::NewObject(env, v30, v32);
    _JNIEnv::CallVoidMethod(env, dword_540A0, dword_54134, v4);
    _JNIEnv::DeleteLocalRef(env, v30);
    v31 = "exit new application";
  }
  else
  {
    v31 = "can't findClass realAppClass";
  }
  v33 = (ali *)_android_log_print(3, "debug", v31);
  if ( dword_540A0 )
  {
    v33 = (ali *)env->functions->NewGlobalRef(&env->functions, (jobject)dword_540A0);
    dword_540A0 = (int)v33;
  }
  v34 = ali::NanoTime(v33);
  _android_log_print(3, "debug", "##### attachBaseContext spent:");
  ali::PrettyDuration((ali *)(v34 - v36), v35);
  result = _android_log_print(3, "debug", "exit attachBaseContext");
  return result;
}
```

接下来进入 parse_dex 进行分析。一开始判断了是采用了 Dalvik 模式还是 ART 模式。我的机器是 Android 4.4.4，用的是 Dalvik 模式，那就只分析一下 Dalvik 的部分。接下来对 SDK 的版本进行了判断，是否大于 SDK13。我用的机器是 SDK19，故下面应该是调用了 openWithHeader 函数。之后的部分看到是用 dlopen 打开 libdvm.so，并开始执行程序，所以就不做进一步分析。主要应该就是 openWithHeader 中的内容解析了出了 dex 文件：

```cpp
signed int __fastcall parse_dex(_JNIEnv *a1, __int64 *a2)
{
  int v2; // r7
  const char *v3; // r1
  char *v4; // r0
  char *v5; // r9
  unsigned __int8 *v6; // r3
  int v7; // r2
  int v8; // t1
  int fd; // ST14_4
  int v10; // r8
  int v11; // r7
  int v12; // r5
  int v13; // r0
  int v14; // r5
  int v15; // r0
  int v16; // r7
  int v17; // r1
  int v18; // r5
  int (__fastcall *v19)(int, signed int); // r5
  int v20; // r5
  unsigned __int8 *v21; // r8
  const char *v22; // r3
  char *v23; // r0
  char *v24; // r0
  char *v25; // r6
  ali::EncFile *v26; // r7
  int v27; // r0
  int *v28; // r0
  char *v29; // r0
  int v30; // r10
  void *v31; // r7
  int (__fastcall *v32)(unsigned __int8 *, int, signed int *); // r9
  int (__fastcall *v33)(_DWORD); // r7
  const char *v34; // r2
  int v35; // r9
  signed int v36; // r7
  _DWORD *v37; // r9
  _BYTE *v38; // r5
  unsigned __int8 *v39; // r3
  void *v40; // r0
  JNINativeMethod *v41; // r0
  unsigned __int8 *v42; // r3
  signed int v43; // r3
  _JNIEnv *v45; // [sp+8h] [bp-2A0h]
  __int64 *v46; // [sp+10h] [bp-298h]
  int v47; // [sp+24h] [bp-284h]
  unsigned __int8 *v48; // [sp+28h] [bp-280h]
  unsigned __int8 *v49; // [sp+2Ch] [bp-27Ch]
  void (__cdecl *v50)(const unsigned int *, jvalue *); // [sp+30h] [bp-278h]
  char v51; // [sp+34h] [bp-274h]
  signed int v52[2]; // [sp+38h] [bp-270h]
  char s; // [sp+40h] [bp-268h]
  char v54; // [sp+54h] [bp-254h]
  int v55; // [sp+64h] [bp-244h]
  int v56; // [sp+68h] [bp-240h]
  char v57; // [sp+6Ch] [bp-23Ch]
  const char *v58; // [sp+80h] [bp-228h]
  char v59; // [sp+84h] [bp-224h]
  const char *v60; // [sp+98h] [bp-210h]
  char v61; // [sp+9Ch] [bp-20Ch]
  unsigned int v62; // [sp+B0h] [bp-1F8h]
  char v63; // [sp+B4h] [bp-1F4h]
  char v64; // [sp+CCh] [bp-1DCh]
  int v65; // [sp+E0h] [bp-1C8h]
  char v66; // [sp+E4h] [bp-1C4h]
  char v67; // [sp+FCh] [bp-1ACh]
  const char *v68; // [sp+110h] [bp-198h]
  char v69; // [sp+114h] [bp-194h]
  char v70; // [sp+12Ch] [bp-17Ch]
  const char *v71; // [sp+140h] [bp-168h]
  char v72; // [sp+144h] [bp-164h]
  char *v73; // [sp+154h] [bp-154h]
  char *v74; // [sp+158h] [bp-150h]
  char v75; // [sp+15Ch] [bp-14Ch]
  char v76; // [sp+174h] [bp-134h]
  char v77; // [sp+18Ch] [bp-11Ch]
  char v78; // [sp+1A4h] [bp-104h]
  char v79; // [sp+1BCh] [bp-ECh]
  char v80; // [sp+1D4h] [bp-D4h]
  char v81; // [sp+1ECh] [bp-BCh]
  char v82; // [sp+204h] [bp-A4h]
  char v83; // [sp+21Ch] [bp-8Ch]
  char v84; // [sp+234h] [bp-74h]
  int v85; // [sp+244h] [bp-64h]
  unsigned __int8 *v86; // [sp+248h] [bp-60h]
  char v87; // [sp+24Ch] [bp-5Ch]
  char v88; // [sp+264h] [bp-44h]
  char *v89; // [sp+274h] [bp-34h]
  char *v90; // [sp+278h] [bp-30h]

  v45 = a1;
  v46 = a2;
  _android_log_print(3, "debug", "enter parse_dex");
  if ( ali::isDalvik )                          // dalvik or art
  {
    v47 = 0;
    std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v88, &ali::g_filePath, "/cls.jar");// locate cls.jar
    v25 = v90;
    v26 = (ali::EncFile *)operator new(0xCu);
    ali::EncFile::EncFile(v26, v25);
    v48 = 0;
    v49 = 0;
    if ( ali::sdk_int > 13 )                    // sdk version > 13
    {
      v27 = ali::EncFile::openWithHeader(v26, &v48, (unsigned int *)&v47, 0x10u);
      v49 = v48 + 16;
    }
    else                                        // sdk version <= 13 ( android 3.x )
    {
      v27 = ali::EncFile::open(v26, &v49, (unsigned int *)&v47);
    }
    if ( v49 == (unsigned __int8 *)-1 )
    {
      v28 = (int *)_errno(v27);
      v29 = strerror(*v28);
      _android_log_print(3, "debug", "mmap dex file :%s", v29);
LABEL_45:
      v24 = &v88;
      goto LABEL_46;
    }
    v30 = *((_DWORD *)v49 + 8);
    if ( ali::sdk_int > 13 )                    // sdk version > 13
    {
      v40 = dlopen("libdvm.so", 1);             // open libdvm.so and start execute program
      v41 = (JNINativeMethod *)dlsym(v40, "dvm_dalvik_system_DexFile");
      v50 = 0;
      lookup(v41, "openDexFile", "([B)I", &v50);
      v42 = v48;
      *((_DWORD *)v48 + 2) = v47;
      *(_DWORD *)&v51 = v42;
      ((void (*)(void))v50)();
      v43 = v52[0];
      *v46 = v52[0];
      *(_DWORD *)(*(_DWORD *)(*(_DWORD *)(v43 + 8) + 4) + 32) = *(_DWORD *)(v43 + 16);
      *(_DWORD *)(*(_DWORD *)(*(_DWORD *)(v43 + 8) + 4) + 36) = v47;
      ali::EncFile::~EncFile(v26);
      operator delete((void *)v26);
    }
    else                                        // sdk version <= 13 ( android 3.x )
    {
      v31 = dlopen("libdvm.so", 1);
      v32 = (int (__fastcall *)(unsigned __int8 *, int, signed int *))dlsym(v31, "dvmDexFileOpenPartial");
      v33 = (int (__fastcall *)(_DWORD))dlsym(v31, "dexCreateClassLookup");
      v52[0] = 0;
      if ( v32(v49, v30, v52) == -1 )
      {
        v34 = "dvmDexFileOpenPartial error";
LABEL_40:
        _android_log_print(3, "debug", v34);
        goto LABEL_45;
      }
      v35 = *(_DWORD *)v52[0];
      *(_DWORD *)(v35 + 36) = v33(*(_DWORD *)v52[0]);
      v36 = v52[0];
      if ( !*(_DWORD *)(*(_DWORD *)v52[0] + 36) )
      {
        v34 = "dexCreateClassLookup error";
        goto LABEL_40;
      }
      v37 = malloc(0x2Cu);
      v38 = malloc(0x14u);
      strdup((const char *)&unk_4CEE9);
      v38[4] = 0;
      v38[5] = 0;
      *((_DWORD *)v38 + 2) = 0;
      v39 = v49;
      *(_DWORD *)v38 = v38;
      *((_DWORD *)v38 + 3) = v37;
      v37[10] = v36;
      *(_DWORD *)(v36 + 32) = v39;
      *(_DWORD *)(v36 + 36) = v47;
      *v46 = (signed int)v38;
    }
    v23 = &v88;
    goto LABEL_44;
  }
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v54, &ali::g_filePath, "/cls.jar");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v57, &ali::g_filePath, "/cls.dex");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v59, &ali::g_filePath, "/fak.jar");
  _android_log_print(3, "debug", "before oat gen");
  if ( !access(v58, 0) )
    goto LABEL_24;
  v2 = android_getCpuFamily();
  std::string::string(&v63, "arm", &v51);
  switch ( v2 )
  {
    case 1:
      v3 = "arm";
LABEL_5:
      std::string::operator=(&v63, v3);
      break;
    case 2:
      v3 = "x86";
      goto LABEL_5;
    case 3:
    case 6:
      v3 = "mips";
      goto LABEL_5;
    case 4:
      v3 = "arm64";
      goto LABEL_5;
    case 5:
      v3 = "x86_64";
      goto LABEL_5;
  }
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v64, &ali::g_libPath, "/libhack.so");
  v4 = getenv("LD_PRELOAD");
  v5 = v4;
  if ( v4 )
  {
    _android_log_print(3, "debug", "the system already define LD_PRELOAD=%s", v4);
    std::string::string(&v84, v5, v52);
    v6 = v86;
    v7 = v85;
    while ( v6 != (unsigned __int8 *)v7 )
    {
      v8 = *v6++;
      if ( v8 == 32 )
        *(v6 - 1) = 58;
    }
    std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v87, &v84, ":");
    std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v88, &v87, &v64);
    std::string::_M_assign((std::string *)&v64, v90, v89);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v88);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v87);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v84);
  }
  _android_log_print(3, "debug", "the new LD_PRELOAD is %s", v65);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v66, &ali::g_filePath, "/juice.data");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v67, &ali::g_filePath, "/fak.jar");
  fd = open(v68, 0);
  memset(&s, 0, 0x14u);
  sprintf(&s, "%d", fd);
  std::string::string(&v69, &s, v52);
  v73 = &v72;
  v74 = &v72;
  std::priv::_String_base<char,std::allocator<char>>::_M_allocate_block(&v72, v55 - v56 + 10);
  *v73 = 0;
  std::string::_M_appendT<char const*>(&v72, "DEX_FILE=", "", v52);
  std::string::append((std::string *)&v72, (const std::string *)&v54);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v75, &v72, "                     JUICE_FILE=");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v76, &v75, &v66);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v77, &v76, "                     LD_PRELOAD=");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v78, &v77, &v64);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(
    &v79,
    &v78,
    "                     /system/bin/dex2oat \t\t\t\t  \t --runtime-arg -Xms64m \t\t\t\t\t --runtime-arg -Xmx64m \t\t\t\t"
    "\t --boot-image=/system/framework/boot.art                      --zip-fd=");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v80, &v79, &v69);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v81, &v80, "\t\t\t\t\t --zip-location=");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v82, &v81, &v67);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v83, &v82, "\t\t\t\t\t --oat-file=");
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v84, &v83, &v57);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v70, &v84, "                     ");
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v84);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v83);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v82);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v81);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v80);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v79);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v78);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v77);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v76);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v75);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v72);
  _android_log_print(3, "debug", "cmd is %s", v71);
  system(v71);
  close(fd);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v70);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v69);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v67);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v66);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v64);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v63);
LABEL_24:
  _android_log_print(3, "debug", "after oat gen");
  v10 = ali::JDexFile;
  v11 = dword_54140;
  if ( ali::sdk_int <= 19 )                     // sdk version <= 19
  {
    v12 = _JNIEnv::NewStringUTF(v45, v60);
    v13 = _JNIEnv::NewStringUTF(v45, v58);
    v16 = _JNIEnv::CallStaticIntMethod(v45, v10, v11, v12, v13, 0);
    v18 = 0;
  }
  else                                          // sdk version > 19
  {
    v14 = _JNIEnv::NewStringUTF(v45, v60);
    v15 = _JNIEnv::NewStringUTF(v45, v58);
    v16 = _JNIEnv::CallStaticLongMethod(v45, v10, v11, v14, v15, 0);
    v18 = v17;
  }
  _android_log_print(3, "debug", "cookie is %llx");
  *(_DWORD *)v46 = v16;
  *((_DWORD *)v46 + 1) = v18;
  v19 = (int (__fastcall *)(int, signed int))dlsym((void *)0xFFFFFFFF, "_ZNK3art7DexFile12FindClassDefEt");
  _android_log_print(3, "debug", "DexFile::FindClassDefFn is %p", v19);
  v20 = v19(v16, 1);
  _android_log_print(3, "debug", "call FindClassDefFn(%p,%d) => %p", v16, 1, v20);
  _android_log_print(3, "debug", "dex position is %p", v20 - 572);
  _android_log_print(3, "debug", "dex head is %08x %08x", *(_DWORD *)(v20 - 572), *(_DWORD *)(v20 - 568));
  v21 = *(unsigned __int8 **)(v20 - 540);
  _android_log_print(3, "debug", "dex size is %d", v21);
  MemEnableWrite((unsigned __int8 *)(v20 - 572), &v21[v20 - 572]);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v61, &ali::g_filePath, "/juice.data");
  if ( !ali::dex_juicer_patch((ali *)(v20 - 572), v21, v62, v22) )
  {
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v61);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v59);
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v57);
    v23 = &v54;
LABEL_44:
    std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(v23);
    _android_log_print(3, "debug", "exit parse_dex");
    return 0;
  }
  _android_log_print(6, "debug", "fail to patch dex");
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v61);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v59);
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(&v57);
  v24 = &v54;
LABEL_46:
  std::priv::_String_base<char,std::allocator<char>>::_M_deallocate_block(v24);
  _android_log_print(3, "debug", "exit parse_dex error");
  return -1;
}
```

在 openWithHeader 中，log 了三次 dex 的 magic number，中间分别进行了 RC4 解密和 LZMA 解压缩。最后得到的结果应该就是最终的 dex 文件：

```cpp
int __fastcall ali::EncFile::openWithHeader(ali::EncFile *this, unsigned __int8 **a2, unsigned int *a3, unsigned int a4)
{
  ali::EncFile *v4; // r5
  unsigned __int8 **v5; // r11
  unsigned int *v6; // r6
  unsigned int v7; // r7
  const char *v8; // r2
  int fd; // r8
  int v10; // r10
  __blksize_t v12; // r3
  unsigned __int8 *v13; // r4
  ali *v14; // r0
  __int64 v15; // r0
  __int64 v16; // ST18_8
  unsigned int *v17; // r3
  ali *v18; // r0
  __int64 v19; // r0
  int v20; // r8
  int v21; // r3
  char v22; // r2
  unsigned __int64 v23; // r0
  ali *v24; // r0
  unsigned __int8 *v25; // r9
  ali *v26; // ST24_4
  __int64 v27; // r0
  __int64 v28; // ST18_8
  ali *v29; // r0
  __int64 v30; // r0
  size_t v31; // [sp+2Ch] [bp-9Ch]
  int v32; // [sp+30h] [bp-98h]
  char v33; // [sp+34h] [bp-94h]
  struct stat buf; // [sp+38h] [bp-90h]

  v4 = this;
  v5 = a2;
  v6 = a3;
  v7 = a4;
  if ( !*((_DWORD *)this + 2) )
  {
    v8 = "file path is null";
LABEL_5:
    _android_log_print(6, "debug", v8);
    return 0;
  }
  fd = open(*((const char **)this + 2), 0);
  v10 = fstat(fd, &buf);
  if ( v10 )
  {
    v8 = "fstat failed";
    goto LABEL_5;
  }
  v12 = buf.st_blksize;
  *v6 = buf.st_blksize;
  *(_DWORD *)v4 = v12;
  v13 = (unsigned __int8 *)mmap(0, *v6, 3, 2, fd, 0);
  *((_DWORD *)v4 + 1) = v13;
  close(fd);
  v14 = (ali *)_android_log_print(
                 3,
                 "debug",
                 "dex magic %c %c %c %c %c %c %c",// original dex magic
                 *v13,
                 v13[1],
                 v13[2],
                 v13[3],
                 v13[4],
                 v13[5],
                 v13[6]);
  LODWORD(v15) = ali::NanoTime(v14);
  v16 = v15;
  v18 = (ali *)ali::decryptRc4((ali *)v13, v13, (unsigned __int8 *)v6, v17);// RC4 decrypt
  LODWORD(v19) = ali::NanoTime(v18);
  ali::PrettyDuration((ali *)(v19 - v16), v19 - v16);
  _android_log_print(3, "debug", "decrypted len:%u", *v6);
  v20 = 0;
  _android_log_print(
    3,
    "debug",
    "after decrypt dex magic %c %c %c %c %c %c %c",// dex magic after RC4
    *v13,
    v13[1],
    v13[2],
    v13[3],
    v13[4],
    v13[5],
    v13[6]);
  v21 = (int)(v13 + 4);
  do
  {
    v22 = 8 * v10++;
    v23 = (unsigned __int64)*(unsigned __int8 *)(v21++ + 1) << v22;
    v20 += v23;
  }
  while ( v10 != 8 );
  _android_log_print(3, "debug", "unpackSize: %u", v20);
  *(_DWORD *)v4 = v7 + v20;
  v24 = (ali *)mmap(0, v7 + v20, 3, 34, -1, 0);
  *((_DWORD *)v4 + 1) = v24;
  v25 = (unsigned __int8 *)v24 + v7;
  v26 = v24;
  LODWORD(v27) = ali::NanoTime(v24);
  v31 = *v6;
  v28 = v27;
  v32 = v20;
  v29 = (ali *)LzmaDecode(v25, &v32, v13 + 13, &v31, v13, 5, 1, &v33, &off_54028);// LZMA uncompress
  LODWORD(v30) = ali::NanoTime(v29);
  ali::PrettyDuration((ali *)(v30 - v28), v30 - v28);
  munmap(v13, buf.st_blksize);
  _android_log_print(
    3,
    "debug",
    "after uncompressed dex magic %c %c %c %c %c %c %c",// dex magic after LZMA
    *((unsigned __int8 *)v26 + v7),
    v25[1],
    v25[2],
    v25[3],
    v25[4],
    v25[5],
    v25[6]);
  *v6 = v20;
  if ( v5 )
    *v5 = (unsigned __int8 *)*((_DWORD *)v4 + 1);
  return *((_DWORD *)v4 + 1);
}
```

# Dump Dex File

知道了解析 dex 的流程，接下来就通过动态调试来吧 dex 文件 dump 下来。现在 BL 跳转到 openWithHeader 的语句处设下断点：

```
.text:00026A7E loc_26A7E                               ; CODE XREF: parse_dex(_JNIEnv *,long long *)+622↑j
.text:00026A7E                 MOV             R1, R9  ; unsigned __int8 **
.text:00026A80                 MOV             R2, R4  ; unsigned int *
.text:00026A82                 MOVS            R3, #0x10 ; unsigned int
.text:00026A84                 BL              _ZN3ali7EncFile14openWithHeaderEPPhPjj ; ali::EncFile::openWithHeader(uchar **,uint *,uint)
.text:00026A88                 LDR.W           R3, [R9]
.text:00026A8C                 ADDS            R3, #0x10
.text:00026A8E                 STR             R3, [R6]
```

运行到断点处，单步步入 openWithHeader 函数，然后单步步过一直到 return，中间可以在 monitor 中用 tag:debug 过滤来查看 log。运行完后看到 log 输出的 magic number 已经是真实 dex 文件的样子了：

![](/pics/2014-AliCTF-EvilAPK_3/1.png)

根据函数的返回值存放在 R0 中，可以看到 R0 所指向的部分是一个 dex 文件的数据了：

![](/pics/2014-AliCTF-EvilAPK_3/2.png)

接下来我们可以把 dex 文件给 dump 下来。但文件的大小为多少？根据 dex 的数据结构，可以知道 dex 文件的大小位于偏移 0x20 处：

![](/pics/2014-AliCTF-EvilAPK_3/3.png)

接下来使用 IDC 脚本来 dump 数据：

```cpp
static main(void) {
    auto fp, begin, end, len, b;
    fp = fopen("dump.dex", "wb");
    begin = 0x7584C010; // 解密后数据在内存中的位置
    len = 0x0941FC; // 文件大小
    end = begin + len;
    for (b = begin; b < end; b++) {
        fputc(Byte(b), fp);
    }
}
```

最后将 dump 下来的数据放进 JEB 中，反汇编可以得到真实的 MainActivity 代码：

![](/pics/2014-AliCTF-EvilAPK_3/4.png)

# Fix Application

使用 AndroidKiller 反编译加固后的 apk，找到 AndroidManifest.xml，删除 Application 的 android:name 属性：

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ali.tg.testapp" platformBuildVersionCode="23" platformBuildVersionName="6.0-2438415">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <activity android:label="@string/app_name" android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name=".WebViewActivity"/>
    </application>
</manifest>
```

回编译后，找到生成的 apk，压缩软件打开，替换我们 dump 出来的 classes.dex，同时删除 assets 文件夹，其他 so 文件不用管。修改完后重新签名打包并安装运行，可以正常使用。

# Find Flag

定位到真实的程序后，开始分析具体的内容。先来看 MainActivity，主要是一个点击事件，其中获取了 EditText 中的字符串并作为参数传入并启动 WebViewActivity：

```java
package com.ali.tg.testapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.ActionBarDrawerToggleJellybeanMR2n;
import android.support.v4.widget.ListViewAutoScrollHelpern;
import android.view.View$OnClickListener;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends Activity {
    class com.ali.tg.testapp.MainActivity$1 implements View$OnClickListener {
        com.ali.tg.testapp.MainActivity$1(MainActivity arg1) {
            MainActivity.this = arg1;
            super();
        }

        public void onClick(View arg6) {
            ActionBarDrawerToggleJellybeanMR2n.b(ActionBarDrawerToggleJellybeanMR2n.a());
            String v1 = MainActivity.this.edit.getText().toString(); // 获取EditText中的字符串
            Intent v0 = new Intent();
            v0.putExtra(ListViewAutoScrollHelpern.decrypt_native("dV.", 2), v1); // 将v1的值传给Intent，变量名为“dV.”解密后的值
            v0.setClass(MainActivity.this, WebViewActivity.class); // 设置Intent要跳转的类为WebViewActivity
            MainActivity.this.startActivity(v0); // 启动WebViewActivity
        }
    }

    Button btn_enter;
    View$OnClickListener btn_listener;
    EditText edit;

    public MainActivity() {
        super();
        this.btn_enter = null;
        this.edit = null;
        this.btn_listener = new com.ali.tg.testapp.MainActivity$1(this);
    }

    protected void onCreate(Bundle arg4) {
        ActionBarDrawerToggleJellybeanMR2n.b(ActionBarDrawerToggleJellybeanMR2n.a());
        super.onCreate(arg4);
        this.setContentView(0x7F030000);
        this.edit = this.findViewById(0x7F060001);
        this.btn_enter = this.findViewById(0x7F060002);
        this.btn_enter.setOnClickListener(this.btn_listener);
    }
}
```

然后来看看 WebViewActivity，主要就是新建了一个 JavaScriptInterface 对象，对象的名称同样被加密了。然后加载输入的 url，目标是最后能够成功调用对象 JavaScriptInterface 里的 showToast 方法。接下来需要根据密文解出对象名，并构造出相应的网页来弹出 Toast。不过这里好像 flag 就是“祥龙”，但还是继续往下尝试构造出能够弹 Toast 的方法：

```java
package com.ali.tg.testapp;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.ActionBarDrawerToggleJellybeanMR2n;
import android.support.v4.widget.ListViewAutoScrollHelpern;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

public class WebViewActivity extends Activity {
    public class JavaScriptInterface {
        Context mContext;

        JavaScriptInterface(WebViewActivity arg1, Context arg2) {
            WebViewActivity.this = arg1;
            super();
            this.mContext = arg2;
        }

        public void showToast() { // 构造出一个页面能够调用这个函数就成功了
            ActionBarDrawerToggleJellybeanMR2n.b(ActionBarDrawerToggleJellybeanMR2n.a());
            Toast.makeText(this.mContext, "祥龙！", 0).show();
        }
    }

    WebView wView;

    public WebViewActivity() {
        super();
        this.wView = null;
    }

    protected void onCreate(Bundle arg7) {
        ActionBarDrawerToggleJellybeanMR2n.b(ActionBarDrawerToggleJellybeanMR2n.a());
        super.onCreate(arg7);
        this.setContentView(0x7F030001);
        this.wView = this.findViewById(0x7F060004);
        WebSettings v2 = this.wView.getSettings();
        v2.setJavaScriptEnabled(true);
        v2.setJavaScriptCanOpenWindowsAutomatically(true);
        this.wView.addJavascriptInterface(new JavaScriptInterface(this, ((Context)this)), ListViewAutoScrollHelpern.decrypt_native("BQ1$*[w6G_", 2)); // 添加一个JavascriptInterface对象，对象的变量名为“BQ1$*[w6G_”解密后的值
        this.wView.loadUrl(this.getIntent().getStringExtra(ListViewAutoScrollHelpern.decrypt_native("dV.", 2))); // 把在MainActivity中获取的变量作为url来加载
    }
}
```

# Crack

接下来再看看 ListViewAutoScrollHelpern 中的 decrypt_native 方法，发现是在 Native 层中的 translate 库实现的：

```java
package android.support.v4.widget;

import android.util.Log;

public class ListViewAutoScrollHelpern {
    static {
        System.loadLibrary("translate");
    }

    public ListViewAutoScrollHelpern() {
        super();
    }

    public static native String decrypt_native(String arg0, int arg1) {
    }

    public static void testLogv(String arg1) {
        Log.v("cheatecore", arg1);
    }

    public static void testLogw(String arg1) {
        Log.w("cheatecore", arg1);
    }
}
```

然后将 libtranslat.so 载入 IDA。先看看 JNI_OnLoad，其中有两个函数 register_Algorithm 和 register_translate：

```cpp
int __fastcall JNI_OnLoad(_JavaVM *a1)
{
  int v1; // r1
  jint v2; // r2
  _JNIEnv *v3; // r4
  jint v4; // r0
  bool v5; // cf
  int result; // r0
  _JNIEnv *env; // [sp+4h] [bp-Ch]

  env = 0;
  if ( a1->functions->GetEnv(&a1->functions, (void **)&env, 65540) )
    return -1;
  v3 = env;
  register_Algorithm(env, v1, v2);
  v4 = register_translate(v3);
  v5 = v4 < 0;
  result = v4 & (v4 >> 32);
  if ( !v5 )
    result = 65540;
  return result;
}
```

在 register_Algorithm 中发现了目标函数：

```cpp
int __fastcall register_Algorithm(_JNIEnv *a1, int a2, jint a3)
{
  _JNIEnv *v3; // r4
  jclass v4; // r0
  jclass v5; // r0

  v3 = a1;
  v4 = a1->functions->FindClass(&a1->functions, "android/support/v4/widget/ListViewAutoScrollHelpern");
  v3->functions->RegisterNatives(&v3->functions, v4, (const JNINativeMethod *)off_607C, 1);
  v5 = v3->functions->FindClass(&v3->functions, "android/support/v4/view/PagerTitleStripIcsn");
  v3->functions->RegisterNatives(&v3->functions, v5, (const JNINativeMethod *)off_607C, 1);
  return 0;
}
```

定位到目标函数，发现其中调用了一个 vigenere_decrypt：

```cpp
jstring __fastcall decrypt_native(_JNIEnv *a1, jobject a2, jstring a3, jint a4)
{
  jstring data; // r6
  jint num; // r9
  _JNIEnv *env; // r4
  const char *v7; // r0
  const char *v8; // r8
  jstring v9; // r7
  int v11; // [sp+4h] [bp+0h]

  data = a3;
  num = a4;
  env = a1;
  memset(&v11, 0, 0x1000u);
  v7 = env->functions->GetStringUTFChars(&env->functions, data, 0);
  v8 = v7;
  if ( num == 2 )
  {
    vigenere_decrypt(v7, (char *)&v11);
    v9 = env->functions->NewStringUTF(&env->functions, (const char *)&v11);
  }
  else
  {
    v9 = data;
  }
  env->functions->ReleaseStringUTFChars(&env->functions, data, v8);
  return v9;
}
```

在 vigenere_decrypt 函数中，对输入的数据进行了解密：

```cpp
signed int __fastcall vigenere_decrypt(const char *ciphertext, char *plaintext)
{
  const char *ciphertext_1; // r8
  char *plaintext_1; // r6
  size_t len; // r0
  char *v5; // r2
  const char *table; // r3
  signed int v7; // r7
  int v8; // r0
  int v9; // r1
  int v10; // r5
  int v11; // r0
  int v12; // r10
  char v13; // r3
  signed int i; // r5
  signed int result; // r0
  signed int v16; // r9
  int ch; // r3
  char s; // [sp+4h] [bp-64h]
  char v19; // [sp+48h] [bp-20h]

  ciphertext_1 = ciphertext;
  plaintext_1 = plaintext;
  len = strlen(ciphertext);
  v5 = &s;
  table = "ncA8DaUPelq*S7Y9q#hLl0T##@XTuXHQpFA&65eaUaY33WigYMXO9y7JtCQU";
  v7 = len;
  do
  {
    v8 = *(_DWORD *)table;
    table += 8;
    v9 = *((_DWORD *)table - 1);
    *(_DWORD *)v5 = v8;
    *((_DWORD *)v5 + 1) = v9;
    v10 = (int)(v5 + 8);
    v5 += 8;
  }
  while ( table != "tCQU" );
  v11 = *(_DWORD *)table;
  v12 = 0;
  v13 = table[4];
  *(_DWORD *)v10 = v11;
  *(_BYTE *)(v10 + 4) = v13;
  i = 0;
  result = strlen(&s);
  v16 = result;
  while ( i < v7 )
  {
    ch = (unsigned __int8)ciphertext_1[i];
    if ( ch - 32 <= (unsigned int)'^' )         // chr(ch) <= 127
    {
      plaintext_1[i] = (ch - (unsigned __int8)*(&v19 + v12 - 68) + 95) % 95 + 32;// &v19 - 68 = &table
      result = (v12 + 1) / v16;
      v12 = (v12 + 1) % v16;
    }
    else                                        // chr(ch) > 127
    {
      plaintext_1[i] = ch;
    }
    ++i;
  }
  return result;
}
```

我先是通过动态调试来获取到了两个字符串的解密结果：

![](/pics/2014-AliCTF-EvilAPK_3/5.png)

![](/pics/2014-AliCTF-EvilAPK_3/6.png)

然后尝试自己实现一个解密函数进行验证：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *table = "ncA8DaUPelq*S7Y9q#hLl0T##@XTuXHQpFA&65eaUaY33WigYMXO9y7JtCQU";

char *vigenere_decrypt(char *ciphertext) {
	int j = 0;
	int len = strlen(ciphertext);
	printf("%d\n", len);
	char plaintext[len];
	for (int i = 0; i < len; i++) {
		char ch = ciphertext[i];
		if ((ch - 32) <= 0x5E) {
			plaintext[i] = (ch - table[j] + 95) % 95 + 32;
			j = (j + 1) % 16;
		} else {
			plaintext[i] = ch;
		}
	}
	plaintext[len] = '\x00';
	return plaintext;
}

int main() {
	char *ciphertext1 = "dV.";
	char *plaintext1 = vigenere_decrypt(ciphertext1);
	printf("%s\n", plaintext1); // url
	char *ciphertext2 = "BQ1$*[w6G_";
	char *plaintext2 = vigenere_decrypt(ciphertext2);
	printf("%s\n", plaintext2); // SmokeyBear
	return 0;
}
```

当然这里也可以 Hook 这个 so 文件，也可以直接编写代码调用 so 中的函数，条条大路通罗马。最后实现一个调用 Toast 的 html 页面：

```html
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <script type="text/javascript">
      function alicrack() {
        SmokeyBear.showToast();
      }
    </script>
  </head>
  <body>
    Crack EvilAPK_3
    <script type="text/javascript">
      alicrack();
    </script>
  </body>
</html>
```

在软件中输入对应的地址，成功弹窗：

![](/pics/2014-AliCTF-EvilAPK_3/7.png)

# References

https://xz.aliyun.com/t/383
https://blog.csdn.net/AliMobileSecurity/article/details/53259788
https://yq.aliyun.com/articles/64691
http://pwn4.fun/2017/04/04/Android%E9%80%86%E5%90%91%E4%B9%8B%E8%84%B1%E5%A3%B3/
