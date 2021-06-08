---
title: Android逆向入门（四）
date: 2020-02-14 14:21:40
tags: [re, android]
---

Android 加壳和脱壳入门。

<!-- more -->

# dex 文件格式

Android 程序编译以后生成 apk 文件，里面的 classes.dex 文件存放着程序运行的字节码，dex 文件是可以直接在 Dalvik 虚拟机中加载运行的文件。由于 Dalvik 是一种针对嵌入式设备而特殊设计的 Java 虚拟机，所以 dex 文件与标准的 class 文件在结构设计上有着本质的区别。当 Java 程序编译成 class 后，还需要使用 dx 工具将所有的 class 文件整合到一个 dex 文件，目的是其中各个类能够共享数据，在一定程度上降低了冗余，同时也是文件结构更加经凑，dex 文件是传统 jar 文件大小的 50% 左右。要想手工脱壳，必须先了解 dex 的文件格式。

![](/pics/Android逆向入门/四/1.png)

ShakaApktool 使用 bs 命令即可对 class.dex 实现反编译回 smali 文件字节码，而使用 s 命令可以把 smali 字节码编译为 class.dex 文件：

```bash
java -jar ShakaApktool bs classes.dex -o smali-dir
java -jar ShakaApktool s smali-dir -o example.dex
```

dex 文件的数据结构大概如下：

|  数据名称  |                               解释                               |
| :--------: | :--------------------------------------------------------------: |
|   header   |            dex 文件头部，记录整个 dex 文件的相关属性             |
| string_ids |         字符串数据索引，记录了每个字符串在数据区的偏移量         |
|  type_ids  |             类似数据索引，记录了每个类型的字符串索引             |
| proto_ids  |  原型数据索引，记录了方法声明的字符串，返回类型字符串，参数列表  |
| field_ids  |            字段数据索引，记录了所属类，类型以及方法名            |
| method_ids |      类方法索引，记录方法所属类名，方法声明以及方法名等信息      |
| class_defs | 类定义数据索引，记录指定类各类信息，包括接口，超类，类数据偏移量 |
|    data    |                  数据区，保存了各个类的真是数据                  |
| link_data  |                            连接数据区                            |

这里先看一下 Android 源码，首先在 [/dalvik/vm/Common.h](http://androidxref.com/4.1.1/xref/dalvik/vm/Common.h) 中对数据类型有一个重命名：

```cpp
/*
 * These match the definitions in the VM specification.
 */
typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;
```

所有 dex 文件相关的数据结构都在 [/dalvik/libdex/DexFile.h](http://androidxref.com/4.1.1/xref/dalvik/libdex/DexFile.h) 中。dex 文件的结构如下：

```cpp
/*
 * Structure representing a DEX file.
 *
 * Code should regard DexFile as opaque, using the API calls provided here
 * to access specific structures.
 */
struct DexFile {
    /* directly-mapped "opt" header */
    const DexOptHeader* pOptHeader;

    /* pointers to directly-mapped structs and arrays in base DEX */
    const DexHeader*    pHeader;
    const DexStringId*  pStringIds;
    const DexTypeId*    pTypeIds;
    const DexFieldId*   pFieldIds;
    const DexMethodId*  pMethodIds;
    const DexProtoId*   pProtoIds;
    const DexClassDef*  pClassDefs;
    const DexLink*      pLinkData;

    /*
     * These are mapped out of the "auxillary" section, and may not be
     * included in the file.
     */
    const DexClassLookup* pClassLookup;
    const void*         pRegisterMapPool;       // RegisterMapClassPool

    /* points to start of DEX file data */
    const u1*           baseAddr;

    /* track memory overhead for auxillary structures */
    int                 overhead;

    /* additional app-specific data structures associated with the DEX */
    //void*               auxData;
};
```

dex 文件结构分别为文件头、索引区和数据区：

![](/pics/Android逆向入门/四/2.png)

## dex 文件头

文件头中简单记录了 dex 文件的一些基本信息，以及大致的数据分布。长度固定为 0x70，其中每一项信息所占用的内存空间也是固定的，好处是虚拟机在处理 dex 时不用考虑 dex 文件的多样性：

|    字段名称     | 偏移值 | 长度 |                  说明                   |
| :-------------: | :----: | :--: | :-------------------------------------: |
|      magic      |  0x00  |  8   |       魔数字段，值为"dex\n035\0"        |
|    checksum     |  0x08  |  4   |                 校验码                  |
|    signature    |  0x0c  |  20  |               sha-1 签名                |
|    file_size    |  0x20  |  4   |             dex 文件总长度              |
|   header_size   |  0x24  |  4   | 文件头长度，009 版本=0x5c,035 版本=0x70 |
|   endian_tag    |  0x28  |  4   |           标示字节顺序的常量            |
|    link_size    |  0x2c  |  4   |   链接段的大小，如果为 0 就是静态链接   |
|    link_off     |  0x30  |  4   |            链接段的开始位置             |
|     map_off     |  0x34  |  4   |              map 数据基址               |
| string_ids_size |  0x38  |  4   |         字符串列表中字符串个数          |
| string_ids_off  |  0x3c  |  4   |             字符串列表基址              |
|  type_ids_size  |  0x40  |  4   |           类列表里的类型个数            |
|  type_ids_off   |  0x44  |  4   |               类列表基址                |
| proto_ids_size  |  0x48  |  4   |         原型列表里面的原型个数          |
|  proto_ids_off  |  0x4c  |  4   |              原型列表基址               |
| field_ids_size  |  0x50  |  4   |                字段个数                 |
|  field_ids_off  |  0x54  |  4   |              字段列表基址               |
| method_ids_size |  0x58  |  4   |                方法个数                 |
| method_ids_off  |  0x5c  |  4   |              方法列表基址               |
| class_defs_size |  0x60  |  4   |           类定义标中类的个数            |
| class_defs_off  |  0x64  |  4   |             类定义列表基址              |
|    data_size    |  0x68  |  4   |       数据段的大小，必须 4k 对齐        |
|    data_off     |  0x6c  |  4   |               数据段基址                |

文件头的数据结构如下：

```cpp
/*
 * Direct-mapped "header_item" struct.
 */
struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
};
```

## 索引区

索引区包括 string_ids、type_ids、proto_ids、field_ids、method_ids 几个数据结构。数组结构如下：

```cpp
/*
 * Direct-mapped "string_id_item".
 */
struct DexStringId {
    u4 stringDataOff;      /* file offset to string_data_item */
};

/*
 * Direct-mapped "type_id_item".
 */
struct DexTypeId {
    u4  descriptorIdx;      /* index into stringIds list for type descriptor */
};

/*
 * Direct-mapped "field_id_item".
 */
struct DexFieldId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  typeIdx;            /* index into typeIds for field type */
    u4  nameIdx;            /* index into stringIds for field name */
};

/*
 * Direct-mapped "method_id_item".
 */
struct DexMethodId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  protoIdx;           /* index into protoIds for method prototype */
    u4  nameIdx;            /* index into stringIds for method name */
};

/*
 * Direct-mapped "proto_id_item".
 */
struct DexProtoId {
    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
    u4  returnTypeIdx;      /* index into typeIds list for return type */
    u4  parametersOff;      /* file offset to type_list for parameter types */
};
```

## 数据区

数据段包括 class_defs、data、link_data，数据结构如下：

```cpp
/*
 * Direct-mapped "map_item".
 */
struct DexMapItem {
    u2 type;              /* type code (see kDexType* above) */
    u2 unused;
    u4 size;              /* count of items of the indicated type */
    u4 offset;            /* file offset to the start of data */
};

/*
 * Direct-mapped "map_list".
 */
struct DexMapList {
    u4  size;               /* #of entries in list */
    DexMapItem list[1];     /* entries */
};

/*
 * Direct-mapped "class_def_item".
 */
struct DexClassDef {
    u4  classIdx;           /* index into typeIds for this class */
    u4  accessFlags;
    u4  superclassIdx;      /* index into typeIds for superclass */
    u4  interfacesOff;      /* file offset to DexTypeList */
    u4  sourceFileIdx;      /* index into stringIds for source file name */
    u4  annotationsOff;     /* file offset to annotations_directory_item */
    u4  classDataOff;       /* file offset to class_data_item */
    u4  staticValuesOff;    /* file offset to DexEncodedArray */
};

/*
 * Link table.  Currently undefined.
 */
struct DexLink {
    u1  bleargh;
};
```

# 动态代码自修改（加壳原理）

DexClassDef -> DexClassData -> DexMethod -> DexCode -> insns

```cpp
/*
 * Direct-mapped "code_item".
 *
 * The "catches" table is used when throwing an exception,
 * "debugInfo" is used when displaying an exception stack trace or
 * debugging. An offset of zero indicates that there are no entries.
 */
struct DexCode {
    u2  registersSize;      // 使用的寄存器个数
    u2  insSize;            // 参数个数
    u2  outsSize;           // 调用其他方法时使用的寄存器个数
    u2  triesSize;          // Try/Catch的个数
    u4  debugInfoOff;       // 指令调试信息的偏移 /* file offset to debug info stream */
    u4  insnsSize;          // 指令集个数，以2字节为单位 /* size of the insns array, in u2 units */
    u2  insns[1];           // 指令集
    /* followed by optional u2 padding */
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
};
```

其中，insns 的值是用于存放程序实现代码的地方。程序执行的时候会把整个 dex 文件加载到内存之中，然后动态地解析执行 insns 中的内容。只要修改了里面的数据，就相当于修改了程序执行流程。

## 修改 insns

### 直接在内存中修改

1. 定位到 dex 文件
2. 计算函数的 DexCode 位置
3. 重写 DexCode 的 insns 数据

#### [JNI Bridge](http://androidxref.com/4.1.1/xref/dalvik/vm/Jni.cpp)

JNI 提供了让我们在 C++代码层中直接操作 Dalvik（Java）数据的接口，可以直接在 JNI 中操作相关数据来修改 Android 中的代码。

#### [Object 结构体](http://androidxref.com/4.1.1/xref/dalvik/vm/oo/Object.cpp)

Android 运行时，解析 dex 文件，并生成相关的结构体：[DvmDex](http://androidxref.com/4.1.1/xref/dalvik/vm/DvmDex.cpp)。其中存储了各种字符串、类、方法等信息。加载的时候，调用 `dvmDexFileOpenPartial` 对 dex 文件进行解析，并转化为可执行的结构体，这也是这个函数可以作为脱壳用的函数的原因之一。（以前的爱加密可以直接通过 Hook 这个函数进行脱壳）。

其中 Method 结构体是根据 DexMethod 生成的执行方法类。Dalvik 执行代码时，都是从 Method 中取出代码来执行的。因此可以直接通过操作 Method 结构体来修改执行的代码。

#### Example

首先新建一个 JNI 项目，并新建两个函数 `ret1()` 和 `ret2()` 函数，以及一个 Native 函数 `changeMethod()`：

```java
package com.assassinq.editdexfile;

import android.os.Bundle;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;

import java.lang.reflect.Method;

public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("hello");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    Method m = MainActivity.class.getMethod("ret1");
                    Log.d("DEBUG", "Return Value = " + ret1());
                    changeMethod(m);
                    Log.d("DEBUG", "Return Value = " + ret1());
                } catch (Exception e) {
//                    e.printStackTrace();
                    Log.d("EXCEPTION", Log.getStackTraceString(e));
                }
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public int ret1() {
        return 1;
    }

    public int ret2() {
        return 2;
    }

    // public native void changeMethod(Method r1);
}
```

先编译生成一个不包含 JNI 的 apk，解压后取出其中的 classes.dex，然后在 010 Editor 中用 DEX Template 解析，找到 DexCode 中的 insns，并记录下 `ret1()` 和 `ret2()` 的字节码：

![](/pics/Android逆向入门/四/3.png)

然后完善 JNI 函数，并且需要导入 Android 源码中 Dalvik 文件夹下相关的头文件。JNI 实现如下，将 `ret1()` 所指向的字节码修改为 `ret2()` 的字节码：

```cpp
#include <jni.h>
#include <string.h>
#include <android/log.h>
#include "Object.h"
#include "Common.h"

#ifdef LOG_TAG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#endif

const char insns[] = {0x12, 0x20, 0x0F, 0x00};

void changeMethod(JNIEnv *env, jobject obj, jobject method) {
    /*
     * 12 10 0F 00 -> ret 1
     * 12 20 0F 00 -> ret 2
     */
    Method *pMethod = (Method *) env->FromReflectedMethod(method);
    pMethod->insns = (const u2*) insns;
}

static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods,
                                 int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static const char *gClassName = "com/assassinq/editdexfile/MainActivity";
static JNINativeMethod gMethods[] = {
        {"changeMethod", "(Ljava/lang/reflect/Method;)V", (void *) changeMethod},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("This jni version is not supported");
        return -1;
    }
    if (registerNativeMethods(env, gClassName, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) ==
        JNI_FALSE) {
        LOGE("Unable to register native methods");
        return -1;
    }
    LOGE("Methods loaded successfully");
    return JNI_VERSION_1_6;
}
```

运行程序并点击触发事件，查看日志发现修改生效：

```log
02-11 11:29:39.202 1795-1795/com.assassinq.editdexfile D/DEBUG: Return Value = 1
02-11 11:29:39.202 1795-1795/com.assassinq.editdexfile D/DEBUG: Return Value = 2
```

### IDA 中动态修改

1. Ctrl+s 打开 map 数据
2. 查找内存加载的额 classes.dex 的位置
3. 直接计算偏移，修改相应的位置

### 内存修改的另一种方法

修改方法定位：dexClassDef 遍历以获取 MethodId，对比 MethodName 与 proto 以获取目标 Method，然后对相应的 DexCode 进行修改。由于 Dex 加载到内存中是只有只读权限，故需要先修改内存页的权限才能正常地修改 DexCode 数据。

遍历 Map：

```cpp
void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];
    if (pid < 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            LOGD("%s", line);
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return (void *) addr;
}
```

重置 Map 属性：

```cpp
#include <asm-generic/mman-common.h>
#include <sys/mman.h>
#include <limits.h>

if (mprotect(PAGE_START((int)(pCode->insns)), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
    *(u4 *)(pCode->insns) = 0x000f2012;
    mprotect(PAGE_START((int)(pCode->insns)), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
}
```

#### Example

接下来编写 changeMethod2 函数，利用 dalvik 中的一些函数来逐步定位到指定函数：

```cpp
void changeMethod2(JNIEnv *env, jobject obj) {
    u1 *pDex = (u1 *) get_module_base(-1, "/data/dalvik-cache/data@app@com.assassinq.editdexfile");
    if (pDex != NULL) {
        LOGD("Get Module");
        pDex += sizeof(DexOptHeader);
        DexFile *pDexFile = dexFileParse(pDex, sizeof(DexHeader), kDexParseContinueOnError);
        if (pDexFile == NULL) {
            LOGE("Unable to parse DexFile");
            return;
        }
        const DexClassDef *pClassDef;
        for (int i = 0; i < pDexFile->pHeader->classDefsSize; ++i) {
            const DexClassDef *pDef = dexGetClassDef(pDexFile, i);
            if (!strcmp(dexStringByTypeIdx(pDexFile, pDef->classIdx),
                        "Lcom/assassinq/editdexfile/MainActivity;")) {
                pClassDef = pDef;
                break;
            }
        }
        if (pClassDef != NULL) {
            LOGD("Class Found");
            const u1 *pData = dexGetClassData(pDexFile, pClassDef);
            if (pData) {
                DexClassData *pClassData = dexReadAndVerifyClassData(&pData, NULL);
                for (int i = 0; i < pClassData->header.virtualMethodsSize; ++i) {
                    DexMethod *pMethod = &pClassData->virtualMethods[i];
                    const DexMethodId *pMethodId = dexGetMethodId(pDexFile, pMethod->methodIdx);
                    if (!strcmp(dexStringById(pDexFile, pMethodId->nameIdx), "ret1")) {
                        const DexCode *pCode = dexGetCode(pDexFile, pMethod);
                        LOGD("Method found and try to patch");
                        if (mprotect((void *) PAGE_START((int) (pCode->insns)), PAGE_SIZE,
                                     PROT_READ | PROT_WRITE) == 0) {
                            *(u4 *) (pCode->insns) = 0x000F2012;
                            mprotect((void *) PAGE_START((int) (pCode->insns)), PAGE_SIZE,
                                     PROT_READ);
                        }
                    }
                }
                free(pClassData);
            }
        }
        dexFileFree(pDexFile);
    }
}


static JNINativeMethod gMethods[] = {
        ...
        {"changeMethod2", "()V",                           (void *) changeMethod2},
};

...
```

在 app 下的 build.gradle 中修改以强制转换指针：

```
android {
    ...
    defaultConfig {
        ...
        externalNativeBuild {
            cmake {
                cppFlags "-fpermissive"
            }
        }
    }
    ...
}
```

TODO

# DVM 脱壳

目前存在对 apk 中的 classes.dex 进行加密的技术，称为加壳。通过对 dex 文件的加壳，可以达到减少体积，隐藏真实代码的效果。Android 的壳与 PE 文件一样，在程序运行时，先到达壳的入口点，运行解壳代码，然后再到达程序入口点并运行代码。如果要脱壳，就需要在程序解码完毕并到达程序真实入口点中间某个位置，把原始的 dex 代码给 dump 下来，还原到 apk 文件中。

## 查壳

壳入口：

```xml
<application android:name="com.ali.mobisecenhance.SubApplication" />
```

程序入口：

```xml
<activity android:name="com.ali.encryption.MainActivity" />
```

## assets 分析

assets 中一般存储着加密过的 dex，以及解密用的 so 等信息，因此先分析 assets 可以有效获取程序解壳思路。

## ProxyApplication 分析

## 壳代码分析

壳代码中 Java 层转 Native 层：

```java
protected native void attachBaseContext(Context arg1) {} // 还原代码
public native void onCreate() {} // 执行原始代码
```

## so 文件分析

带压缩的，一般用 libz 中的 uncompress 函数进行解码，可以用该函数进行快速定位。

## IDA 中 dump 数据

在 Native 层中解密 dex 数据并还原后，替换为原始 Application。IDC Dump 脚本：

```cpp
static main(void) {
    auto fp, begin, end, len, b;
    fp = fopen("dump.data", "wb");
    begin = 0x544D2008; // 解密后数据在内存中的位置
    len = 0x019CF4; // 文件大小
    end = begin + len;
    for (b = begin; b < end; b++) {
        fputc(Byte(b), fp);
    }
}
```

## Dex 加载流程

vm->native->dalvik_systm_DexFile->openDexFile，读取内存中的 Dex 文件数据，并加载 Dalvik_dalvik_system_DexFile_openDexFile_bytearray。

```cpp
// 转换存储的dex格式为可执行的dex格式
dvmRawDexFileOpenArray(pBytes, length, &pRawDexFile);
// 添加到gDvm中
addToDexFileTable(pDexOrJar);
```

壳实现加载流程：

1. 内存中解密 dex 函数
2. 将 dex 存储结构转换为可执行结构
3. 添加到 gDvm 中（有些壳是自己实现了这个功能，有些是调用了系统的函数）
4. 抹去 dex 存储结构中的有效数据

## 内存 dex 定位

gDvm.userDexFiles 是存放 dex cookie（dexOfJar 结构）的地方，因此可以通过遍历该数据结构来获得每个 dex 文件的起始地址。

Dex 重构：通过分析内存中的 dex 存储结构，完成对整个 dex 文件的 dump。

Dex 转 Odex：优化 vm\analysis\Optimize.cpp->dvmOptimizeClass

Dex 校验：vm\analysis\DexVerify.cpp->dvmVerifyClass

取消非必要优化与校验：\system\build.prop => Dalvik.vm.dexopt-flag=v=n,o=n

# ELF 文件简介（ARM 架构下的 ELF）

## 文件结构

ELF 在加载前和加载后的文件格式是完全不同的，给加密提供了方便。

![](/pics/Android逆向入门/四/4.png)

链接执行时，Section Header 中的表将会被映射到 Program Header 中，里面的 ELF Header、Program Header 和 Section header 非常重要，Linker 会根据这三个头信息进行 so 文件加载。

PS：如何从内存中 dump 下 so 文件？开启 IDA 动态调试，在 Module 窗口中找到对应的 so 文件，根据 so 文件的起始地址和文件大小，使用 IDC 脚本 dump 下来。

### ELF Header

存储 so 文件最为基本的信息，如 so 运行的 CPU 平台、Program Header 数量、Section Header 数量等，重要性等同于 Dex Header。

```bash
$ readelf -h libxtian.so
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          117240 (bytes into file)
  Flags:                             0x5000200, Version5 EABI, soft-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         8
  Size of section headers:           40 (bytes)
  Number of section headers:         25
  Section header string table index: 24
```

### Section Header

存储 so 的链接用信息，主要是用于给外部程序详细地提供本 so 的信息，比如第几行对应哪个函数、什么名字、对应着源码的什么位置等等。IDA 就是通过读取该头信息进行 so 分析的。

```bash
$ readelf -S libxtian.so
There are 25 section headers, starting at offset 0x1c9f8:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.build-i NOTE            00000134 000134 000024 00   A  0   0  4
  [ 2] .dynsym           DYNSYM          00000158 000158 000570 10   A  3   1  4
  [ 3] .dynstr           STRTAB          000006c8 0006c8 00034e 00   A  0   0  1
  [ 4] .hash             HASH            00000a18 000a18 000270 04   A  2   0  4
  [ 5] .gnu.version      VERSYM          00000c88 000c88 0000ae 02   A  2   0  2
  [ 6] .gnu.version_d    VERDEF          00000d38 000d38 00001c 00   A  3   1  4
  [ 7] .gnu.version_r    VERNEED         00000d54 000d54 000020 00   A  3   1  4
  [ 8] .rel.dyn          REL             00000d74 000d74 0050f8 08   A  2   0  4
  [ 9] .rel.plt          REL             00005e6c 005e6c 0000a0 08  AI  2  10  4
  [10] .plt              PROGBITS        00005f0c 005f0c 000104 00  AX  0   0  4
  [11] .text             PROGBITS        00006010 006010 013684 00  AX  0   0  4
  [12] .ARM.extab        PROGBITS        00019694 019694 0001a4 00   A  0   0  4
  [13] .ARM.exidx        ARM_EXIDX       00019838 019838 000250 08  AL 11   0  4
  [14] .rodata           PROGBITS        00019a90 019a90 0002d0 00   A  0   0 16
  [15] .fini_array       FINI_ARRAY      0001ad64 019d64 000008 00  WA  0   0  4
  [16] .init_array       INIT_ARRAY      0001ad6c 019d6c 000004 00  WA  0   0  1
  [17] .dynamic          DYNAMIC         0001ad70 019d70 000120 08  WA  3   0  4
  [18] .got              PROGBITS        0001ae90 019e90 000170 00  WA  0   0  4
  [19] .data             PROGBITS        0001b000 01a000 002870 00  WA  0   0 16
  [20] .bss              NOBITS          0001d870 01c870 0001d8 00  WA  0   0  4
  [21] .comment          PROGBITS        00000000 01c870 00003d 01  MS  0   0  1
  [22] .note.gnu.gold-ve NOTE            00000000 01c8b0 00001c 00      0   0  4
  [23] .ARM.attributes   ARM_ATTRIBUTES  00000000 01c8cc 000036 00      0   0  1
  [24] .shstrtab         STRTAB          00000000 01c902 0000f6 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
```

### Program Header

存储 so 文件运行时需要的信息。该信息会直接被 Linker 所使用，运用于 so 加载。因此这个 Header 的数据是肯定可信的

```bash
$ readelf -l libxtian.so

Elf file type is DYN (Shared object file)
Entry point 0x0
There are 8 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00000034 0x00000034 0x00100 0x00100 R   0x4
  LOAD           0x000000 0x00000000 0x00000000 0x19d60 0x19d60 R E 0x1000
  LOAD           0x019d64 0x0001ad64 0x0001ad64 0x02b0c 0x02ce4 RW  0x1000
  DYNAMIC        0x019d70 0x0001ad70 0x0001ad70 0x00120 0x00120 RW  0x4
  NOTE           0x000134 0x00000134 0x00000134 0x00024 0x00024 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0
  EXIDX          0x019838 0x00019838 0x00019838 0x00250 0x00250 R   0x4
  GNU_RELRO      0x019d64 0x0001ad64 0x0001ad64 0x0029c 0x0029c RW  0x4

 Section to Segment mapping:
  Segment Sections...
   00
   01     .note.gnu.build-id .dynsym .dynstr .hash .gnu.version .gnu.version_d .gnu.version_r .rel.dyn .rel.plt .plt .text .ARM.extab .ARM.exidx .rodata
   02     .fini_array .init_array .dynamic .got .data .bss
   03     .dynamic
   04     .note.gnu.build-id
   05
   06     .ARM.exidx
   07     .fini_array .init_array .dynamic .got
```

## 加载 so 的流程

Android 上的 ELF 文件是通过 Linker（位于 Bionic/Linker）加载到内存中并进行执行的。所以通过研究 Linker 可以清楚地知道 Android 系统到底使用了到了 so 的哪些数据。Linker 启动时会先对自身的函数表数据等进行重定位，然后再对其他 so 文件进行定位。

Linkere 加载中只会用到 Program Header（甚至直接删除 Section Header 也是可以的）。Program Header 解析：

```cpp
link.cpp -> soinfo *do_dlopen(const char *name, int flags) // so加载
find_library(name);
si->CallConstructors();
CallFunction("DT_INIT", init_func); // so脱壳点
CallArray("DT_INIT_ARRAY", init_array, init_array_count, false); // dex脱壳点
```

加载 so 的时候，有两种加载方式，一个是直接 load，还有一个是 loadLibrary。无论是哪种方式，都会先获取 ClassLoader，然后再调用相应的方法。当传进来的 loader 不为空，则会调用 findLibrary 方法，然后执行 doLoad 方法，如果 loader 为空，则会执行另一个流程，但是后面也会执行 doLoad 方法。

## ELF 文件变形与保护（阻碍分析）

- Section 段处理：鉴于 Section Header 没有被 Linker 用于加载，所以可以对 Section 段写入无用数据，可以阻碍静态分析软件的分析。
- Program 段处理：Program 段中可以对 DYNAMIC 区段进行混淆，添加重复的数据以及无效的数据。

# so 文件加壳修复

```bash
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  EXIDX          0x02867c 0x0002867c 0x0002867c 0x00568 0x00568 R   0x4
  LOAD           0x000000 0x00000000 0x00000000 0x13294 0x13294 R E 0x8000
  LOAD           0x018c10 0x00030c10 0x00030c10 0x0052c 0x01548 RW  0x8000
  DYNAMIC        0x018c74 0x00030c74 0x00030c74 0x00108 0x00108 RW  0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
  GNU_RELRO      0x018c10 0x00030c10 0x00030c10 0x003f0 0x003f0 R   0x1
```

加过壳的标志：`FileSiz!=MemSiz`，明显存在加载后在内存进行解码的可能。函数地址也在文件之外。

修复：dump 内存，数据对齐重定位。

# Android 源码定制添加反反调试基址

反调试一般会检测 proc 下是否有 status/stat 文件。首先修改 kernel 源码中的 `fs/proc/base.c`。修改 proc_pid_wchan 函数的返回值：

```cpp
static int proc_pid_wchan(struct task_struct *task, char *buffer)
{
        unsigned long wchan;
        char symname[KSYM_NAME_LEN];

        wchan = get_wchan(task);

        if (lookup_symbol_name(wchan, symname) < 0)
                if (!ptrace_may_access(task, PTRACE_MODE_READ))
                        return 0;
                else
                        return sprintf(buffer, "%lu", wchan);
        else {
                if (strstr(symname, "trace")) { // 检测进程中是否有trace这个字符串
                        return sprintf(buffer, "%s", "sys_epoll_wait"); // sys_epoll_wait用来获取文件状态已经就绪的事件
                }
                return sprintf(buffer, "%s", symname);
        }
}
```

然后是 `fs/proc/array.c` 文件，分别修改 tast_state 函数和 task_state_array 变量：

```cpp
static inline void task_state(struct seq_file *m, struct pid_namespace *ns,
                                struct pid *pid, struct task_struct *p)
{
        struct group_info *group_info;
        int g;
        struct fdtable *fdt = NULL;
        const struct cred *cred;
        pid_t ppid, tpid;

        rcu_read_lock();
        ppid = pid_alive(p) ?
                task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;
        tpid = 0;
        if (pid_alive(p)) {
                struct task_struct *tracer = ptrace_parent(p);
                if (tracer)
                        tpid = task_pid_nr_ns(tracer, ns);
        }
        cred = get_task_cred(p);
        seq_printf(m,
                "State:\t%s\n"
                "Tgid:\t%d\n"
                "Pid:\t%d\n"
                "PPid:\t%d\n"
                "TracerPid:\t%d\n"
                "Uid:\t%d\t%d\t%d\t%d\n"
                "Gid:\t%d\t%d\t%d\t%d\n",
                get_task_state(p),
                task_tgid_nr_ns(p, ns),
                pid_nr_ns(pid, ns),
                ppid, 0, // 把tpid修改为0
                cred->uid, cred->euid, cred->suid, cred->fsuid,
                cred->gid, cred->egid, cred->sgid, cred->fsgid);

        task_lock(p);
        if (p->files)
                fdt = files_fdtable(p->files);
        seq_printf(m,
                "FDSize:\t%d\n"
                "Groups:\t",
                fdt ? fdt->max_fds : 0);
        rcu_read_unlock();

        group_info = cred->group_info;
        task_unlock(p);

        for (g = 0; g < min(group_info->ngroups, NGROUPS_SMALL); g++)
                seq_printf(m, "%d ", GROUP_AT(group_info, g));
        put_cred(cred);

        seq_putc(m, '\n');
}

static const char * const task_state_array[] = {
        "R (running)",          /*   0 */
        "S (sleeping)",         /*   1 */
        "D (disk sleep)",       /*   2 */
        "S (sleeping)",         // "T (stopped)",          /*   4 */
        "S (sleeping)",         // "t (tracing stop)",     /*   8 */
        "Z (zombie)",           /*  16 */
        "X (dead)",             /*  32 */
        "x (dead)",             /*  64 */
        "K (wakekill)",         /* 128 */
        "W (waking)",           /* 256 */
};
```

然后可以根据[这篇文章](https://se8s0n.github.io/2019/04/19/%E5%B0%9D%E8%AF%95%E7%BB%95%E8%BF%87TracePID%E5%8F%8D%E8%B0%83%E8%AF%95%E4%BA%8C%E2%80%94%E2%80%94%E4%BB%8E%E6%BA%90%E7%A0%81%E5%85%A5%E6%89%8B/)把 boot.img 重新打包并刷入手机。

# Refereences

https://www.bilibili.com/video/av45424886
https://www.jianshu.com/p/f7f0a712ddfe
https://source.android.com/devices/tech/dalvik/dex-format.html
https://www.jianshu.com/p/f7f0a712ddfe
http://gnaixx.cc/2016/11/26/20161126dex-file/
https://www.cnblogs.com/stars-one/p/8890162.html
http://shxi.me/posts/7b82cd68.html
