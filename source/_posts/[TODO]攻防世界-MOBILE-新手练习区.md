---
title: 攻防世界-MOBILE-新手练习区
date: 2020-02-20 19:51:47
tags: [re, android]
---

持续更新。

<!-- more -->

# app1

将 apk 拖入 jadx 进行反编译，查看入口点 MainActivity 代码：

```java
package com.example.yaphetshan.tencentgreat;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.support.v4.view.accessibility.AccessibilityNodeInfoCompat;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
    Button btn;
    public final String pName = BuildConfig.APPLICATION_ID;
    EditText text;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_main);
        this.btn = (Button) findViewById(R.id.checBtn);
        this.text = (EditText) findViewById(R.id.input);
        this.btn.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                try {
                    String inputString = MainActivity.this.text.getText().toString();
                    PackageInfo pinfo = MainActivity.this.getPackageManager().getPackageInfo(BuildConfig.APPLICATION_ID, AccessibilityNodeInfoCompat.ACTION_COPY);
                    String versionCode = pinfo.versionName; // 获取包信息中的versionName
                    int versionName = pinfo.versionCode; // 获取包信息中的versionCode
                    int i = 0;
                    while (i < inputString.length() && i < versionCode.length()) {
                        if (inputString.charAt(i) != (versionCode.charAt(i) ^ versionName)) { // 将versionCode中的每一字节和versionName异或并和输入比较
                            Toast.makeText(MainActivity.this, "\u518d\u63a5\u518d\u5389\uff0c\u52a0\u6cb9~", 1).show(); // 再接再厉，加油~
                            return;
                        }
                        i++;
                    }
                    if (inputString.length() == versionCode.length()) { // 判断输入的长度和versionCode是否相同
                        Toast.makeText(MainActivity.this, "\u606d\u559c\u5f00\u542f\u95ef\u5173\u4e4b\u95e8\uff01", 1).show(); // 恭喜开启闯关之门！
                        return;
                    }
                } catch (NameNotFoundException e) {
                }
                Toast.makeText(MainActivity.this, "\u5e74\u8f7b\u4eba\u4e0d\u8981\u800d\u5c0f\u806a\u660e\u5662", 1).show(); // 年轻人不要耍小聪明噢
            }
        });
    }
}
```

代码中可以判断出是将 versionCode 和 versionName 进行异或然后和输入比较，具体信息可以在 AndroidManifest.xml 中找到：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="15" android:versionName="X<cP[?PHNB<P?aj" package="com.example.yaphetshan.tencentgreat" platformBuildVersionCode="25" platformBuildVersionName="7.1.1">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="25" />
    <uses-permission android:name="android.permission.INTERNET" />
    <meta-data android:name="android.support.VERSION" android:value="25.3.0" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round">
        <activity android:name="com.example.yaphetshan.tencentgreat.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

编写脚本来得到 flag：

```python
#!/usr/bin/env python
versionCode = 15
versionName = "X<cP[?PHNB<P?aj"
flag = ''
for c in versionName:
    flag += chr(ord(c) ^ versionCode)
print flag
# W3l_T0_GAM3_0ne
```

# app2

先使用 jadx 反编译，查看入口点的代码，在两个输入框中输入字符串后会去调用 SecondActivity：

```java
package com.tencent.testvuln;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.BuildConfig;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import com.tencent.testvuln.c.SignatureTool;

@SuppressLint({"ShowToast"})
public class MainActivity extends Activity implements OnClickListener {
    private Button a;
    private Handler b = null;
    private EditText c;
    private EditText d;

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.a = (Button) findViewById(R.id.button1);
        this.a.setOnClickListener(this);
        this.c = (EditText) findViewById(R.id.editText1);
        this.d = (EditText) findViewById(R.id.editText2);
        Editor edit = getSharedPreferences("test", 0).edit();
        edit.putLong("ili", System.currentTimeMillis());
        edit.commit();
        Log.d("hashcode", SignatureTool.getSignature(this) + BuildConfig.VERSION_NAME);
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(menuItem);
    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.button1:
                if (this.c.getText().length() == 0 || this.d.getText().length() == 0) {
                    Toast.makeText(this, "\u4e0d\u80fd\u4e3a\u7a7a", 1).show(); // 不能为空
                    return;
                }
                String obj = this.c.getText().toString(); // 获取第一个输入框中的字符串
                String obj2 = this.d.getText().toString(); // 获取第二个输入框中的字符串
                Log.e("test", obj + " test2 = " + obj2);
                Intent intent = new Intent(this, SecondActivity.class); // 设置Intent跳转到SecondActivity
                intent.putExtra("ili", obj); // 设置变量ili的值为obj的值
                intent.putExtra("lil", obj2); // 设置变量lil的值为obj2的值
                startActivity(intent); // 调用SecondActivity
                return;
            default:
                return;
        }
    }
}
```

接下来看看 SecondActivity，将输入的字符串拼接起来，经过 Encryto.doRawData 的操作后和一串 base64 进行比较：

```java
package com.tencent.testvuln;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import com.tencent.testvuln.c.Encryto;

public class SecondActivity extends a {
    private BroadcastReceiver c = new BroadcastReceiver(this) {
        final /* synthetic */ SecondActivity a;

        {
            this.a = r1;
        }

        public void onReceive(Context context, Intent intent) {
            Toast.makeText(context, "myReceiver receive", 0).show();
            if (!context.getPackageName().equals(intent.getAction())) {
            }
        }
    };

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main2);
        Intent intent = getIntent();
        String stringExtra = intent.getStringExtra("ili"); // obj
        String stringExtra2 = intent.getStringExtra("lil"); // obj2
        if (Encryto.doRawData(this, stringExtra + stringExtra2).equals("VEIzd/V2UPYNdn/bxH3Xig==")) { // 判断obj+obj2经过Encryto.doRawData后是否等于指定字符串
            intent.setAction("android.test.action.MoniterInstallService");
            intent.setClass(this, MoniterInstallService.class);
            intent.putExtra("company", "tencent");
            intent.putExtra("name", "hacker");
            intent.putExtra("age", 18);
            startActivity(intent);
            startService(intent);
        }
        Editor edit = getSharedPreferences("test", 0).edit();
        edit.putString("ilil", stringExtra);
        edit.putString("lili", stringExtra2);
        edit.commit();
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(menuItem);
    }
}
```

然后我找到了 Encryto.doRawData 函数的位置。可以看到这里的所有函数都是在 Native 层实现的：

```java
package com.tencent.testvuln.c;

public class Encryto {
    public static native int checkSignature(Object obj);

    public static native String decode(Object obj, String str);

    public static native String doRawData(Object obj, String str);

    public static native String encode(Object obj, String str);

    public native String HelloLoad();

    static {
        System.loadLibrary("JNIEncrypt");
    }
}
```

用 IDA 打开 libJNIEncrypt.so，然后定位到 JNI_OnLoad，并找到被动态注册的函数：

```
.data:00006008 off_6008        DCD aChecksignature_0   ; DATA XREF: register_ndk_load+22↑o
.data:00006008                                         ; .text:off_221C↑o
.data:00006008                                         ; "checkSignature"
.data:0000600C                 DCD aLjavaLangObjec     ; "(Ljava/lang/Object;)I"
.data:00006010                 DCD check+1
.data:00006014                 DCD aDecode_0           ; "decode"
.data:00006018                 DCD aLjavaLangObjec_0   ; "(Ljava/lang/Object;Ljava/lang/String;)L"...
.data:0000601C                 DCD decode+1
.data:00006020                 DCD aEncode_0           ; "encode"
.data:00006024                 DCD aLjavaLangObjec_0   ; "(Ljava/lang/Object;Ljava/lang/String;)L"...
.data:00006028                 DCD encode+1
.data:0000602C                 DCD aDorawdata_0        ; "doRawData"
.data:00006030                 DCD aLjavaLangObjec_0   ; "(Ljava/lang/Object;Ljava/lang/String;)L"...
.data:00006034                 DCD doRawData+1
.data:00006034 ; .data         ends
```

看一下其中的 doRawData 函数，发现其中调用了一个 j_AES_128_ECB_PKCS5Padding_Encrypt 函数，可以大概推断出经过了 AES-128 的加密，且加密模式用了 ECB，Padding 用了 PKCS5：

```cpp
int __fastcall doRawData(_JNIEnv *env, int a2, int a3, char *string)
{
  _JNIEnv *v4; // r4
  char *v5; // r9
  const char *utf_string; // r6
  int ciphertext; // r8
  int result; // r0
  jstring (__cdecl *v9)(JNIEnv *, const jchar *, jsize); // r6
  char *v10; // r5
  size_t v11; // r2
  int key; // [sp+0h] [bp-28h]
  int v13; // [sp+18h] [bp-10h]

  v4 = env;
  v5 = string;
  if ( j_checkSignature((int)env, a2, a3) == 1
    && (strcpy((char *)&key, "thisisatestkey=="),
        utf_string = (const char *)((int (__fastcall *)(_JNIEnv *, char *, _DWORD))v4->functions->GetStringUTFChars)(
                                     v4,
                                     v5,
                                     0),
        ciphertext = j_AES_128_ECB_PKCS5Padding_Encrypt(utf_string, (int)&key),
        ((void (__fastcall *)(_JNIEnv *, char *, const char *))v4->functions->ReleaseStringUTFChars)(v4, v5, utf_string),
        result = ((int (__fastcall *)(_JNIEnv *, int))v4->functions->NewStringUTF)(v4, ciphertext),
        _stack_chk_guard == v13) )
  {
    return result;
  }
  do
  {
    v9 = v4->functions->NewString;
    v10 = UNSIGNATURE[0];
    v11 = strlen(UNSIGNATURE[0]);
  }
  while ( _stack_chk_guard != v13 );
  result = ((int (__fastcall *)(_JNIEnv *, char *, size_t))v9)(v4, v10, v11);
  return result;
}
```

然后进去看到加密完成之后进行了 base64 加密在返回密文：

```cpp
int __fastcall AES_128_ECB_PKCS5Padding_Encrypt(const char *a1, int a2)
{
  int v2; // r9
  const char *v3; // r10
  signed int v4; // r0
  signed int v5; // r5
  _BYTE *v6; // r11
  signed int v7; // r0
  const char *v8; // r1
  signed int v9; // r8
  char *v10; // r10
  int v11; // r5
  _BYTE *v12; // r0
  signed int v13; // r2
  char v14; // r6
  int v15; // r6
  int v16; // r4
  int v17; // r5

  v2 = a2;
  v3 = a1;
  v4 = strlen(a1);
  v5 = v4;
  if ( v4 <= 15 )
  {
    v6 = malloc(0x10u);
    v7 = 0;
    do
    {
      v8 = &byte_3BB0[16 - v5];
      if ( v7 < v5 )
        v8 = &v3[v7];
      v6[v7++] = *v8;
    }
    while ( v7 != 16 );
    v9 = 16;
    v10 = (char *)malloc(0x10u);
    v11 = 1;
LABEL_18:
    v15 = 0;
    v16 = 0;
    do
    {
      j_AES128_ECB_encrypt(&v6[v15], v2, &v10[v15]);
      ++v16;
      v15 += 16;
    }
    while ( v16 < v11 );
    goto LABEL_22;
  }
  v9 = (v4 + 16) & 0xFFFFFFF0;
  v12 = malloc(v9);
  v6 = v12;
  if ( v9 <= 0 )
  {
    v10 = (char *)malloc((v5 + 16) & 0xFFFFFFF0);
    goto LABEL_22;
  }
  v13 = 0;
  do
  {
    if ( v13 >= v5 )
    {
      if ( !(v5 & 0xF) )
      {
        v12[v13] = 16;
        goto LABEL_15;
      }
      v14 = byte_3BB0[v9 - v5];
    }
    else
    {
      v14 = v3[v13];
    }
    v12[v13] = v14;
LABEL_15:
    ++v13;
  }
  while ( v9 != v13 );
  v10 = (char *)malloc((v5 + 16) & 0xFFFFFFF0);
  if ( v9 >= 16 )
  {
    v11 = v9 / 16;
    goto LABEL_18;
  }
LABEL_22:
  v17 = j_b64_encode((int)v10, v9);
  free(v6);
  free(v10);
  return v17;
}
```

用 Python 脚本解密得到明文：

```python
#!/usr/bin/env python
from Crypto.Cipher import AES

key = 'thisisatestkey=='
aes = AES.new(key, AES.MODE_ECB)

ciphertext = 'VEIzd/V2UPYNdn/bxH3Xig=='.decode('base64')
print aes.decrypt(ciphertext)
# aimagetencent
```

尝试提交这串字符串提示错误，再尝试用这字符串登录也没得到什么结果，那么继续往下分析。发现其中调用了多次 Intent，还设置了 IntentFilter，看的眼花缭乱都没找到 flag 在哪里。再去尝试一下交叉引用，看看哪些类调用了 Encryto 类，发现了 FileDataActivity 类中调用了 decode 方法，在 IDA 中可以发现 decode 和 doRawData 的功能一模一样：

```java
package com.tencent.testvuln;

import android.os.Bundle;
import android.widget.TextView;
import com.tencent.testvuln.c.Encryto;

public class FileDataActivity extends a {
    private TextView c;

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main3);
        this.c = (TextView) findViewById(R.id.textView1);
        this.c.setText(Encryto.decode(this, "9YuQ2dk8CSaCe7DTAmaqAA=="));
    }
}
```

最后用这里的密文解密得到了 flag：

```python
...
ciphertext2 = '9YuQ2dk8CSaCe7DTAmaqAA=='.decode('base64')
print aes.decrypt(ciphertext2)
# Cas3_0f_A_CAK3
```

# app3

拿到文件用 file 没有识别出来，xxd 看一下：

```bash
$ xxd app3.ab | head
00000000: 414e 4452 4f49 4420 4241 434b 5550 0a32  ANDROID BACKUP.2
00000010: 0a31 0a6e 6f6e 650a 78da e47a e55f 936f  .1.none.x..z._.o
00000020: fcaf 8a74 8e1e 0d1b 5d63 0361 303a 4797  ...t....]c.a0:G.
00000030: 8422 3d06 8ab4 c248 a507 a373 3046 2328  ."=....H...s0F#(
00000040: 2a65 a088 d20c 4623 8222 4883 a252 5202  *e....F#."H..RR.
00000050: 9e7d 7fe7 75fe 80f3 e43c 39d7 93fb 75bf  .}..u....<9...u.
00000060: b6dd d775 7de2 1df7 2e8f a0a0 5045 afc0  ...u}.......PE..
00000070: bb0a a808 8fbb 41fe 2805 8c47 902f 2a2c  ......A.(..G./*,
00000080: d4d7 2340 210c 15e0 850a 080b 47f9 53be  ..#@!.......G.S.
00000090: 8052 f450 f4f4 0845 2978 04dd b9f4 7f37  .R.P...E)x.....7
```

搜了一下发现是安卓备份文件，可以用 Android Backup Extractor 来解压：

```bash
$ java -jar abe.jar unpack app3.ab app3.tar ""
0% 1% 2% 3% 4% 5% 6% 7% 8% 9% 10% 11% 12% 13% 14% 15% 16% 17% 18% 19% 20% 21% 22% 23% 24% 25% 26% 27% 28% 29% 30% 31% 32% 33% 34% 35% 36% 37% 38% 39% 40% 41% 42% 43% 44% 45% 46% 47% 48% 49% 50% 51% 52% 53% 54% 55% 56% 57% 58% 59% 60% 61% 62% 63% 64% 65% 66% 67% 68% 69% 70% 71% 72% 73% 74% 75% 76% 77% 78% 79% 80% 81% 82% 83% 84% 85% 86% 87% 88% 89% 90% 91% 92% 93% 94% 95% 96% 97% 98% 99% 100%
9097216 bytes written to /Users/assassinq/Downloads/app3.tar.
```

在解压得到的 tar 包：

```bash
$ x app3.tar
x apps/com.example.yaphetshan.tencentwelcome/a/base.apk
x apps/com.example.yaphetshan.tencentwelcome/db/Demo.db
x apps/com.example.yaphetshan.tencentwelcome/Encryto.db
x apps/com.example.yaphetshan.tencentwelcome/_manifest
```

生成的文件中，两个 db 都是被加密了的 sqlite 数据库。先来用 jadx 看看 base.apk，可以看到 `a()` 函数通过一些操作计算出一个密码，来获得一个数据库的接口。详细分析我记录在了注释中，其他的分析再看之后的函数：

```java
package com.example.yaphetshan.tencentwelcome;

import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import com.example.yaphetshan.tencentwelcome.a.a;
import net.sqlcipher.database.SQLiteDatabase;

public class MainActivity extends AppCompatActivity implements OnClickListener {
    private SQLiteDatabase a;
    private a b;
    private Button c;

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_main);
        this.c = (Button) findViewById(R.id.add_data);
        this.c.setOnClickListener(this);
        Editor edit = getSharedPreferences("test", 0).edit();
        edit.putString("Is_Encroty", "1"); // Is_Encroty="1"
        edit.putString("Encryto", "SqlCipher"); // Encryto="SqlCipher"
        edit.putString("ver_sion", "3_4_0"); // ver_sion="3_4_0"
        edit.apply();
        a();
    }

    private void a() {
        SQLiteDatabase.loadLibs(this);
        this.b = new a(this, "Demo.db", null, 1); // 打开Demo.db
        ContentValues contentValues = new ContentValues();
        contentValues.put("name", "Stranger"); // name="Stanger"
        contentValues.put("password", Integer.valueOf(123456)); // password=123456
        a aVar = new a();
        String a = aVar.a(contentValues.getAsString("name"), contentValues.getAsString("password")); // a = name[:4] + password[:4]
        this.a = this.b.getWritableDatabase(aVar.a(a + aVar.b(a, contentValues.getAsString("password"))).substring(0, 7)); // 将SHA1(a+MD5(a)+"yaphetshan")[:7]作为密码，获取指定数据库接口
        this.a.insert("TencentMicrMsg", null, contentValues); // 将数据contentValues插入表TencentMicrMsg
    }

    public void onClick(View view) {
        if (view == this.c) {
            Intent intent = new Intent();
            intent.putExtra("name", "name");
            intent.putExtra("password", "pass");
            intent.setClass(this, AnotherActivity.class);
            startActivity(intent);
        }
    }
}
```

在同一包下的 a 类中，看到了数据库 TencentMicrMsg 的结构，其中有一个 F_l_a_g 字段，可以判断是 flag：

```java
package com.example.yaphetshan.tencentwelcome;

import android.content.Context;
import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteDatabase.CursorFactory;
import net.sqlcipher.database.SQLiteOpenHelper;

/* compiled from: DatabaseManager */
public class a extends SQLiteOpenHelper {
    private int a = 0;

    public a(Context context, String str, CursorFactory cursorFactory, int i) { // 打开指定数据库
        super(context, str, cursorFactory, i);
    }

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        sQLiteDatabase.execSQL("create table TencentMicrMsg(name text,password integer,F_l_a_g text)"); // 表TencentMicrMsg中三个字段分别是text、integer和text
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }
}
```

在包 a 下的 a 类，其中两个函数可以根据 b 类的函数分析得到功能：

```java
package com.example.yaphetshan.tencentwelcome.a;

/* compiled from: Cipher */
public class a {
    private String a = "yaphetshan";

    public String a(String str, String str2) {
        String substring = str.substring(0, 4);
        return substring + str2.substring(0, 4);
    }

    public String b(String str, String str2) { // 返回MD5十六进制字符串
        b bVar = new b();
        return b.a(str);
    }

    public String a(String str) { // 返回SHA1(str+"yaphetshan")的十六进制字符串
        b bVar = new b();
        return b.b(str + this.a);
    }
}
```

包 a 下的 b 类，根据 MessageDigest 创建的实例可以分别判断出是获取 MD5 和 SHA-1 的十六进制摘要：

```java
package com.example.yaphetshan.tencentwelcome.a;

import java.security.MessageDigest;

/* compiled from: SHA1Manager */
public class b {
    public static final String a(String str) { // 获取MD5十六进制字符串
        int i = 0;
        char[] cArr = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            byte[] bytes = str.getBytes();
            MessageDigest instance = MessageDigest.getInstance("MD5");
            instance.update(bytes);
            byte[] digest = instance.digest(); // 获取MD5哈希摘要
            int length = digest.length;
            char[] cArr2 = new char[(length * 2)];
            int i2 = 0;
            while (i < length) {
                byte b = digest[i];
                int i3 = i2 + 1;
                cArr2[i2] = cArr[(b >>> 4) & 15];
                i2 = i3 + 1;
                cArr2[i3] = cArr[b & 15];
                i++;
            }
            return new String(cArr2);
        } catch (Exception e) {
            return null;
        }
    }

    public static final String b(String str) { // 获取SHA1十六进制字符串
        int i = 0;
        char[] cArr = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            byte[] bytes = str.getBytes();
            MessageDigest instance = MessageDigest.getInstance("SHA-1");
            instance.update(bytes);
            byte[] digest = instance.digest(); // 获取SHA1哈希摘要
            int length = digest.length;
            char[] cArr2 = new char[(length * 2)];
            int i2 = 0;
            while (i < length) {
                byte b = digest[i];
                int i3 = i2 + 1;
                cArr2[i2] = cArr[(b >>> 4) & 15];
                i2 = i3 + 1;
                cArr2[i3] = cArr[b & 15];
                i++;
            }
            return new String(cArr2);
        } catch (Exception e) {
            return null;
        }
    }
}
```

那么根据上面的分析可以正向地得到密码：

```python
#!/usr/bin/env python
import hashlib

md5hash = lambda m: hashlib.md5(m).hexdigest()
sha1hash = lambda m: hashlib.sha1(m).hexdigest()

name = "Stranger"
password = "123456"
a = name[:4] + password[:4]
database = sha1hash(a + md5hash(a) + "yaphetshan")[:7]
print database
# ae56f99
```

打开 Decypt.db 库，查看表中数据：

![](/pics/攻防世界-MOBILE-新手练习区/1.png)

将字段中的字符串解 base64：

```bash
$ echo "VGN0ZntIM2xsMF9Eb19ZMHVfTG92M19UZW5jM250IX0=" | base64 -D
Tctf{H3ll0_Do_Y0u_Lov3_Tenc3nt!}
```

# easy-apk

把 apk 拖进 jadx，反编译查看入口事件代码，判断出对输入进行了 Base64 加密：

```java
package com.testjava.jack.pingan1;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_main);
        ((Button) findViewById(R.id.button)).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                if (new Base64New().Base64Encode(((EditText) MainActivity.this.findViewById(R.id.editText)).getText().toString().getBytes()).equals("5rFf7E2K6rqN7Hpiyush7E6S5fJg6rsi5NBf6NGT5rs=")) {
                    Toast.makeText(MainActivity.this, "\u9a8c\u8bc1\u901a\u8fc7!", 1).show(); // 验证通过!
                } else {
                    Toast.makeText(MainActivity.this, "\u9a8c\u8bc1\u5931\u8d25!", 1).show(); // 验证失败!
                }
            }
        });
    }
}
```

再看看 Base64New 类中代码，发现是一个换表的 base64：

```java
package com.testjava.jack.pingan1;

import android.support.v4.view.accessibility.AccessibilityNodeInfoCompat;

public class Base64New {
    private static final char[] Base64ByteToStr = new char[]{'v', 'w', 'x', 'r', 's', 't', 'u', 'o', 'p', 'q', '3', '4', '5', '6', '7', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'y', 'z', '0', '1', '2', 'P', 'Q', 'R', 'S', 'T', 'K', 'L', 'M', 'N', 'O', 'Z', 'a', 'b', 'c', 'd', 'U', 'V', 'W', 'X', 'Y', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', '8', '9', '+', '/'};
    private static final int RANGE = 255;
    private static byte[] StrToBase64Byte = new byte[AccessibilityNodeInfoCompat.ACTION_CLEAR_ACCESSIBILITY_FOCUS];

    public String Base64Encode(byte[] bytes) {
        StringBuilder res = new StringBuilder();
        for (int i = 0; i <= bytes.length - 1; i += 3) {
            int k;
            byte[] enBytes = new byte[4];
            byte tmp = (byte) 0;
            for (k = 0; k <= 2; k++) {
                if (i + k <= bytes.length - 1) {
                    enBytes[k] = (byte) (((bytes[i + k] & RANGE) >>> ((k * 2) + 2)) | tmp);
                    tmp = (byte) ((((bytes[i + k] & RANGE) << (((2 - k) * 2) + 2)) & RANGE) >>> 2);
                } else {
                    enBytes[k] = tmp;
                    tmp = (byte) 64;
                }
            }
            enBytes[3] = tmp;
            for (k = 0; k <= 3; k++) {
                if (enBytes[k] <= (byte) 63) {
                    res.append(Base64ByteToStr[enBytes[k]]);
                } else {
                    res.append('=');
                }
            }
        }
        return res.toString();
    }
}
```

直接改表解码：

```python
#!/usr/bin/env python
#-*- encoding=utf-8 -*-
from utils import *

base64_charset = 'vwxrstuopq34567ABCDEFGHIJyz012PQRSTKLMNOZabcdUVWXYefghijklmn89+/='

ciphertext = '5rFf7E2K6rqN7Hpiyush7E6S5fJg6rsi5NBf6NGT5rs='
plaintext = decipher(ciphertext)
print plaintext
# 05397c42f9b6da593a3644162d36eb01
```

# easyjava

jadx 反编译，MainActivity 中看到主要是 `b()` 函数判断了 flag 的格式，下面主要是把 a 和 b 两个类的构造函数理清：

```java
package com.a.easyjava;

import android.os.Bundle;
import android.support.v7.app.c;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.Toast;
import java.util.Timer;
import java.util.TimerTask;

public class MainActivity extends c {
    private static char a(String str, b bVar, a aVar) {
        return aVar.a(bVar.a(str));
    }

    private static Boolean b(String str) {
        int i = 0;
        if (!str.startsWith("flag{")) {
            return Boolean.valueOf(false);
        }
        if (!str.endsWith("}")) {
            return Boolean.valueOf(false);
        }
        String substring = str.substring(5, str.length() - 1);
        b bVar = new b(Integer.valueOf(2));
        a aVar = new a(Integer.valueOf(3));
        StringBuilder stringBuilder = new StringBuilder();
        int i2 = 0;
        while (i < substring.length()) {
            stringBuilder.append(a(substring.charAt(i) + "", bVar, aVar));
            Integer valueOf = Integer.valueOf(bVar.b().intValue() / 25); // 将bVar中d的值除以25并赋值给valueOf
            if (valueOf.intValue() > i2 && valueOf.intValue() >= 1) {
                i2++;
            }
            i++;
        }
        return Boolean.valueOf(stringBuilder.toString().equals("wigwrkaugala"));
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_main);
        findViewById(R.id.button).setOnClickListener(new OnClickListener(this) {
            final /* synthetic */ MainActivity b;

            public void onClick(View view) {
                if (MainActivity.b(((EditText) ((MainActivity) this).findViewById(R.id.edit)).getText().toString()).booleanValue()) {
                    Toast.makeText(this, "You are right!", 1).show();
                    return;
                }
                Toast.makeText(this, "You are wrong! Bye~", 1).show();
                new Timer().schedule(new TimerTask(this) {
                    final /* synthetic */ AnonymousClass1 a;

                    {
                        this.a = r1;
                    }

                    public void run() {
                        System.exit(1);
                    }
                }, 2000);
            }
        });
    }
}
```

a 类的构造函数，是对数组 c 的重新排列。然后在 `a()` 函数中对输入的数字和下标进行转换：

```java
package com.a.easyjava;

import java.util.ArrayList;

public class a {
    public static ArrayList<Integer> a = new ArrayList();
    static String b = "abcdefghijklmnopqrstuvwxyz";
    static Integer d = Integer.valueOf(0);
    Integer[] c = new Integer[]{Integer.valueOf(7), Integer.valueOf(14), Integer.valueOf(16), Integer.valueOf(21), Integer.valueOf(4), Integer.valueOf(24), Integer.valueOf(25), Integer.valueOf(20), Integer.valueOf(5), Integer.valueOf(15), Integer.valueOf(9), Integer.valueOf(17), Integer.valueOf(6), Integer.valueOf(13), Integer.valueOf(3), Integer.valueOf(18), Integer.valueOf(12), Integer.valueOf(10), Integer.valueOf(19), Integer.valueOf(0), Integer.valueOf(22), Integer.valueOf(2), Integer.valueOf(11), Integer.valueOf(23), Integer.valueOf(1), Integer.valueOf(8)};

    public a(Integer num) {
        int intValue;
        for (intValue = num.intValue(); intValue < this.c.length; intValue++) {
            a.add(this.c[intValue]);
        }
        for (intValue = 0; intValue < num.intValue(); intValue++) {
            a.add(this.c[intValue]);
        }
    }

    public static void a() {
        Integer num = d;
        d = Integer.valueOf(d.intValue() + 1); // 将d加一
        if (d.intValue() == 25) { // 判断d是否等于25
            int intValue = ((Integer) a.get(0)).intValue();
            a.remove(0);
            a.add(Integer.valueOf(intValue)); // 将a的第一个元素添加到最后一位
            d = Integer.valueOf(0); // 将d设置成0
        }
    }

    public char a(Integer num) {
        int i = 0;
        Integer valueOf = Integer.valueOf(0);
        if (num.intValue() == -10) { // 判断num是否为-10
            a();
            return " ".charAt(0);
        }
        while (i < a.size() - 1) {
            if (a.get(i) == num) {
                valueOf = Integer.valueOf(i); // 获取a中等于num的元素，并将valueOf设置成其下标i
            }
            i++;
        }
        a();
        return b.charAt(valueOf.intValue()); // 返回下标对应的b中的字符
    }
}
```

b 类中同理，也是对下标的一个转换：

```java
package com.a.easyjava;

import java.util.ArrayList;

public class b {
    public static ArrayList<Integer> a = new ArrayList();
    static String b = "abcdefghijklmnopqrstuvwxyz";
    static Integer d = Integer.valueOf(0);
    Integer[] c = new Integer[]{Integer.valueOf(8), Integer.valueOf(25), Integer.valueOf(17), Integer.valueOf(23), Integer.valueOf(7), Integer.valueOf(22), Integer.valueOf(1), Integer.valueOf(16), Integer.valueOf(6), Integer.valueOf(9), Integer.valueOf(21), Integer.valueOf(0), Integer.valueOf(15), Integer.valueOf(5), Integer.valueOf(10), Integer.valueOf(18), Integer.valueOf(2), Integer.valueOf(24), Integer.valueOf(4), Integer.valueOf(11), Integer.valueOf(3), Integer.valueOf(14), Integer.valueOf(19), Integer.valueOf(12), Integer.valueOf(20), Integer.valueOf(13)};

    public b(Integer num) {
        int intValue;
        for (intValue = num.intValue(); intValue < this.c.length; intValue++) {
            a.add(this.c[intValue]);
        }
        for (intValue = 0; intValue < num.intValue(); intValue++) {
            a.add(this.c[intValue]);
        }
    }

    public static void a() {
        int intValue = ((Integer) a.get(0)).intValue();
        a.remove(0);
        a.add(Integer.valueOf(intValue)); // 将a的第一个元素添加到最后一位
        b += "" + b.charAt(0);
        b = b.substring(1, 27); // 将b的第一个元素添加到最后一位
        Integer num = d;
        d = Integer.valueOf(d.intValue() + 1); // 将d加一
    }

    public Integer a(String str) {
        int i = 0;
        Integer valueOf = Integer.valueOf(0);
        if (b.contains(str.toLowerCase())) { // 判断字符串是否在“abcdefghijklmnopqrstuvwxyz”中
            Integer valueOf2 = Integer.valueOf(b.indexOf(str)); // str在b中的起始下标
            while (i < a.size() - 1) {
                if (a.get(i) == valueOf2) { // 获取a中与valueOf2相等的值，并设置valueOf为其下标i
                    valueOf = Integer.valueOf(i);
                }
                i++;
            }
        } else {
            valueOf = str.contains(" ") ? Integer.valueOf(-10) : Integer.valueOf(-1); // 判断字符串中是否有空格，如果有valueOf设置成-10，反之设置成-1
        }
        a();
        return valueOf;
    }

    public Integer b() {
        return d;
    }
}
```

其中有很多条件判断不可能发生，实际的算法逻辑没有反编译出的代码这么复杂。逆向实现脚本：

```python
#!/usr/bin/env python
bArray = [17, 23, 7, 22, 1, 16, 6, 9, 21, 0, 15, 5, 10, 18, 2, 24, 4, 11, 3, 14, 19, 12, 20, 13, 8, 25]
aArray = [21, 4, 24, 25, 20, 5, 15, 9, 17, 6, 13, 3, 18, 12, 10, 19, 0, 22, 2, 11, 23, 1, 8, 7, 14, 16]

ciphertext = 'wigwrkaugala'
table = 'abcdefghijklmnopqrstuvwxyz'
valueOfArray = []
for i in range(len(ciphertext)):
    valueOfArray.append(table.index(ciphertext[i]))
print valueOfArray

numArray = []
for i in range(len(valueOfArray)):
    numArray.append(aArray[valueOfArray[i]])
print numArray

prefix = 'flag{'
suffix = '}'
substring = ''
for i in range(len(numArray)):
    ch = table[bArray[numArray[i]]]
    substring += ch
    bArray.append(bArray[0])
    del bArray[0]
    table = (table + table[0])[1:27]
flag = prefix + substring + suffix
print flag
```

# easyjni

反编译，其中调用了 a 函数，其中调用了 a 类中的 a 函数和在 libnative.so 实现的 ncheck 函数：

```java
package com.a.easyjni;

import android.os.Bundle;
import android.support.v7.app.c;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends c {
    static {
        System.loadLibrary("native");
    }

    private boolean a(String str) {
        try {
            return ncheck(new a().a(str.getBytes()));
        } catch (Exception e) {
            return false;
        }
    }

    private native boolean ncheck(String str);

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_main);
        findViewById(R.id.button).setOnClickListener(new OnClickListener(this) {
            final /* synthetic */ MainActivity b;

            public void onClick(View view) {
                if (this.b.a(((EditText) ((MainActivity) this).findViewById(R.id.edit)).getText().toString())) {
                    Toast.makeText(this, "You are right!", 1).show();
                } else {
                    Toast.makeText(this, "You are wrong! Bye~", 1).show();
                }
            }
        });
    }
}
```

a 类里的 a 函数很容易发现是个换表 base64：

```java
package com.a.easyjni;

public class a {
    private static final char[] a = new char[]{'i', '5', 'j', 'L', 'W', '7', 'S', '0', 'G', 'X', '6', 'u', 'f', '1', 'c', 'v', '3', 'n', 'y', '4', 'q', '8', 'e', 's', '2', 'Q', '+', 'b', 'd', 'k', 'Y', 'g', 'K', 'O', 'I', 'T', '/', 't', 'A', 'x', 'U', 'r', 'F', 'l', 'V', 'P', 'z', 'h', 'm', 'o', 'w', '9', 'B', 'H', 'C', 'M', 'D', 'p', 'E', 'a', 'J', 'R', 'Z', 'N'};

    public String a(byte[] bArr) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i <= bArr.length - 1; i += 3) {
            byte[] bArr2 = new byte[4];
            byte b = (byte) 0;
            for (int i2 = 0; i2 <= 2; i2++) {
                if (i + i2 <= bArr.length - 1) {
                    bArr2[i2] = (byte) (b | ((bArr[i + i2] & 255) >>> ((i2 * 2) + 2)));
                    b = (byte) ((((bArr[i + i2] & 255) << (((2 - i2) * 2) + 2)) & 255) >>> 2);
                } else {
                    bArr2[i2] = b;
                    b = (byte) 64;
                }
            }
            bArr2[3] = b;
            for (int i3 = 0; i3 <= 3; i3++) {
                if (bArr2[i3] <= (byte) 63) {
                    stringBuilder.append(a[bArr2[i3]]);
                } else {
                    stringBuilder.append('=');
                }
            }
        }
        return stringBuilder.toString();
    }
}
```

查看 native 层 ncheck 函数，是静态注册的。理一下发现是个简单的置换：

```cpp
signed int __fastcall Java_com_a_easyjni_MainActivity_ncheck(_JNIEnv *a1, int a2, jstring a3)
{
  int v3; // r8
  _JNIEnv *env; // r5
  jstring str; // r8
  const char *utf_string; // r6
  int i; // r0
  char *v8; // r2
  char v9; // r1
  int j; // r0
  bool v11; // nf
  unsigned __int8 v12; // vf
  int v13; // r1
  signed int result; // r0
  char s1[32]; // [sp+3h] [bp-35h]
  char tmp; // [sp+23h] [bp-15h]
  int v17; // [sp+28h] [bp-10h]

  v17 = v3;
  env = a1;
  str = a3;
  utf_string = a1->functions->GetStringUTFChars(&a1->functions, a3, 0);
  if ( strlen(utf_string) == 32 )               // len(str) == 32
  {
    i = 0;
    do
    {
      v8 = &s1[i];
      s1[i] = utf_string[i + 16];               // s1[i] = str[i + 16]
      v9 = utf_string[i++];
      v8[16] = v9;                              // s1[i + 16] = str[i]
    }
    while ( i != 16 );
    env->functions->ReleaseStringUTFChars(&env->functions, str, utf_string);
    j = 0;
    do
    {
      v12 = __OFSUB__(j, 30);
      v11 = j - 30 < 0;
      tmp = s1[j];
      s1[j] = s1[j + 1];
      s1[j + 1] = tmp;                          // s1[j], s1[j + 1] = s1[j + 1], s1[j]
      j += 2;
    }
    while ( v11 ^ v12 );                        // while j <= 30
    v13 = memcmp(s1, "MbT3sQgX039i3g==AQOoMQFPskB1Bsc7", 0x20u);
    result = 0;
    if ( !v13 )
      result = 1;
  }
  else
  {
    env->functions->ReleaseStringUTFChars(&env->functions, str, utf_string);
    result = 0;
  }
  return result;
}
```

逆向把位置颠倒的字符串倒回去，再用改表的 base64 解码：

```python
#!/usr/bin/env python
from base64 import *

base64_charset = 'i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN='

ciphertext = 'MbT3sQgX039i3g==AQOoMQFPskB1Bsc7'
ciphertext = [ord(c) for c in ciphertext]
for i in range(len(ciphertext) / 2):
    ciphertext[2 * i], ciphertext[2 * i + 1] = ciphertext[2 * i + 1], ciphertext[2 * i]
print ciphertext

for i in range(len(ciphertext) / 2):
    ciphertext[i], ciphertext[i + 16] = ciphertext[i + 16], ciphertext[i]
print ciphertext

ciphertext = ''.join([chr(c) for c in ciphertext])
print ciphertext
# QAoOQMPFks1BsB7cbM3TQsXg30i9g3==
plaintext = decipher(ciphertext)
print plaintext
# flag{just_ANot#er_@p3}
```

# easy-so

用 jadx 反编译后，看到调用了 cyberpeace 类中的 CheckString 函数：

```java
package com.testjava.jack.pingan2;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_main);
        ((Button) findViewById(R.id.button)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (cyberpeace.CheckString(((EditText) MainActivity.this.findViewById(R.id.editText)).getText().toString()) == 1) {
                    Toast.makeText(MainActivity.this, "\u9a8c\u8bc1\u901a\u8fc7!", 1).show(); // 验证通过!
                } else {
                    Toast.makeText(MainActivity.this, "\u9a8c\u8bc1\u5931\u8d25!", 1).show(); // 验证失败!
                }
            }
        });
    }
}
```

看到函数在 Native 层实现：

```java
package com.testjava.jack.pingan2;

public class cyberpeace {
    public static native int CheckString(String str);

    static {
        System.loadLibrary("cyberpeace");
    }
}
```

发现是静态实现的函数，其中将输入调用了 TestDec，并将结果和指定字符串比较：

```cpp
signed int __fastcall Java_com_testjava_jack_pingan2_cyberpeace_CheckString(_JNIEnv *a1, int a2, jstring *str)
{
  signed int v3; // r8
  const char *str_1; // r9
  int v5; // r6
  const char *v6; // r5
  signed int v7; // r1

  v3 = 0;
  str_1 = a1->functions->GetStringUTFChars(&a1->functions, str, 0);
  v5 = strlen(str_1);
  v6 = (const char *)malloc(v5 + 1);
  v7 = 0;
  if ( v5 != -1 )
    v7 = 1;
  _aeabi_memclr(&v6[v5], v7);
  _aeabi_memcpy((int)v6, (int)str_1, v5);
  j_TestDec((int)v6);
  if ( !strcmp(v6, "f72c5a36569418a20907b55be5bf95ad") )
    v3 = 1;
  return v3;
}
```

看一下 TestDec 发现和之前一样，也是一组简单置换：

```cpp
size_t __fastcall TestDec(const char *a1)
{
  char *str; // r4
  size_t i; // r5
  char *v3; // r1
  char v4; // r0
  size_t result; // r0
  int j; // r5
  char *v7; // r0
  char v8; // r1
  unsigned int v9; // r1

  str = (char *)a1;
  if ( strlen(a1) >= 2 )
  {
    i = 0;
    do
    {
      v3 = &str[i];
      v4 = str[i];
      str[i] = str[i + 16];
      ++i;
      v3[16] = v4;                              // str[i], str[i + 16] = str[i + 16], str[i]
    }
    while ( i < strlen(str) >> 1 );
  }
  result = (unsigned __int8)*str;
  if ( !*str )
    return result;
  *str = str[1];
  str[1] = result;                              // str[0], str[1] = str[1], str[0]
  result = strlen(str);
  if ( result < 3 )
    return result;
  j = 0;
  do
  {
    v7 = &str[j];
    v8 = str[j + 2];
    v7[2] = str[j + 3];
    v7[3] = v8;                                 // str[j + 2], str[j + 3] = str[j + 3], str[j + 2]
    result = strlen(str);
    v9 = j + 4;
    j += 2;
  }
  while ( v9 < result );
  return result;
}
```

照样学样逆一下就好了：

```python
#!/usr/bin/env python
ciphertext = 'f72c5a36569418a20907b55be5bf95ad'
ciphertext = [ord(c) for c in ciphertext]
ciphertext[0], ciphertext[1] = ciphertext[1], ciphertext[0]
for i in range(len(ciphertext) / 2 - 1):
    ciphertext[2 * i + 2], ciphertext[2 * i + 3] = ciphertext[2 * i + 3], ciphertext[2 * i + 2]
print ciphertext

for i in range(len(ciphertext) / 2):
    ciphertext[i], ciphertext[i + 16] = ciphertext[i + 16], ciphertext[i]
print ciphertext

plaintext = ''.join([chr(c) for c in ciphertext])
print plaintext
# 90705bb55efb59da7fc2a5636549812a
```

# Ph0en1x-100

MainActivity 中，encrypt 和 getFlag 函数在 Native 层实现，getSecret 函数返回某种哈希摘要的十六进制字符串。输入经过 encrypt 函数操作后的值与 getFlag 的值相等：

```java
package com.ph0en1x.android_crackme;

import android.os.Bundle;
import android.support.v4.view.MotionEventCompat;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MainActivity extends AppCompatActivity {
    EditText etFlag;

    public native String encrypt(String str);

    public native String getFlag();

    static {
        System.loadLibrary("phcm");
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_main);
        this.etFlag = (EditText) findViewById(R.id.flag_edit);
    }

    public void onGoClick(View v) {
        if (getSecret(getFlag()).equals(getSecret(encrypt(this.etFlag.getText().toString())))) {
            Toast.makeText(this, "Success", 1).show();
        } else {
            Toast.makeText(this, "Failed", 1).show();
        }
    }

    public String getSecret(String string) { // 获取某种哈希摘要的十六进制字符串
        try {
            byte[] hash = MessageDigest.getInstance(encrypt("KE3TLNE6M43EK4GM34LKMLETG").substring(5, 8)).digest(string.getBytes("UTF-8"));
            if (hash != null) {
                StringBuilder hex = new StringBuilder(hash.length * 2);
                for (byte b : hash) {
                    if ((b & MotionEventCompat.ACTION_MASK) < 16) {
                        hex.append("0");
                    }
                    hex.append(Integer.toHexString(b & MotionEventCompat.ACTION_MASK));
                }
                return hex.toString();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
        return null;
    }
}
```

在 IDA 中看到静态注册的 encrypt 函数，对字符串的每个值进行了减一操作：

```cpp
jstring __fastcall Java_com_ph0en1x_android_1crackme_MainActivity_encrypt(_JNIEnv *a1, int a2, jstring a3)
{
  _JNIEnv *v3; // r6
  const char *v4; // r4
  const char *i; // r5

  v3 = a1;
  v4 = a1->functions->GetStringUTFChars(&a1->functions, a3, 0);
  for ( i = v4; i - v4 < strlen(v4); ++i )
    --*i;
  return v3->functions->NewStringUTF(&v3->functions, v4);
}
```

反向加一，得到指定的哈希摘要是 MD5：

```python
#!/usr/bin/env python
import hashlib

md5hash = lambda m: hashlib.md5(m).hexdigest()

secret_digest = 'KE3TLNE6M43EK4GM34LKMLETG'
digest_type = ''
for i in range(len(secret_digest)):
    digest_type += chr(ord(secret_digest[i]) - 1)
digest_type = digest_type[5:8]
print digest_type
# MD5
```

接下来看 getFlag 函数，读取内存中 data 的值，在循环中对相邻两个值进行相减并加 1，然后和 key 值异或，最后返回字符串：

```cpp
jstring __fastcall Java_com_ph0en1x_android_1crackme_MainActivity_getFlag(_JNIEnv *a1)
{
  char *v1; // r4
  _JNIEnv *v2; // r7
  char *v3; // r3
  int v4; // r0
  int v5; // r1
  char *v6; // r2
  char *v7; // r3
  int v8; // r0
  int v9; // r1
  int v10; // r4
  int v11; // r0
  __int16 v12; // r3
  signed int l1; // r8
  signed int l2; // r0
  char *v15; // r9
  char a; // r3
  char b; // t1
  int idx; // r1
  char s; // [sp+4h] [bp-5Ch]
  char data_1[40]; // [sp+14h] [bp-4Ch]
  char v22; // [sp+40h] [bp-20h]

  v1 = data_1;
  v2 = a1;
  v3 = (char *)&data;
  do
  {
    v4 = *(_DWORD *)v3;                         // low 4 bytes
    v3 += 8;
    v5 = *((_DWORD *)v3 - 1);                   // high 4 bytes
    *(_DWORD *)v1 = v4;
    *((_DWORD *)v1 + 1) = v5;
    v1 += 8;
  }
  while ( v3 != "Hello Ph0en1x" );
  v6 = &s;
  v7 = "Hello Ph0en1x";
  do
  {
    v8 = *(_DWORD *)v7;
    v7 += 8;
    v9 = *((_DWORD *)v7 - 1);
    *(_DWORD *)v6 = v8;
    *((_DWORD *)v6 + 1) = v9;
    v10 = (int)(v6 + 8);
    v6 += 8;
  }
  while ( v7 != "0en1x" );
  v11 = *(_DWORD *)v7;
  v12 = *((_WORD *)v7 + 2);
  *(_DWORD *)v10 = v11;
  *(_WORD *)(v10 + 4) = v12;
  l1 = strlen(&s);                              // len('Hello Ph0en1x')
  l2 = strlen(data_1) - 1;                      // len(data) - 1
  v15 = &data_1[l2];
  while ( l2 > 0 )
  {
    a = *v15 + 1;
    *v15 = a;                                   // data[l2] = data[l2] + 1
    b = *(v15-- - 1);                           // data[l2 - 1]
    idx = l2-- % l1;                            // l2 % l1
    v15[1] = ((a - b) ^ *(&v22 + idx - 60)) - 1;// data[l2] = ((data[l2 + 1] - data[l2 - 1]) ^ s[idx]) - 1
  }
  data_1[0] = (data_1[0] ^ 0x48) - 1;
  return v2->functions->NewStringUTF(&v2->functions, data_1);
}
```

因为涉及到了异或和减法的操作，需要注意到及时和 0xFF 与一下，不然结果会出错。脚本：

```python
data = [0x2E, 0x36, 0x42, 0x4C, 0x5F, 0xBF, 0xE0, 0x3A, 0xA8, 0xC3, 0x20, 0x63, 0x89, 0xB7, 0xC0, 0x1C, 0x1D, 0x44, 0xC2, 0x28, 0x7F, 0xED, 0x02, 0x0E, 0x5D, 0x66, 0x8F, 0x98, 0xB5, 0xB7, 0xD0, 0x16, 0x4D, 0x83, 0xF8, 0xFB, 0x01, 0x43, 0x47]
key = 'Hello Ph0en1x'
l1 = len(key)
l2 = len(data)
for i in range(l2 - 1, 0, -1):
    data[i] = (((data[i] + 1 - data[i - 1]) ^ ord(key[i % l1])) & 0xFF) - 1
data[0] = (data[0] ^ 0x48) - 1
flag = ''.join([chr(c + 1) for c in data])
print flag
# flag{Ar3_y0u_go1nG_70_scarborough_Fair}
```

# RememberOther

这道题简直出的莫名其妙，发现如果用户名和密码都为空会返回 True，并且会弹出 strings.xml 中指向的 successed 字符串：

```java
package com.droider.crackme0201;

import android.app.Activity;
import android.os.Bundle;
import android.support.v4.view.MotionEventCompat;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MainActivity extends Activity {
    private Button btn_register;
    private EditText edit_sn;
    private EditText edit_userName;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle(R.string.unregister);
        this.edit_userName = (EditText) findViewById(R.id.edit_username);
        this.edit_sn = (EditText) findViewById(R.id.edit_sn);
        this.btn_register = (Button) findViewById(R.id.button_register);
        this.btn_register.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (MainActivity.this.checkSN(MainActivity.this.edit_userName.getText().toString().trim(), MainActivity.this.edit_sn.getText().toString().trim())) {
                    Toast.makeText(MainActivity.this, R.string.successed, 0).show();
                    MainActivity.this.btn_register.setEnabled(false);
                    MainActivity.this.setTitle(R.string.registered);
                    return;
                }
                Toast.makeText(MainActivity.this, R.string.unsuccessed, 0).show();
            }
        });
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_main, menu);
        return true;
    }

    private boolean checkSN(String userName, String sn) {
        try {
            if (userName.length() == 0 && sn.length() == 0) {
                return true;
            }
            if (userName == null || userName.length() == 0) {
                return false;
            }
            if (sn == null || sn.length() != 16) {
                return false;
            }
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.reset();
            digest.update(userName.getBytes());
            String hexstr = toHexString(digest.digest(), BuildConfig.FLAVOR);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hexstr.length(); i += 2) {
                sb.append(hexstr.charAt(i));
            }
            if (sb.toString().equalsIgnoreCase(sn)) {
                return true;
            }
            return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String toHexString(byte[] bytes, String separator) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & MotionEventCompat.ACTION_MASK);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex).append(separator);
        }
        return hexString.toString();
    }
}
```

在资源中找到指定的字符串：

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Crackme0201</string>
    <string name="hint_sn">请输入16位的注册码</string>
    <string name="hint_username">请输入用户名</string>
    <string name="info">Xman Android</string>
    <string name="menu_settings">Settings</string>
    <string name="register">注 册</string>
    <string name="registered">程序已注册</string>
    <string name="sn">注册码：</string>
    <string name="successed">md5:b3241668ecbeb19921fdac5ac1aafa69</string>
    <string name="title_activity_main">Crackme</string>
    <string name="unregister">程序未注册</string>
    <string name="unsuccessed">无效用户名或注册码</string>
    <string name="username">用户名：</string>
</resources>
```

搜一下 MD5，得到原字符串为 `YOU_KNOW_`。但结果不对，网上找到别人的 wp，说另一半要结合 word 中的提示，出题人说他不懂安卓，那么我们就懂了，flag 就是 `YOU_KNOW_ANDROID`。

# 黑客精神

这题相比前面的题目开始复杂起来了。在 MainActivity 中，看到一开始对一个 m 的值进行了判断。然后接下来在 onClick 中新建了一个 MyApp 实例，如果 m 为 0 就调用 doRegister 函数，其中跳转到 RegActivity。

```java
package com.gdufs.xman;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.ComponentName;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static String workString;
    private Button btn1;

    public void onCreate(Bundle savedInstanceState) {
        String str2;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String str1 = "Xman";
        Log.d("com.gdufs.xman m=", str1);
        MyApp myApp = (MyApp) getApplication();
        int m = MyApp.m;
        if (m == 0) {
            str2 = "\u672a\u6ce8\u518c"; // 未注册
        } else if (m == 1) {
            str2 = "\u5df2\u6ce8\u518c"; // 已注册
        } else {
            str2 = "\u5df2\u6df7\u4e71"; // 已混乱
        }
        setTitle(str1 + str2);
        this.btn1 = (Button) findViewById(R.id.button1);
        this.btn1.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                MyApp myApp = (MyApp) MainActivity.this.getApplication();
                if (MyApp.m == 0) {
                    MainActivity.this.doRegister();
                    return;
                }
                ((MyApp) MainActivity.this.getApplication()).work();
                Toast.makeText(MainActivity.this.getApplicationContext(), MainActivity.workString, 0).show();
            }
        });
    }

    public void doRegister() {
        new Builder(this).setTitle("\u6ce8\u518c").setMessage("Flag\u5c31\u5728\u524d\u65b9\uff01").setPositiveButton("\u6ce8\u518c", new DialogInterface.OnClickListener() { // Title => 注册 | Message => Flag就在前方！ | PositiveButton => 注册
            public void onClick(DialogInterface dialog, int which) {
                Intent intent = new Intent();
                intent.setComponent(new ComponentName(BuildConfig.APPLICATION_ID, "com.gdufs.xman.RegActivity"));
                MainActivity.this.startActivity(intent); // 跳转到RegActivity
                MainActivity.this.finish();
            }
        }).setNegativeButton("\u4e0d\u73a9\u4e86", new DialogInterface.OnClickListener() { // NagetiveButton => 不玩了
            public void onClick(DialogInterface dialog, int which) {
                Process.killProcess(Process.myPid());
            }
        }).show();
    }

    public void work(String str) {
        workString = str;
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }
}
```

然后看一下 MyApp 类中，发现分别有三个函数在 Native 层实现。其中 onCreate 中调用了 initSN 函数。SN 猜测是 Serial Number 即序列号：

```java
package com.gdufs.xman;

import android.app.Application;
import android.util.Log;

public class MyApp extends Application {
    public static int m = 0;

    public native void initSN();

    public native void saveSN(String str);

    public native void work();

    static {
        System.loadLibrary("myjni");
    }

    public void onCreate() {
        initSN();
        Log.d("com.gdufs.xman m=", String.valueOf(m));
        super.onCreate();
    }
}
```

RegActivity 中获取输入的字符串，并作为 SN 传入 saveSN 函数。然后 App 将会把自己的进程杀死：

```java
package com.gdufs.xman;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Process;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class RegActivity extends Activity {
    private Button btn_reg;
    private EditText edit_sn;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reg);
        this.btn_reg = (Button) findViewById(R.id.button1);
        this.edit_sn = (EditText) findViewById(R.id.editText1);
        this.btn_reg.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                String sn = RegActivity.this.edit_sn.getText().toString().trim();
                if (sn == null || sn.length() == 0) {
                    Toast.makeText(RegActivity.this, "\u60a8\u7684\u8f93\u5165\u4e3a\u7a7a", 0).show(); // 您的输入为空
                    return;
                }
                ((MyApp) RegActivity.this.getApplication()).saveSN(sn);
                new Builder(RegActivity.this).setTitle("\u56de\u590d").setMessage("\u60a8\u7684\u6ce8\u518c\u7801\u5df2\u4fdd\u5b58").setPositiveButton("\u597d\u5427", new DialogInterface.OnClickListener() { // Title => 回复 | Message => 您的注册码已保存 | PositiveButton => 好吧
                    public void onClick(DialogInterface dialog, int which) {
                        Process.killProcess(Process.myPid());
                    }
                }).show();
            }
        });
    }
}
```

那么基本上就是求出正确的 SN 了。在 Native 查看，发现函数在 JNI_OnLoad 中动态注册：

```cpp
signed int __fastcall JNI_OnLoad(_JavaVM *a1)
{
  if ( a1->functions->GetEnv(&a1->functions, (void **)&g_env, 65542) )
    return -1;
  _android_log_print(2, "com.gdufs.xman", "JNI_OnLoad()");
  native_class = (int)g_env->functions->FindClass(&g_env->functions, "com/gdufs/xman/MyApp");
  if ( !g_env->functions->RegisterNatives(&g_env->functions, (jclass)native_class, (const JNINativeMethod *)gMethods, 3) )// register 3 methods
  {
    _android_log_print(2, "com.gdufs.xman", "RegisterNatives() --> nativeMethod() ok");
    return 65542;
  }
  _android_log_print(6, "com.gdufs.xman", "RegisterNatives() --> nativeMethod() failed");
  return -1;
}
```

先来看 initSN，其中读取 `/sdcard/reg.dat` 中的内容并和 `EoPAoY62@ElRD` 进行比较：

```cpp
void __fastcall initSN(_JNIEnv *a1)
{
  _JNIEnv *env; // r6
  FILE *f; // r0
  FILE *f_1; // r4
  _JNIEnv *env_1; // r0
  int v5; // r1
  int len; // r7
  char *data; // r5
  _JNIEnv *env_2; // r0
  int v9; // r1

  env = a1;
  f = fopen("/sdcard/reg.dat", "r+");
  f_1 = f;
  if ( !f )                                     // read file error
  {
    env_1 = env;
    v5 = (int)f_1;
LABEL_5:
    setValue(env_1, v5);
    return;
  }
  fseek(f, 0, 2);                               // seek to file end ( SEEK_END )
  len = ftell(f_1);
  data = (char *)malloc(len + 1);               // malloc error
  if ( !data )
  {
    fclose(f_1);
    env_1 = env;
    v5 = 0;
    goto LABEL_5;
  }
  fseek(f_1, 0, 0);                             // seek to file start ( SEEK_SET )
  fread(data, len, 1u, f_1);
  data[len] = 0;
  if ( !strcmp(data, "EoPAoY62@ElRD") )
  {
    env_2 = env;
    v9 = 1;
  }
  else
  {
    env_2 = env;
    v9 = 0;
  }
  setValue(env_2, v9);
  j_fclose(f_1);
}
```

其中看到有一个 setValue 函数，将 m 的值设为指定的值：

```cpp
void __fastcall setValue(_JNIEnv *a1, int val)
{
  int val_1; // r7
  _JNIEnv *v3; // r4
  jclass v4; // r0
  void *v5; // r5
  struct _jfieldID *v6; // r0

  val_1 = val;
  v3 = a1;
  v4 = a1->functions->FindClass(&a1->functions, "com/gdufs/xman/MyApp");
  v5 = v4;
  v6 = v3->functions->GetStaticFieldID(&v3->functions, v4, "m", "I");
  v3->functions->SetStaticIntField(&v3->functions, v5, v6, val_1);// set m = val
}
```

接下来看 saveSN，这里做一个循环，将 reg.dat 中的字符串取出来并和 key 进行异或：

```cpp
int __fastcall saveSN(_JNIEnv *a1, int a2, jstring a3)
{
  _JNIEnv *env; // r6
  jstring str; // r9
  FILE *v5; // r7
  int *v7; // r4
  const char *v8; // r3
  int v9; // r0
  int v10; // r1
  _WORD *v11; // r5
  JNIEnv *v12; // r0
  int i; // r4
  const struct JNINativeInterface *v14; // r3
  signed int j; // r6
  const char *utf_string; // r9
  const char *data; // r5
  signed int len; // r10
  char val; // r2
  char tmp; // r3
  int v21; // [sp+0h] [bp-38h]
  int v22; // [sp+14h] [bp-24h]
  char v23; // [sp+18h] [bp-20h]

  env = a1;
  str = a3;
  f = fopen("/sdcard/reg.dat", "w+");
  if ( f )
  {
    v7 = &v21;
    v8 = "W3_arE_whO_we_ARE";
    do
    {
      v9 = *(_DWORD *)v8;
      v8 += 8;
      v10 = *((_DWORD *)v8 - 1);
      *v7 = v9;
      v7[1] = v10;
      v11 = v7 + 2;
      v7 += 2;
    }
    while ( v8 != "E" );
    v12 = &env->functions;
    i = 2016;
    *v11 = *(_WORD *)v8;
    v14 = env->functions;
    j = 0;
    utf_string = v14->GetStringUTFChars(v12, str, 0);
    data = utf_string;
    len = strlen(utf_string);
    while ( j < len )
    {
      if ( j % 3 == 1 )
      {
        i = (i + 5) % 16;
        val = *(&v23 + i - 23);                 // &v23 - 32 = &"3_arE_whO_we_ARE"
      }
      else if ( j % 3 == 2 )
      {
        i = (i + 7) % 15;
        val = *(&v23 + i - 22);                 // &v23 - 22 = &"_arE_whO_we_ARE"
      }
      else
      {
        i = (i + 3) % 13;
        val = *(&v23 + i - 21);                 // &v23 - 21 = &"arE_whO_we_ARE"
      }
      tmp = *data;
      ++j;
      *((_BYTE *)++data - 1) = tmp ^ val;
    }
    fputs(utf_string, f);
  }
  else if ( v22 == _stack_chk_guard )
  {
    return j___android_log_print(3, "com.gdufs.xman", &unk_2DCA);
  }
  return j_fclose(f);
}
```

work 函数中初始化了 SN，获取了 m 的值，并最后调用 callWork：

```cpp
void __fastcall work(_JNIEnv *a1)
{
  _JNIEnv *env; // r4
  jint m; // r0
  _JNIEnv *env_1; // r0
  void *v4; // r1
  bool v5; // zf

  env = a1;
  initSN(a1);
  m = getValue(env);
  if ( m )
  {
    v5 = m == 1;
    env_1 = env;
    if ( v5 )
      v4 = &unk_2E6B;                           // [0xE8, 0xBE, 0x93, 0xE5, 0x85, 0xA5, 0xE5, 0x8D, 0xB3, 0xE6, 0x98, 0xAF, 0x66, 0x6C, 0x61, 0x67, 0x2C, 0xE6, 0xA0, 0xBC, 0xE5, 0xBC, 0x8F, 0xE4, 0xB8, 0xBA, 0x78, 0x6D, 0x61, 0x6E, 0x7B, 0xE2, 0x80, 0xA6, 0xE2, 0x80, 0xA6, 0x7D, 0xEF, 0xBC, 0x81]
    else
      v4 = &unk_2E95;                           // [0xE7, 0x8A, 0xB6, 0xE6, 0x80, 0x81, 0xE4, 0xB8, 0x8D, 0xE5, 0xA4, 0xAA, 0xE5, 0xAF, 0xB9, 0xE3, 0x80, 0x82, 0xE3, 0x80, 0x82]
  }
  else
  {
    env_1 = env;
    v4 = &unk_2E5B;                             // [0xE8, 0xBF, 0x98, 0xE4, 0xB8, 0x8D, 0xE8, 0xA1, 0x8C, 0xE5, 0x91, 0xA2, 0xEF, 0xBC, 0x81]
  }
  callWork(env_1, (int)v4);
}
```

其中 getValue 就是获取 m 的值：

```cpp
jint __fastcall getValue(_JNIEnv *a1)
{
  _JNIEnv *v1; // r4
  jclass v2; // r0
  void *v3; // r5
  struct _jfieldID *v4; // r0

  v1 = a1;
  v2 = a1->functions->FindClass(&a1->functions, "com/gdufs/xman/MyApp");
  v3 = v2;
  v4 = v1->functions->GetStaticFieldID(&v1->functions, v2, "m", "I");
  return v1->functions->GetStaticIntField(&v1->functions, v3, v4);// get m's value
}
```

callWork 中就是调用了 work 函数，这样看来是个死循环：

```cpp
void __fastcall callWork(_JNIEnv *a1, void *a2)
{
  const char *v2; // r8
  _JNIEnv *env; // r4
  jclass v4; // r0
  void *v5; // r5
  struct _jmethodID *v6; // r0
  jobject v7; // r7
  struct _jmethodID *v8; // r5
  void (*v9)(JNIEnv *, jobject, jmethodID, ...); // r6
  jstring v10; // r0

  v2 = (const char *)a2;
  env = a1;
  v4 = a1->functions->FindClass(&a1->functions, "com/gdufs/xman/MainActivity");
  v5 = v4;
  v6 = env->functions->GetMethodID(&env->functions, v4, "<init>", "()V");
  v7 = env->functions->NewObject(&env->functions, v5, v6);
  v8 = env->functions->GetMethodID(&env->functions, v5, "work", "(Ljava/lang/String;)V");
  if ( v8 )
  {
    v9 = env->functions->CallVoidMethod;
    v10 = env->functions->NewStringUTF(&env->functions, v2);
    v9(&env->functions, v7, v8, v10);
  }
}
```

在 saveSN 中其实就是实际的算法，逆一下实现解 SN 脚本：

```python
#!/usr/bin/env python
ciphertext = 'EoPAoY62@ElRD'
key = 'W3_arE_whO_we_ARE'
i = 2016
j = 0
l = len(ciphertext)
result = ''
while j < l:
    if j % 3 == 1:
        i = (i + 5) % 16
        val = ord(key[i + 1])
    elif j % 3 ==2:
        i = (i + 7) % 15
        val = ord(key[i + 2])
    else:
        i = (i + 3) % 13
        val = ord(key[i + 3])
    result += chr(ord(ciphertext[j]) ^ val)
    j += 1
print result
```

# easy-dex

首先查看 AndroidManifest.xml，发现启动 Activity 为 `android.app.NativeActivity`，是在 Native 层实现的安卓 Activity：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest android:versionCode="1" android:versionName="1.0" package="com.a.sample.findmydex" platformBuildVersionCode="24" platformBuildVersionName="7.0" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="24" />
  <application android:allowBackup="false" android:fullBackupContent="false" android:hasCode="false" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    <activity android:configChanges="0xa0" android:label="@string/app_name" android:name="android.app.NativeActivity">
      <meta-data android:name="android.app.lib_name" android:value="native" />
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:name="com.a.sample.findmydex.MainActivity">
      <intent-filter>
        <action android:name="com.a.sample.findmydex.MAIN" />
        <category android:name="android.intent.category.DEFAULT" />
      </intent-filter>
    </activity>
  </application>
</manifest>
```

看了一下 Java 只有一个类：

```java
class Placeholder {
    Placeholder() {
        super();
    }
}
```

先查看 NativeActivity 中的 onCreate 函数，其中在 pthread_create 里的第三个参数是对应的 MainActivity 的入口点，即 android_app_entry：

```cpp
int __fastcall ANativeActivity_onCreate(_DWORD *a1, int a2, size_t a3)
{
  _DWORD *v3; // r8
  int savedState; // r10
  size_t savedStateSize; // r9
  int activity; // r0
  __int64 v7; // r2
  char *v8; // r5
  void *v9; // r0
  int *v10; // r0
  char *v11; // r0
  pthread_attr_t attr; // [sp+4h] [bp-30h]

  v3 = a1;
  savedState = a2;
  savedStateSize = a3;
  activity = *a1;
  *(_DWORD *)(activity + 20) = sub_3000;
  *(_DWORD *)activity = sub_305A;
  *(_DWORD *)(activity + 4) = sub_3062;
  *(_DWORD *)(activity + 8) = sub_306A;
  *(_DWORD *)(activity + 12) = sub_30BE;
  HIDWORD(v7) = sub_30EE;
  *(_DWORD *)(activity + 16) = sub_30C6;
  LODWORD(v7) = sub_30DE;
  *(_DWORD *)(activity + 56) = sub_30CE;
  *(_DWORD *)(activity + 60) = sub_30D6;
  *(_QWORD *)(activity + 24) = v7;
  *(_DWORD *)(activity + 40) = sub_30F4;
  *(_DWORD *)(activity + 44) = sub_30FC;
  *(_DWORD *)(activity + 48) = sub_3102;
  v8 = (char *)malloc(0x94u);
  _aeabi_memclr4();
  *((_DWORD *)v8 + 3) = v3;
  pthread_mutex_init((pthread_mutex_t *)(v8 + 64), 0);
  pthread_cond_init((pthread_cond_t *)(v8 + 68), 0);
  if ( savedState )
  {
    v9 = malloc(savedStateSize);
    *((_DWORD *)v8 + 5) = v9;
    *((_DWORD *)v8 + 6) = savedStateSize;
    _aeabi_memcpy(v9, savedState, savedStateSize);
  }
  if ( pipe(&attr.__align + 6) )
  {
    v10 = (int *)_errno();
    v11 = strerror(*v10);
    _android_log_print(6, "threaded_app", "could not create pipe: %s", v11);
    v8 = 0;
  }
  else
  {
    *((_QWORD *)v8 + 9) = *((_QWORD *)&attr.__align + 3);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
    pthread_create((pthread_t *)v8 + 20, &attr, (void *(*)(void *))android_app_entry, v8);
    pthread_mutex_lock((pthread_mutex_t *)(v8 + 64));
    while ( !*((_DWORD *)v8 + 27) )
      pthread_cond_wait((pthread_cond_t *)(v8 + 68), (pthread_mutex_t *)(v8 + 64));
    pthread_mutex_unlock((pthread_mutex_t *)(v8 + 64));
  }
  v3[7] = v8;
  return _stack_chk_guard - *(&attr.__align + 8);
}
```

在 android_app_entry 中，在 android_app_destroy 上面可以找到对应的 MainActivity 函数：

```cpp
int __fastcall android_app_entry(int a1)
{
  int v1; // r4
  int v2; // r1
  int v3; // r5
  int result; // r0
  char v5; // [sp+8h] [bp-14h]
  char v6; // [sp+Ah] [bp-12h]
  int v7; // [sp+Ch] [bp-10h]

  v1 = a1;
  *(_DWORD *)(a1 + 16) = AConfiguration_new();
  v2 = *(_DWORD *)(*(_DWORD *)(v1 + 12) + 32);
  AConfiguration_fromAssetManager();
  AConfiguration_getLanguage(*(_DWORD *)(v1 + 16), &v6);
  AConfiguration_getCountry(*(_DWORD *)(v1 + 16), &v5);
  *(_DWORD *)(v1 + 84) = 1;
  *(_DWORD *)(v1 + 88) = v1;
  *(_DWORD *)(v1 + 92) = sub_3344;
  *(_DWORD *)(v1 + 96) = 2;
  *(_DWORD *)(v1 + 100) = v1;
  *(_DWORD *)(v1 + 104) = sub_3370;
  v3 = ALooper_prepare(1);
  ALooper_addFd(v3, *(_DWORD *)(v1 + 72), 1, 1, 0, v1 + 84);
  *(_DWORD *)(v1 + 28) = v3;
  pthread_mutex_lock((pthread_mutex_t *)(v1 + 64));
  *(_DWORD *)(v1 + 108) = 1;
  pthread_cond_broadcast((pthread_cond_t *)(v1 + 68));
  pthread_mutex_unlock((pthread_mutex_t *)(v1 + 64));
  j_android_main(v1);
  android_app_destroy(v1);
  pthread_mutex_lock((pthread_mutex_t *)(v1 + 64));
  if ( *(_DWORD *)(v1 + 32) )
    AInputQueue_detachLooper();
  AConfiguration_delete(*(_DWORD *)(v1 + 16));
  *(_DWORD *)(v1 + 116) = 1;
  pthread_cond_broadcast((pthread_cond_t *)(v1 + 68));
  pthread_mutex_unlock((pthread_mutex_t *)(v1 + 64));
  result = _stack_chk_guard - v7;
  if ( _stack_chk_guard == v7 )
    result = 0;
  return result;
}
```

进入 MainActivity 之后，一开始有一段异或的数据：

```cpp
  *(_DWORD *)filename = 0x9D888DC6;
  *(_DWORD *)&filename[4] = 0x888DC688;
  *(_DWORD *)&filename[8] = 0x8AC6889D;
  *(_DWORD *)&filename[12] = 0x88C78486;
  *(_DWORD *)&filename[16] = 0x84889AC7;
  *(_DWORD *)&filename[20] = 0xC78C8599;
  *(_DWORD *)&filename[24] = 0x8D87808F;
  *(_DWORD *)&filename[28] = 0x8C8D9084;
  *(_DWORD *)&filename[32] = 0x808FC691;
  *(_DWORD *)&filename[36] = 0xC69A8C85;
  *(_DWORD *)&filename[40] = 0x9A88858A;
  *(_DWORD *)&filename[44] = 0xC79A8C9A;
  *(_DWORD *)&filename[48] = 0xE9918C8D;
  filename[52] = 0;
  *(_DWORD *)name = 0x9D888DC6;
  *(_DWORD *)&name[4] = 0x888DC688;
  *(_DWORD *)&name[8] = 0x8AC6889D;
  *(_DWORD *)&name[12] = 0x88C78486;
  *(_DWORD *)&name[16] = 0x84889AC7;
  *(_DWORD *)&name[20] = 0xC78C8599;
  *(_DWORD *)&name[24] = 0x8D87808F;
  *(_DWORD *)&name[28] = 0x8C8D9084;
  *(_DWORD *)&name[32] = 0x808FC691;
  *(_DWORD *)&name[36] = 0xC69A8C85;
  *(_DWORD *)&name[40] = 0x918C8D86;
  name[46] = 0;
  i = 1;
  *(_WORD *)&name[44] = 0xE9C6u;
  filename[0] = 47;
  do
  {
    filename[i] ^= 0xE9u;                       // filename = '/data/data/com.a.sample.findmydex/files/classes.dex'
    ++i;
  }
  while ( i != 53 );
  j = 1;
  name[0] = 47;
  do
  {
    name[j] ^= 0xE9u;                           // name = '/data/data/com.a.sample.findmydex/files/odex/'
    ++j;
  }
  while ( j != 47 );
```

解密一下，可以发现是生成目标 dex 文件和 odex 的路径：

```python
#!/usr/bin/env python

def word2bytes(w):
    return [w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, w >> 24]

def bytes2word(bs):
    return bs[0] | bs[1] << 8 | bs[2] << 16 | bs[3] << 24

def words2byte(ws):
    result = []
    for w in ws:
        temp = word2bytes(w)
        for b in temp:
            result.append(b)
    return result

def bytes2words(bs):
    result = []
    for i in range(len(bs) / 4):
        temp = bytes2word(bs[4*i:4*i+4])
        result.append(temp)
    return result

filename = [0x9D888DC6, 0x888DC688, 0x8AC6889D, 0x88C78486, 0x84889AC7, 0xC78C8599, 0x8D87808F, 0x8C8D9084, 0x808FC691, 0xC69A8C85, 0x9A88858A, 0xC79A8C9A, 0xE9918C8D]
name = [0x9D888DC6, 0x888DC688, 0x8AC6889D, 0x88C78486, 0x84889AC7, 0xC78C8599, 0x8D87808F, 0x8C8D9084, 0x808FC691, 0xC69A8C85, 0x918C8D86, 0x0000E9C6]
filename = words2byte(filename)
name = words2byte(name)
filename = chr(47) + ''.join(list(map(lambda c: chr(c ^ 0xE9), filename[1:])))
name = chr(47) + ''.join(list(map(lambda c: chr(c ^ 0xE9), name[1:])))
print filename
# /data/data/com.a.sample.findmydex/files/classes.dex
print name
# /data/data/com.a.sample.findmydex/files/odex/
```

然后接下来，可以看到一些涉及到 OpenGL 库的函数：

```cpp
...
  _android_log_print(4, "FindMyDex", "Can you shake your phone 100 times in 10 seconds?");
  v10 = 0;
  do
  {
    while ( 1 )
    {
      v12 = 0;
      if ( !v30 )
        v12 = -1;
      v13 = ALooper_pollAll(v12, 0, &v25, &v24);// get time
      if ( v13 >= 0 )
        break;
      if ( v30 )
      {
        v11 = v31 + 0.01;
        if ( (float)(v31 + 0.01) > 1.0 )
          v11 = 0.0;
        v31 = v11;
        sub_2C14((int)&v26);                    // OpenGL
      }
    }
...

int __fastcall sub_2C14(int a1)
{
  int v1; // r4
  int result; // r0

  v1 = a1;
  result = *(_DWORD *)(a1 + 20);
  if ( !result )
    return result;
  glClearColor(
    (float)*(signed int *)(v1 + 44) / (float)*(signed int *)(v1 + 32),// red
    *(GLclampf *)(v1 + 40),                     // green
    (float)*(signed int *)(v1 + 48) / (float)*(signed int *)(v1 + 36),// blue
    1.0);
  glClear(0x4000u);
  result = j_eglSwapBuffers(*(_QWORD *)(v1 + 20), *(_QWORD *)(v1 + 20) >> 32);
  return result;
}
```

这部分不去仔细看，可以直接根据 log 来判断程序的流程，可以判断出是要求在 10 秒内摇 100 次手机。在 `(times - 1) <= 88` 处可以看到开始对数据进行解压缩处理。在后面 `times == 100`，可以判断是达到了 100 次后，开始对将数据输出到文件中：

```cpp
...
  _android_log_print(4, "FindMyDex", "Can you shake your phone 100 times in 10 seconds?");
...
            _android_log_print(4, "FindMyDex", "Oh yeah~ You Got it~ %d times to go~", 99 - v10);
...
        if ( (unsigned int)(times - 1) <= 88 )
        {
          v10 = times;
          v15 = times / 10;
          if ( times % 10 == 9 )
          {
            v16 = size_1;
            v17 = (signed int)size_1 / 10;
            v18 = (v15 + 1) * ((signed int)size_1 / 10);
            if ( (signed int)size_1 / 10 * v15 < v18 )
            {
              v19 = &data[v17 * v15];
              do
              {
                --v17;
                *v19++ ^= times;
              }
              while ( v17 );
            }
            if ( times == 89 )
            {
              while ( v18 < (signed int)v16 )
                data[v18++] ^= 0x59u;
            }
            v10 = times + 1;
          }
        }
        if ( times == 100 )                     // reach the target
        {
          if ( (signed int)(time(0) - v6) > 9 )
          {
            _android_log_print(4, "FindMyDex", "OH~ You are too slow. Please try again");
            _aeabi_memcpy(data, &data_1, size_1);
            v10 = 0;
          }
          else
          {
            v20 = v6;
            if ( uncompress(dest, &destLen, data, (uLong)size_1) )// uncompress data
              _android_log_print(5, "FindMyDex", "Dangerous operation detected.");
            v21 = open(filename, 577, 511);
            if ( !v21 )
              _android_log_print(5, "FindMyDex", "Something wrong with the permission.");
            write(v21, dest, destLen);
            close(v21);
            free(dest);
            free(data);
            if ( access(name, 0) && mkdir(name, 0x1FFu) )
              _android_log_print(5, "FindMyDex", "Something wrong with the permission..");
            sub_2368((int)v1);
            remove(filename);
            _android_log_print(4, "FindMyDex", "Congratulations!! You made it!");
            sub_2250(v1);
            v10 = 0x80000000;
            v6 = v20;
          }
        }
      }
    }
...
```

用 IDC 脚本把数据 dump 下来：

```cpp
static main() {
    auto fp, start, end, len, b;
    fp = fopen("dump.data", "wb");
    start = 0x7004;
    len = 0x3CA10;
    end = start + len;
    for (b = start; b < end; b++) {
        fputc(Byte(b), fp);
    }
}
```

然后实现一下对 dex 文件的解压缩过程：

```python
#!/usr/bin/env python
import zlib

with open('dump.data', 'rb') as f:
    data = f.read()
data = [ord(c) for c in data]
size = 0x3CA10
for times in range(90):
    v15 = times / 10
    if times % 10 == 9:
        v16 = size
        v17 = size / 10
        v18 = (v15 + 1) * (size / 10)
        if size / 10 * v15 < v18:
            for i in range(v17):
                data[v17 * v15 + i] ^= times
        if times == 89:
            while v18 - v16 < 0:
                data[v18] ^= 0x59
                v18 += 1
data = ''.join([chr(c) for c in data])
data = zlib.decompress(data)
with open('dump.dex', 'wb') as f:
    for c in data:
        f.write(c)
```

接下来用 JEB 对 dex 文件进行分析。首先在 MainActivity 中，变量 m 是密文，onCreate 中调用了 a 类。函数 b 则是一个加密函数，其中涉及到了 b 类中函数：

```java
package com.a.sample.findmydex;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.a.u;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class MainActivity extends u {
    private static byte[] m;

    static {
        MainActivity.m = new byte[]{-120, 77, -14, -38, 17, 5, -42, 44, -32, 109, 85, 0x1F, 24, -91, -112, -83, 0x40, -83, -128, 84, 5, -94, -98, -30, 18, 70, -26, 71, 5, -99, -62, -58, 0x75, 29, -44, 6, 0x70, -4, 81, 84, 9, 22, -51, 0x5F, -34, 12, 0x2F, 77};
    }

    public MainActivity() {
        super();
    }

    static byte[] a(String arg1, String arg2) {
        return MainActivity.b(arg1, arg2);
    }

    private static byte[] b(String arg7, String arg8) {
        byte[] v0_1;
        try {
            BufferedInputStream v2 = new BufferedInputStream(new ByteArrayInputStream(arg7.getBytes()));
            byte[] v1 = new byte[16];
            ArrayList v3 = new ArrayList();
            Object v4 = b.a(arg8.getBytes()); // 处理密钥
            while(v2.read(v1, 0, 16) != -1) { // 循环加密，采用ECB模式
                v3.add(b.a(v1, 0, v4));
                v1 = new byte[16];
            }

            ByteBuffer v2_1 = ByteBuffer.allocate(v3.size() * 16); // 转换成字节数组
            Object[] v3_1 = v3.toArray();
            int v4_1 = v3_1.length;
            int v1_1;
            for(v1_1 = 0; v1_1 < v4_1; ++v1_1) {
                v2_1.put(v3_1[v1_1]);
            }

            v0_1 = v2_1.array();
        }
        catch(Exception v0) {
            v0_1 = new byte[1];
        }

        return v0_1;
    }

    static byte[] i() { // Cipheretxt
        return MainActivity.m;
    }

    protected void onCreate(Bundle arg4) {
        super.onCreate(arg4);
        this.setContentView(0x7F04001A); // activity_main
        this.findViewById(0x7F0B0055).setOnClickListener(new a(this, this.findViewById(0x7F0B0054), ((Context)this))); // button | edit_text
    }
}
```

类 a 中设置了一个监听按钮的事件，并将输入和指定的字符串作为参数传入 MainActivity 的函数 a。并与密文进行比较：

```java
package com.a.sample.findmydex;

import android.content.Context;
import android.view.View$OnClickListener;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import java.util.Arrays;

class a implements View$OnClickListener {
    a(MainActivity arg1, EditText arg2, Context arg3) {
        this.c = arg1;
        this.a = arg2;
        this.b = arg3;
        super();
    }

    public void onClick(View arg5) {
        if(Arrays.equals(MainActivity.a(this.a.getText().toString(), this.c.getString(0x7F060023)), MainActivity.i())) { // I have a male fish and a female fish.
            Toast.makeText(this.b, this.c.getString(0x7F060025), 1).show(); // Yes! You got me! :)
        }
        else {
            Toast.makeText(this.b, this.c.getString(0x7F060022), 1).show(); // NO~ You don't get me~ T_T
        }
    }
}
```

b 类的 a 函数主要将数组的长度补齐成 8 的倍数，并调用 b 函数：

```java
    public static Object a(byte[] arg5) { // 补齐块
        Object v0_3;
        int v1 = 0x20;
        int v0 = 0;
        Class v2 = b.class;
        __monitor_enter(v2);
        try {
            if(arg5.length > v1 || arg5.length % 8 != 0) { // 长度大于32或不是8的倍数
                if(arg5.length <= v1) {
                    v1 = arg5.length;
                }

                if((v1 & 7) > 0) { // 判断数组长度是否是8的倍数，不是的话补齐
                    v0 = 1;
                }

                byte[] v0_2 = new byte[v0 * 8 + v1];
                System.arraycopy(arg5, 0, v0_2, 0, v1);
                arg5 = v0_2;
            }

            v0_3 = b.b(arg5);
        }
        catch(Throwable v0_1) {
            __monitor_exit(v2);
            throw v0_1;
        }

        __monitor_exit(v2);
        return v0_3;
    }
```

b 类中的 b 函数是一个处理密钥的函数：

```java
    private static Object b(byte[] arg19) { // 处理密钥
        Object[] v1_2;
        int[] v13;
        int v10_1;
        int v9_1;
        int v8_1;
        int[] v11_1;
        int v12;
        int v3;
        int v1_1;
        int v5;
        int v4;
        Class v6 = b.class;
        __monitor_enter(v6);
        if(arg19 != null) {
            goto label_10;
        }

        try {
            throw new InvalidKeyException("Empty key");
        label_10:
            v4 = arg19.length;
            if(v4 != 8 && v4 != 16 && v4 != 24 && v4 != 0x20) {
                throw new InvalidKeyException("Incorrect key length");
            }

            int v7 = v4 / 8;
            v5 = 40;
            int[] v8 = new int[4];
            int[] v9 = new int[4];
            int[] v10 = new int[4];
            v1_1 = 0;
            v3 = 0;
            int v2;
            for(v2 = v7 - 1; v3 < 4; --v2) {
                if(v1_1 >= v4) {
                    break;
                }

                int v11 = v1_1 + 1;
                v12 = v11 + 1;
                v1_1 = arg19[v1_1] & 0xFF | (arg19[v11] & 0xFF) << 8;
                v11 = v12 + 1;
                v1_1 |= (arg19[v12] & 0xFF) << 16;
                v12 = v11 + 1;
                v8[v3] = v1_1 | (arg19[v11] & 0xFF) << 24;
                v1_1 = v12 + 1;
                v11 = arg19[v12] & 0xFF;
                v12 = v1_1 + 1;
                v1_1 = (arg19[v1_1] & 0xFF) << 8 | v11;
                v11 = v12 + 1;
                v12 = (arg19[v12] & 0xFF) << 16 | v1_1;
                v1_1 = v11 + 1;
                v9[v3] = (arg19[v11] & 0xFF) << 24 | v12;
                v10[v2] = b.a(v8[v3], v9[v3]);
                ++v3;
            }

            v11_1 = new int[v5];
            v1_1 = 0;
            v2 = 0;
            while(v2 < 20) {
                v3 = b.a(v7, v1_1, v8);
                v4 = b.a(v7, 0x1010101 + v1_1, v9);
                v4 = v4 >>> 24 | v4 << 8;
                v3 += v4;
                v11_1[v2 * 2] = v3;
                v3 += v4;
                v11_1[v2 * 2 + 1] = v3 >>> 23 | v3 << 9;
                ++v2;
                v1_1 += 0x2020202;
            }

            v8_1 = v10[0];
            v9_1 = v10[1];
            v12 = v10[2];
            v10_1 = v10[3];
            v13 = new int[0x400];
            v2 = 0;
            while(true) {
            label_120:
                if(v2 >= 0x100) {
                    goto label_324;
                }

                switch(v7 & 3) {
                    case 0: {
                        goto label_183;
                    }
                    case 1: {
                        goto label_126;
                    }
                    case 2: {
                        goto label_332;
                    }
                    case 3: {
                        goto label_337;
                    }
                }

                goto label_124;
            }
        }
        catch(Throwable v1) {
            goto label_8;
        }

    label_337:
        v1_1 = v2;
        v3 = v2;
        v4 = v2;
        v5 = v2;
        goto label_211;
        try {
        label_183:
            v5 = b.a[1][v2] & 0xFF ^ b.e(v10_1);
            v4 = b.a[0][v2] & 0xFF ^ b.f(v10_1);
            v3 = b.g(v10_1) ^ b.a[0][v2] & 0xFF;
            v1_1 = b.a[1][v2] & 0xFF ^ b.h(v10_1);
        label_211:
            v5 = b.a[1][v5] & 0xFF ^ b.e(v12);
            v4 = b.a[1][v4] & 0xFF ^ b.f(v12);
            v3 = b.a[0][v3] & 0xFF ^ b.g(v12);
            v1_1 = b.a[0][v1_1] & 0xFF ^ b.h(v12);
            goto label_239;
        }
        catch(Throwable v1) {
            goto label_8;
        }

    label_332:
        v1_1 = v2;
        v3 = v2;
        v4 = v2;
        v5 = v2;
        try {
        label_239:
            v13[v2 * 2] = b.b[0][b.a[0][b.a[0][v5] & 0xFF ^ b.e(v9_1)] & 0xFF ^ b.e(v8_1)];
            v13[v2 * 2 + 1] = b.b[1][b.a[0][b.a[1][v4] & 0xFF ^ b.f(v9_1)] & 0xFF ^ b.f(v8_1)];
            v13[v2 * 2 + 0x200] = b.b[2][b.a[1][b.a[0][v3] & 0xFF ^ b.g(v9_1)] & 0xFF ^ b.g(v8_1)];
            v13[v2 * 2 + 0x201] = b.b[3][b.a[1][b.a[1][v1_1] & 0xFF ^ b.h(v9_1)] & 0xFF ^ b.h(v8_1)];
            goto label_124;
        label_126:
            v13[v2 * 2] = b.b[0][b.a[0][v2] & 0xFF ^ b.e(v8_1)];
            v13[v2 * 2 + 1] = b.b[1][b.a[0][v2] & 0xFF ^ b.f(v8_1)];
            v13[v2 * 2 + 0x200] = b.b[2][b.a[1][v2] & 0xFF ^ b.g(v8_1)];
            v13[v2 * 2 + 0x201] = b.b[3][b.a[1][v2] & 0xFF ^ b.h(v8_1)];
        label_124:
            ++v2;
            goto label_120;
        label_324:
            v1_2 = new Object[]{v13, v11_1};
        }
        catch(Throwable v1) {
            goto label_8;
        }

        __monitor_exit(v6);
        return v1_2;
    label_8:
        __monitor_exit(v6);
        throw v1;
    }
```

这个 a 函数判断传入的字节数组、、密钥都不为空，并调用 b 函数：

```java
    public static byte[] a(byte[] arg1, int arg2, Object arg3) {
        byte[] v0 = arg1 == null || arg3 == null || arg2 < 0 ? null : b.b(arg1, arg2, arg3);
        return v0;
    }
```

b 函数应该就是对数据的加密过程，明显是个 16 次轮函数的分组密码：

```java
    private static byte[] b(byte[] arg12, int arg13, Object arg14) {
        int[] v0 = arg14[0];
        Object v1 = arg14[1];
        int v2 = arg13 + 1;
        int v4 = v2 + 1;
        int v3 = v4 + 1;
        v2 = (arg12[v2] & 0xFF) << 8 | arg12[arg13] & 0xFF | (arg12[v4] & 0xFF) << 16;
        v4 = v3 + 1;
        v2 |= (arg12[v3] & 0xFF) << 24;
        v3 = v4 + 1;
        int v5 = v3 + 1;
        v3 = (arg12[v3] & 0xFF) << 8 | arg12[v4] & 0xFF;
        v4 = v5 + 1;
        v3 |= (arg12[v5] & 0xFF) << 16;
        v5 = v4 + 1;
        v3 |= (arg12[v4] & 0xFF) << 24;
        v4 = v5 + 1;
        int v6 = v4 + 1;
        v4 = (arg12[v4] & 0xFF) << 8 | arg12[v5] & 0xFF;
        v5 = v6 + 1;
        v4 |= (arg12[v6] & 0xFF) << 16;
        v6 = v5 + 1;
        v4 |= (arg12[v5] & 0xFF) << 24;
        v5 = v6 + 1;
        int v7 = v5 + 1;
        int v8 = (arg12[v5] & 0xFF) << 8 | arg12[v6] & 0xFF | (arg12[v7] & 0xFF) << 16 | (arg12[v7 + 1] & 0xFF) << 24;
        v7 = v2 ^ v1[0];
        v6 = v3 ^ v1[1];
        v5 = v4 ^ v1[2];
        v4 = v8 ^ v1[3];
        v3 = 8;
        for(v2 = 0; v2 < 16; v2 += 2) {
            v8 = b.a(v0, v7, 0);
            int v9 = b.a(v0, v6, 3);
            int v11 = v3 + 1;
            v3 = v1[v3] + (v8 + v9) ^ v5;
            v5 = v3 >>> 1 | v3 << 0x1F;
            v3 = v4 << 1 | v4 >>> 0x1F;
            v4 = v9 * 2 + v8;
            v8 = v11 + 1;
            v4 = v4 + v1[v11] ^ v3;
            v3 = b.a(v0, v5, 0);
            v9 = b.a(v0, v4, 3);
            v11 = v8 + 1;
            v7 ^= v1[v8] + (v3 + v9);
            v7 = v7 << 0x1F | v7 >>> 1;
            v8 = v9 * 2 + v3;
            v3 = v11 + 1;
            v6 = (v6 >>> 0x1F | v6 << 1) ^ v8 + v1[v11];
        }

        int v0_1 = v1[4] ^ v5;
        v2 = v1[5] ^ v4;
        v3 = v1[6] ^ v7;
        int v1_1 = v1[7] ^ v6;
        return new byte[]{((byte)v0_1), ((byte)(v0_1 >>> 8)), ((byte)(v0_1 >>> 16)), ((byte)(v0_1 >>> 24)), ((byte)v2), ((byte)(v2 >>> 8)), ((byte)(v2 >>> 16)), ((byte)(v2 >>> 24)), ((byte)v3), ((byte)(v3 >>> 8)), ((byte)(v3 >>> 16)), ((byte)(v3 >>> 24)), ((byte)v1_1), ((byte)(v1_1 >>> 8)), ((byte)(v1_1 >>> 16)), ((byte)(v1_1 >>> 24))};
    }
```

分组密码可以去找一下特征，看到了 b 类的头上定义了两个数据，转成 16 进制之后拿去搜一下：

```java
        v0[0] = new byte[]{-87, 103, -77, -24, 4, -3, -93, 0x76, -102, -110, -128, 120, -28, -35, -47, 56, 13, -58, 53, -104, 24, -9, -20, 108, 67, 0x75, 55, 38, -6, 19, -108, 72, -14, -48, -117, 0x30, -124, 84, -33, 35, 25, 91, 61, 89, -13, -82, -94, -126, 99, 1, -125, 46, -39, 81, -101, 0x7C, -90, -21, -91, -66, 22, 12, -29, 97, -64, -116, 58, -11, 0x73, 44, 37, 11, -69, 78, -119, 107, 83, 106, -76, -15, -31, -26, -67, 69, -30, -12, -74, 102, -52, -107, 3, 86, -44, 28, 30, -41, -5, -61, -114, -75, -23, -49, -65, -70, -22, 0x77, 57, -81, 51, -55, 98, 0x71, -127, 0x79, 9, -83, 36, -51, -7, -40, -27, -59, -71, 77, 68, 8, -122, -25, -95, 29, -86, -19, 6, 0x70, -78, -46, 65, 0x7B, -96, 17, 49, -62, 39, -112, 0x20, -10, 0x60, -1, -106, 92, -79, -85, -98, -100, 82, 27, 0x5F, -109, 10, -17, -111, -123, 73, -18, 45, 0x4F, -113, 59, 71, -121, 109, 70, -42, 62, 105, 100, 42, -50, -53, 0x2F, -4, -105, 5, 0x7A, -84, 0x7F, -43, 26, 75, 14, -89, 90, 40, 20, 0x3F, 41, -120, 60, 76, 2, -72, -38, -80, 23, 85, 0x1F, -118, 0x7D, 87, -57, -115, 0x74, -73, -60, -97, 0x72, 0x7E, 21, 34, 18, 88, 7, -103, 52, 110, 80, -34, 104, 101, -68, -37, -8, -56, -88, 43, 0x40, -36, -2, 50, -92, -54, 16, 33, -16, -45, 93, 15, 0, 0x6F, -99, 54, 66, 74, 94, -63, -32}; // 0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
        v0[1] = new byte[]{0x75, -13, -58, -12, -37, 0x7B, -5, -56, 74, -45, -26, 107, 69, 0x7D, -24, 75, -42, 50, -40, -3, 55, 0x71, -15, -31, 0x30, 15, -8, 27, -121, -6, 6, 0x3F, 94, -70, -82, 91, -118, 0, -68, -99, 109, -63, -79, 14, -128, 93, -46, -43, -96, -124, 7, 20, -75, -112, 44, -93, -78, 0x73, 76, 84, -110, 0x74, 54, 81, 56, -80, -67, 90, -4, 0x60, 98, -106, 108, 66, -9, 16, 0x7C, 40, 39, -116, 19, -107, -100, -57, 36, 70, 59, 0x70, -54, -29, -123, -53, 17, -48, -109, -72, -90, -125, 0x20, -1, -97, 0x77, -61, -52, 3, 0x6F, 8, -65, 0x40, -25, 43, -30, 0x79, 12, -86, -126, 65, 58, -22, -71, -28, -102, -92, -105, 0x7E, -38, 0x7A, 23, 102, -108, -95, 29, 61, -16, -34, -77, 11, 0x72, -89, 28, -17, -47, 83, 62, -113, 51, 38, 0x5F, -20, 0x76, 42, 73, -127, -120, -18, 33, -60, 26, -21, -39, -59, 57, -103, -51, -83, 49, -117, 1, 24, 35, -35, 0x1F, 78, 45, -7, 72, 0x4F, -14, 101, -114, 120, 92, 88, 25, -115, -27, -104, 87, 103, 0x7F, 5, 100, -81, 99, -74, -2, -11, -73, 60, -91, -50, -23, 104, 68, -32, 77, 67, 105, 41, 46, -84, 21, 89, -88, 10, -98, 110, 71, -33, 52, 53, 106, -49, -36, 34, -55, -64, -101, -119, -44, -19, -85, 18, -94, 13, 82, -69, 2, 0x2F, -87, -41, 97, 30, -76, 80, 4, -10, -62, 22, 37, -122, 86, 85, 9, -66, -111}; // 0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
```

发现是 twofish 算法：

![](/pics/攻防世界-MOBILE-新手练习区/2.png)

上面的一些资源可以在 Resources/values/public.xml 中找到 ID 对应的字符串名：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<resources>
  ...
  <public id="0x7f04001a" name="activity_main" type="layout" />
  ...
  <public id="0x7f060022" name="no" type="string" />
  <public id="0x7f060023" name="two_fish" type="string" />
  ...
  <public id="0x7f060025" name="yes" type="string" />
  ...
  <public id="0x7f0b0054" name="edit_text" type="id" />
  <public id="0x7f0b0055" name="button" type="id" />
  ...
</resources>
```

可以在 Resources/values/strings.xml 中找到对应的字符串：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<resources>
  ...
  <string name="no">
    NO~ You don't get me~ T_T</string>
  <string name="two_fish">
    I have a male fish and a female fish.</string>
  <string name="what_else">
    What else?</string>
  <string name="yes">
    Yes! You got me! :)</string>
</resources>
```

最后找个库实现一下解密：

```python
#!/usr/bin/env python
from twofish import Twofish

ciphertext = [0x88, 0x4D, 0xF2, 0xDA, 0x11, 0x05, 0xD6, 0x2C, 0xE0, 0x6D, 0x55, 0x1F, 0x18, 0xA5, 0x90, 0xAD, 0x40, 0xAD, 0x80, 0x54, 0x05, 0xA2, 0x9E, 0xE2, 0x12, 0x46, 0xE6, 0x47, 0x05, 0x9D, 0xC2, 0xC6, 0x75, 0x1D, 0xD4, 0x06, 0x70, 0xFC, 0x51, 0x54, 0x09, 0x16, 0xCD, 0x5F, 0xDE, 0x0C, 0x2F, 0x4D]
ciphertext = ''.join([chr(c) for c in ciphertext])

T = Twofish('I have a male fish and a female ')

flag = ''
for i in range(0, 48, 16):
    flag += T.decrypt(ciphertext[i:i+16])
print flag
# qwb{TH3y_Io<e_EACh_OTh3r_FOrEUER}
```

# 你是谁

TODO

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" package="xyz.konso.testsrtp" platformBuildVersionCode="23" platformBuildVersionName="6.0-2166767">
    <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="23" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.CALL_PHONE" />
    <uses-permission android:name="android.permission.BROADCAST_STICKY" />
    注：部分手机如无此权限会报错
    <uses-permission android:name="android.permission.BLUETOOTH" />
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/icon" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true">
        <activity android:name="xyz.konso.testsrtp.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.view" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name="xyz.konso.testsrtp.SplashActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

```java
package xyz.konso.testsrtp;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.view.accessibility.AccessibilityNodeInfoCompat;
import android.widget.TextView;

public class SplashActivity extends Activity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(AccessibilityNodeInfoCompat.ACTION_NEXT_HTML_ELEMENT, AccessibilityNodeInfoCompat.ACTION_NEXT_HTML_ELEMENT);
        setContentView(R.layout.activity_splash);
        try {
            ((TextView) findViewById(R.id.versionNumber)).setText("Version " + getPackageManager().getPackageInfo("com.lyt.android", 0).versionName);
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        new Handler().postDelayed(new Runnable() {
            public void run() {
                SplashActivity.this.startActivity(new Intent(SplashActivity.this, MainActivity.class));
                SplashActivity.this.finish();
            }
        }, 2500);
    }
}
```

```java
package xyz.konso.testsrtp;

import android.app.Activity;
import android.media.AudioManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.Toast;
import com.iflytek.cloud.InitListener;
import com.iflytek.cloud.RecognizerListener;
import com.iflytek.cloud.RecognizerResult;
import com.iflytek.cloud.SpeechConstant;
import com.iflytek.cloud.SpeechError;
import com.iflytek.cloud.SpeechRecognizer;
import com.iflytek.cloud.SpeechSynthesizer;
import com.iflytek.cloud.SpeechUtility;
import com.iflytek.cloud.SynthesizerListener;
import org.json.JSONObject;

public class MainActivity extends Activity {
    private String TAG = "shitou";
    private Button button1;
    private Button button2;
    private AudioManager mAudioManager;
    private SpeechRecognizer mIat;
    private InitListener mInitListener = new InitListener() {
        public void onInit(int code) {
            Log.d(MainActivity.this.TAG, "SpeechRecognizer init() code = " + code);
        }
    };
    private SynthesizerListener mSynListener = new SynthesizerListener() {
        public void onCompleted(SpeechError error) {
        }

        public void onBufferProgress(int percent, int beginPos, int endPos, String info) {
        }

        public void onSpeakBegin() {
            Log.d(MainActivity.this.TAG, "speakcheck");
        }

        public void onSpeakPaused() {
        }

        public void onSpeakProgress(int percent, int beginPos, int endPos) {
        }

        public void onSpeakResumed() {
        }

        public void onEvent(int arg0, int arg1, int arg2, Bundle arg3) {
        }
    };
    private SpeechSynthesizer mTts;
    private RecognizerListener recognizerListener = new RecognizerListener() {
        public void onBeginOfSpeech() {
        }

        public void onError(SpeechError error) {
        }

        public void onEndOfSpeech() {
        }

        public void onResult(RecognizerResult results, boolean isLast) {
            Log.d(MainActivity.this.TAG, results.getResultString());
            try {
                MainActivity.this.ss = new JSONObject(results.getResultString()).getJSONArray("ws").getJSONObject(0).getJSONArray("cw").getJSONObject(0).getString("w");
            } catch (Exception e) {
                Log.d(MainActivity.this.TAG, "catch Excepetion");
            }
            if (MainActivity.this.ss.equals("\u4f60\u597d")) { // 你好
                MainActivity.this.getsna();
            }
            Log.d(MainActivity.this.TAG, MainActivity.this.ss);
        }

        public void onVolumeChanged(int volume, byte[] var2) {
        }

        public void onEvent(int eventType, int arg1, int arg2, Bundle obj) {
        }
    };
    private JSONObject res;
    private String ss;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(new background(this));
        this.mAudioManager = (AudioManager) getSystemService("audio");
        this.mAudioManager.setBluetoothScoOn(true);
        this.mAudioManager.startBluetoothSco();
        SpeechUtility.createUtility(this, "appid=561e6833");
        this.mIat = SpeechRecognizer.createRecognizer(this, this.mInitListener);
        this.mTts = SpeechSynthesizer.createSynthesizer(this, null);
    }

    public void setParam() {
        this.mIat.setParameter(SpeechConstant.DOMAIN, "iat");
        this.mIat.setParameter(SpeechConstant.LANGUAGE, "zh_cn");
        this.mIat.setParameter(SpeechConstant.ACCENT, "mandarin");
    }

    public void getsna() {
        Toast.makeText(this, "haha", 0).show();
    }

    protected void onDestroy() {
        super.onDestroy();
        this.mAudioManager.setBluetoothScoOn(false);
        this.mAudioManager.stopBluetoothSco();
    }
}
```

```cpp
signed int __fastcall JNI_OnLoad(_JavaVM *vm)
{
  jclass v2; // r4
  _JNIEnv *env; // [sp+4h] [bp-Ch]

  env = 0;
  if ( vm->functions->GetEnv(&vm->functions, (void **)&env, 65540) )
    return -1;
  if ( byte_FF45C )
    _android_log_write(3, "MSC_LOG", "JNI_OnLoad is called !");
  v2 = env->functions->FindClass(&env->functions, "java/io/FileDescriptor");
  if ( !v2 && byte_FF45C )
    _android_log_write(3, "MSC_LOG", "Unable to find Java class java.io.FileDescriptor");
  dword_FFC14 = (int)env->functions->GetFieldID(&env->functions, v2, "descriptor", "I");
  if ( dword_FFC14 || !byte_FF45C )             // get descriptor in FileDescriptor and judge
    return 65540;
  _android_log_write(3, "MSC_LOG", "Unable to find descriptor field in java.io.FileDescriptor");
  return 65540;
}
```

# References

https://www.jianshu.com/p/a2f826064e29
https://blog.csdn.net/jscese/article/details/51005447
https://blog.csdn.net/zhuzhuzhu22/article/details/80306203
https://blog.csdn.net/ldpxxx/article/details/9253369
https://stackoverflow.com/questions/23624212/how-to-convert-a-float-into-hex
https://www.52pojie.cn/thread-1105062-1-1.html
https://blog.csdn.net/jason0539/article/details/10049899
