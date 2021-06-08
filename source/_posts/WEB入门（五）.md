---
title: WEB入门（五）
date: 2018-07-10 17:10:35
tags: [ctf, web]
---

PHP 伪协议和文件包含。

<!-- more -->

# PHP 伪协议

不是指网络上的**TCP/IP 协议**，而是操作系统提供支持的一种协议，类似标准协议 HTTP、FTP。自定义协议叫做伪协议。

伪协议格式：`zzz://xxxxxx`。

## PHP 伪协议总和

|    形式     |                作用                 |
| :---------: | :---------------------------------: |
|   file://   |          访问本地文件系统           |
|   http://   |          访问 HTTP(s) 网址          |
|   ftp://    |          访问 FTP(s) URLs           |
| **php://**  | **访问各个输入/输出（I/Ostreams）** |
| **zlib://** |             **压缩流**              |
| **data://** |        **数据（RFC 2397）**         |
|   glob://   |       查找匹配的文件路径模式        |
| **phar://** |            **PHP 归档**             |
|   ssh2://   |           Secure Shell 2            |
| **rar://**  |               **RAR**               |
|   ogg://    |               音频流                |
|  expect://  |           处理交互式的流            |

## 配置

- `allow_url_fopen`：能否远程文件包含
- `allow_url_include`：能否使用伪协议

# PHP 伪协议应用

## `php://filter`

形式：`?file=php://filter/convert.base64-encode/resource=xxx.php`

`php://filter` 是一种元封装器，设计用于“数据流打开”时的“筛选过滤”应用，对本地磁盘文件进行读写。简单来讲就是可以在执行代码前将代码换个方式读取出来，只是读取，不需要开启 `allow_url_include`。

### [应用](http://4.chinalover.sinaapp.com/web7/index.php)

点击跳转页面后，通过伪协议读取源码：

![](/pics/WEB集训/五/1.png)

源码解密后得到 flag：

![](/pics/WEB集训/五/2.png)

## 变量覆盖漏洞（`extract()`）

`int extract(array &$var_array, int $extract_type = EXTR_OVERWRITE, string $prefix = null)`

`extract()` 函数从数组中将变量导入到当前的符号表。该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每个元素，将在当前符号表中创建对应的一个变量。

第二个参数 `type` 用于指定当某个变量已经存在，而数组中又有同名元素时，`extract()` 函数如何对待这样的冲突。该函数返回成功导入到符号表中的变量数目。

`extract_rules` 的默认值为 `EXTR_OVERWRITE`，表示如果有冲突，则覆盖已有的变量。

### 应用（lianxi-input1）

源码：

```php
<?php
$flag='xxxxx';
extract($_GET);
if(isset($shiyan)
{
    $content=trim($flag);
    if($shiyan==$content)
       echo'flag{......}';
    else
       echo'Oh.no';
}
?>
```

通过 `extract()` 变量覆盖，构造 `?shiyan=1&flag=1` 得到 flag。

![](/pics/WEB集训/五/3.png)

## `file_get_contents()`

`file_get_contents()` 函数把整个文件读入一个字符串中。

### 应用（lianxi-data）

源码：

```php
<?php
$user=$_GET['user'];
#echo $user;
if(isset($user)&&(file_get_contents($user,'r')==='the user is admin'))
    echo "flag{xxxxxxxxxxxxx}";
else
    echo "you are not admin ! ";
?>
```

分别通过 GET 和 POST 两种方式获得 flag：

![](/pics/WEB集训/五/4.png)

![](/pics/WEB集训/五/5.png)

## [应用四](http://level3.tasteless.eu/index.php)

先根据提示查看 `php.ini` 配置情况

![](/pics/WEB集训/五/6.png)

发现可以通过伪协议来执行代码，先获得根路径：

![](/pics/WEB集训/五/7.png)

再通过 `scandir()` 函数来扫根路径就能找到 flag 路径，直接访问就得到 flag。

![](/pics/WEB集训/五/8.png)

## `eval()` 闭合漏洞

`eval()` 函数可以执行函数内部字符串所构成的指令。通过闭合前后的括号可以达到执行其他命令的效果。

### 应用（lianxi-excute）

源码：

```php
 <?php
    include "flag.php";
    $a = @$_REQUEST['hello'];
    eval( "var_dump($a);");
    show_source(__FILE__);
?>
```

构造 payload：`);print_r(file("./flag.php")`，即 `eval("var_dump();print_r(file("./flag.php"));");`。

![](/pics/WEB集训/五/9.png)

## 应用六

源码：

```php
 <?php
    show_source(__FILE__);
    if(isset($_REQUEST['path'])){
        include($_REQUEST['path']);
    }else{
        include('phpinfo.php');
    }
?>
```

先通过伪协议扫描当前目录：`<?php print_r(scandir(".")); ?>`

![](/pics/WEB集训/五/10.png)

直接访问 `flag.php` 得到 flag。

## `phar://`

`phar://` 是数据流包装器，自 PHP5.3.0 起开始有效，也是 php 的一个函数，功能是解压还原。

### 应用

在 php 文件中写入 `<?php phpinfo(); ?>`，将文件压缩后修改后缀名为 `jpg`。

上传文件后构造 payload：`http://127.0.0.1/lianxi/phar1/include.php?file=phar://upload/11.jpg/11`。

# PHP 文件包含漏洞

在通过**函数包含文件**时，由于没有对包含的文件名进行有效的**过滤处理**，被攻击者利用从而导致了包含了**Web 根目录以外的文件**进来，就会导致文件信息的的泄漏甚至注入了恶意代码

## 分类

- 远程文件包含（RFI）：`?file=http://file/text.txt`
- 本地文件包含（LFI）：`?file=../text.txt`

## PHP 文件包含的几个函数

- `include()`：只有代码执行到该函数时才会包含文件进来，发生错误时只给出一个警告并继续向下执行。
- `include_once()`：和 `include()` 功能相同，区别在于当重复调用同一文件时，程序至调用一次。
- `require()`：只要程序执行就包含文件进来，发生错误时会输出错误结果并终止运行。
- `require_once()`：和 `require()` 功能相同，区别在于当重复调用同一文件时，程序只调用一次。

## `%00`截断（在 PHP5.3.4 之前有效）

在 `$_GET["filename"]` 中常见

形式：`filename=test.php%00.txt`

主要利用：
上传时路径必须为

- 上传路径必须为 txt、png 等结尾时
- 文件下载时，绕过白名单检查
- 文件包含时，截断后面限制（主要是文件包含时）

PS：PHP 配置中 `magic_quotes_gpc=Off`，即没有对数据进行转义解析。

## 从根目录搜寻

`/../../../../../../www/dvwa/php.ini`

前面必须加 `/`，表示从根目录开始。

## 双写重构造

`str_replace(array("../","..\"),"",$file);`

payload：`?page=/..././..././www/dvwa/php.ini`

## file 包含

`file://` 协议（本地包含文件）：将绝对路径下的文件包含进来。

漏洞利用：

1. 上传一个内容为**php**的文件
2. 利用**file**协议取**包含**上传文件（需要知道上传文件的绝对路径）
3. 实现**任意命令执行**

# PHP 相关函数整理

|         函数          |                                                                                                             功能                                                                                                             |
| :-------------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|      `extract()`      |                                      从数组中将变量导入到当前的符号表。该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每个元素，将在当前符号表中创建对应的一个变量。                                      |
|       `isset()`       |                                                                                              检测变量是否设置，并且不是 NULL。                                                                                               |
|       `trim()`        |                                                                                          移除字符串两侧的空白字符或其他预定义字符。                                                                                          |
| `file_get_contents()` |                                                               用于将文件的内容读入到一个字符串中的首选方法。如果操作系统支持，还会使用内存映射技术来增强性能。                                                               |
|      `print_r()`      |                               显示关于一个变量的易于理解的信息。如果给出的是 string、integer 或 float，将打印变量值本身。如果给出的是 array，将会按照一定格式显示键和元素。object 与数组类似。                               |
|      `scandir()`      |                                                                                              返回指定目录中的文件和目录的数组。                                                                                              |
|      `phpinfo()`      | 输出 PHP 当前状态的大量信息，包含了 PHP 编译选项、启用的扩展、PHP 版本、服务器信息和环境变量（如果编译为一个模块的话）、PHP 环境变量、操作系统版本信息、path 变量、配置选项的本地值和主值、HTTP 头和 PHP 授权信息(License)。 |
|       `eval()`        |                   把字符串按照 PHP 代码来计算。该字符串必须是合法的 PHP 代码，且必须以分号结尾。如果没有在代码字符串中调用 return 语句，则返回 NULL。如果代码中存在解析错误，则 `eval()` 函数返回 false。                    |
|     `var_dump()`      |                                                               显示关于一个或多个表达式的结构信息，包括表达式的类型与值。数组将递归展开值，通过缩进显示其结构。                                                               |
|      `include()`      |                                                                         获取指定文件中存在的所有文本/代码/标记，并复制到使用 include 语句的文件中。                                                                          |
|    `show_source()`    |                                                                                                   对文件进行语法高亮显示。                                                                                                   |

# 参考网站

http://vinc.top/2016/09/28/%E3%80%90%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E3%80%91%E5%8F%98%E9%87%8F%E8%A6%86%E7%9B%96%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/
https://lightless.me/archives/include-file-from-zip-or-phar.html
https://blog.csdn.net/Ni9htMar3/article/details/69812306?locationNum=2&fps=1
