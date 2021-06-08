---
title: Apache Rewrite（路由重写）
date: 2018-05-16 13:36:06
tags: [note, web]
---

Apache Rewrite 能够实现 URL 的跳转和隐藏真实地址。它基于 Perl 语言的正则表达式规范。平时帮助我们实现拟静态，拟目录，域名跳转，防止盗链等。

<!-- more -->

# 理解 Apache Rewrite 的三个核心

## RewriteEngine

这个是 rewrite 功能的总开关，用来开启是否启动 url rewrite。

```
RewriteEngine on
```

## RewriteCond

RewriteCond 就是一个过滤条件，简单来说，当 URL 满足 RewriteCond 配置的条件的情况，就会执行 RewriteCond 下面紧邻的 RewriteRule 语句。

RewriteCond 和 RewriteRule 是上下对应的关系。可以有 1 个或者好几个 RewriteCond 来匹配一个 RewriteRule。

`RewriteCond %{待测试项目} 正则表达式条件`。

```
RewriteEngine on
RewriteCond  %{HTTP_USER_AGENT}  ^Mozilla//5/.0.*
RewriteRule  index.php            index.m.php
```

如果设置上面的匹配规则，到来的 http 请求中的 `HTTP_USER_AGENT` 匹配 `^Mozilla//5/.0.*` 正则表达式的话，则执行下面的 RewriteRule，也就是说访问路径会跳转到 `index.m.php` 这个文件。

## RewriteRule

```
RewriteRule Pattern Substitution [flags]
```

Pattern 是一个正则匹配。Substitution 是匹配的替换 `[flags]` 是一些参数限制。

```
RewriteRule ^room/video/(\d+)\.html web/index\.php?c=room&a=video&r=$1 [QSA,NC,L]
```

意思是 以 room 开头的 `room/video/123.html` 这样子，变成 `web/index.php?c=room&a=video&r=123`。

```
RewriteRule \.(jpg|gif) http://image.baidu.com/ [R,NC,L]
```

意思是以为是访问 `.jpg` 或者 `.gif` 的文件，都会调整到 `http://image.baidu.com`。

# 重写规则的作用范围

1. 可以使用在 Apache 主配置文件 `httpd.conf` 中。

2. 可以使用在 `httpd.conf` 里定义的虚拟主机配置中。

3. 可以使用在基本目录的跨越配置文件 `.htaccess` 中。

这三种方式，都需要在写规则前，用“`RewriteEngine on`”指令来打开 rewrite 功能。

# Apache Rewrite 规则修正符

- `R[=code](force redirect)`：强制外部重定向，强制在替代字符串加上 `http://thishost[:thisport]/` 前缀重定向到外部的 URL。如果 code 不指定，将用缺省的 302 HTTP 状态码。
- `F(force URL to be forbidden)`：禁用 URL，返回 403HTTP 状态码。
- `G(force URL to be gone)`：强制 URL 为 GONE，返回 410HTTP 状态码。
- `P(force proxy)`：强制使用代理转发。
- `L(last rule)`：表明当前规则是最后一条规则，停止分析以后规则的重写。
- `N(next round)`：重新从第一条规则开始运行重写过程。
- `C(chained with next rule)`：与下一条规则关联

如果规则匹配则正常处理，该标志无效，如果不匹配，那么下面所有关联的规则都跳过。

- `T=MIME-type(force MIME type)`：强制 MIME 类型。
- `NS(used only if no internal sub-request)`：只用于不是内部子请求。
- `NC(no case)`：不区分大小写。
- `QSA(query string append)`：追加请求字符串。
- `NE(no URI escaping of output)`：不在输出转义特殊字符。

例如：

```
RewriteRule /foo/(.*) /bar?arg=P1%3d$1 [R,NE] #将能正确的将/foo/zoo转换成/bar?arg=P1=zoo
```

- `PT(pass through to next handler)`：传递给下一个处理。

例如：

```
RewriteRule ^/abc(.*) /def$1 [PT] # 将会交给/def规则处理
Alias /def /ghi
```

- `S=num(skip next rule(s))`：跳过 num 条规则。
- `E=VAR:VAL(set environment variable)`：设置环境变量。

注：P 是代理模式转发，必须用 url 全称，并且要保证 modProxy 打开，也就是下面 `httpd.conf` 中的如下两个指令：

```
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
```

如果对应 proxy 模块没加载，则会出现 403 禁止页面。

# 特殊字符的含义

- `*` 代表前面 0 或更多个字符。
- `+` 代表前面 1 或更多个字符。
- `?` 代表前面 0 或 1 个字符。
- `^` 代表字符串的开始位置。
- `$` 代表字符串结束的位置。
- `.` 为通配符，代表任何字符。
- `\` 将跟在其后的字符还原为字符本身，例如“`\+`”代表的就是“`+`”，而非其它意思。
- `^` 在方括号里表示非的意思。例如 `[^.]` 代表非通配符。

# htaccess

`.htaccess` 文件(或者"分布式配置文件"），全称是 Hypertext Access(超文本入口)。提供了针对目录改变配置的方法，即在一个特定的文档目录中放置一个包含一个或多个指令的文件，以作用于此目录及其所有子目录。作为用户，所能使用的命令受到限制。管理员可以通过 Apache 的 AllowOverride 指令来设置。概述来说，htaccess 文件是 Apache 服务器中的一个配置文件，它负责相关目录下的网页配置。通过 htaccess 文件，可以帮我们实现：网页 301 重定向、自定义 404 错误页面、改变文件扩展名、允许或阻止特定的用户或者目录的访问、禁止目录列表、配置默认文档等功能。

# Apache Rewrite 的方式

将 apache 的配置文件 `httpd.conf` 中

```
#LoadModule rewrite_module modules/mod_rewrite.so
```

前的 `#` 去掉。找到 `AllowOverride None` 改成 `AllowOverride All`。

注：`AllowOverride` 的参数设置为 `ALL`，表示整台服务器上都支持 URL 规则重写。

对于不同的网址，需要在 APACHE 中增加如下内容：

```
<Directory “E:/Apache Group/Apache2/htdocs/leapsoul”>
/*引号里代表你的web存放目录*/
/*如果是Linux，只要你定位到你网站目录即可*/
Options FollowSymLinks
AllowOverride None
</Directory>
```

Apache 服务器要读每个网站下目录下的 `.htaccess` 文件。如果没有这个文件，或者这个文档没有定义任何关于 URL 重写的规则就不会有任何效果。

只要启用 mod_rewrite，然后简单的通过一个 `.htaccess` 文件再加上一些简单的规则就可以移除 URL 中的 `index.php` 了。

## 针对整个 apache 服务器的配置

在网站配置下加入

```
RewriteEngine on
RewriteRule index.html index.php
RewriteRule (d+).html$ info.php?id=$1
```

即通过 `index.html` 访问就是 `index.php`；通过 `1.html` 访问就是 `info.php?id=1`。

## 针对 apache 服务器下的某一目录的配置

在 `.htaccess` 文件中加入

```
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-f#这里将除了实际文件以为的所有其他请求都指向下行代码给出的脚本，这里是index.php
RewriteRule .* index.php
```

在 Windows 资源管理器里面不允许你建立 `.htaccess` 这样只有扩展名的文件。所以你必须先将文件保存为其他名字，例如 `app.htaccess`。然后进入 cmd，输入 `ren a.htaccess .htaccess` 命令来对文件改名。或者新建一个记事本，另存为 `.htaccess` 即可。

# 例子

## 如果文件不存在重定向到 404 页面

```
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .? /404.php [L]
```

这里 `-f` 匹配的是存在的文件名，`-d` 匹配的存在的路径名。这段代码在进行 404 重定向之前，会判断你的文件名以及路径名是否存在。还可以在 404 页面上加一个 `?url=\$1` 参数：

```
RewriteRule ^/?(.*)$ /404.php?url=$1 [L]
```

## 域名跳转

```
RewriteEngine on
RewriteCond %{HTTP_HOST} ^en.smilejay.com [NC]
RewriteRule ^(.*) http://www.smilejay.com/ [L]
```

## 配置多用户虚拟服务器

```
ServerAdmin webmaster@kiya.us
DocumentRoot /home/www/www.kiya.us
ServerName dns.kiya.us
ServerAlias dns.kiya.us kiya.us *.kiya.us
CustomLog /var/log/httpd/osa/access_log.log” common
ErrorLog /var/log/httpd/osa/error_log.log”
AllowOverride None
Order deny,allow

RewriteEngine on
RewriteCond %{HTTP_HOST} ^[^.]+.kiya.(cn|us)$
RewriteRule ^(.+) %{HTTP_HOST}$1 [C]
RewriteRule ^([^.]+).kiya.(cn|us)(.*)$ /home/www/www.kiya.us/sylvan$3?un=$1&%{QUERY_STRING} [L]
```

## 通过 Rewrite 防止盗链

```
RewriteEngine On
RewriteCond %{HTTP_REFERER} chinaz.com [NC]
RewriteCond %{HTTP_REFERER} im286.com [NC]
RewriteRule .*\.(jpg|jpeg|gif|png|rar|zip|txt|ace|torrent|gz|swf)$ http://www.xxx.com/fuck.png [R,NC,L]
```

## 屏蔽 IE 和 Opera 浏览器

```
RewriteEngine on
RewriteCond %{HTTP_USER_AGENT} ^MSIE [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^Opera [NC]
RewriteRule ^.* – [F,L]             #这里"-"表示没有替换，浏览器为IE和Opera的访客将被禁止访问。
```

## 自动添加 `.php` 扩展名及自动换 `.html` 到 `.php` 扩展名

```
RewriteEngine On
RewriteBase /test
RewriteCond %{REQUEST_FILENAME}.php -f
RewriteRule ([^/]+)$ /test/$1.php
#for example: /test/admin => /test/admin.php
RewriteRule ([^/]+)\.html$ /test/$1.php [L]
#for example: /test/admin.html => /test/admin.php
```

## 限制仅显示图片

```
#限制目录只能显示图片
< IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !^.*\.(gif|jpg|jpeg|png|swf)$
RewriteRule .*$ – [F,L]
< /IfModule>
```

## 隐藏 `index.php`

```
Options +FollowSymLinks
IndexIgnore */*
RewriteEngine on

# if a directory or a file exists, use it directly
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d

# otherwise forward it to index.php
RewriteRule . index.php
```

```
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php/$1 [L]
```

# 参考网站

http://www.111cn.net/phper/apache/45642.htm
http://smilejay.com/2012/10/apache-rewrite/
https://www.cnblogs.com/zhenghongxin/p/6798310.html
https://phperzh.com/articles/2922
https://zybuluo.com/phper/note/73726
