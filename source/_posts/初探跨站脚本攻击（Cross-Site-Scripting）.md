---
title: 初探跨站脚本攻击（Cross-Site Scripting）
date: 2019-08-12 09:13:17
tags: web
---

最近在做渗透测试，需要接触一些 WEB 方面的基础知识。

<!-- more -->

# Intro

XSS 全称跨站脚本(Cross Site Scripting)，为不和层叠样式表(Cascading Style Sheets, CSS)的缩写混淆，故缩写为 XSS，比较合适的方式应该叫做跨站脚本攻击。

跨站脚本攻击是一种常见的 web 安全漏洞，它主要是指攻击者可以在页面中插入恶意脚本代码，当受害者访问这些页面时，浏览器会解析并执行这些恶意代码，从而达到窃取用户身份/钓鱼/传播恶意代码等行为。

注入点：

1. GET 请求参数
2. POST 请求参数
3. UA（User Agent）
4. Referer
5. URL
6. ...

总共分成三类，存储型 XSS（`Stored XSS`）、反射型 XSS（`Reflected XSS`）和 `DOM-based XSS`。几种攻击方式的图解可以参考[绿盟的这篇文章](http://blog.nsfocus.net/xss-start-finish/)，三种 XSS 可以参考[这篇文章](https://blog.csdn.net/u011781521/article/details/53894399)在本地测试

## 存储型 XSS

也叫持久型 XSS，那些将恶意脚本永久的保存在目标服务器上的攻击方式，如存储在数据库、消息论坛、访问日志、评论内容扥等。Payload 是有经过存储的，当一个页面存在存储型 XSS 的时候，XSS 注入成功后，那么每次访问该页面都将触发 XSS。

### Example

http://www.secist.com/archives/5388.html

## 反射型 XSS

也叫非持久型 XSS，当用户点击一个恶意链接，或者提交一个表单，或者进入一个恶意网站时，注入脚本进入被攻击者的网站。Web 服务器将注入脚本，比如一个错误信息，搜索结果等返回到用户的浏览器上。浏览器会执行这段脚本，因为，它认为这个响应来自可信任的服务器。最常见的是 Payload 是构造在网址的某个 GET 参数的值里。

### Example

https://blog.csdn.net/binyao02123202/article/details/9041113

## DOM-Based 型 XSS

攻击者利用原生 JavaScript 代码篡改客户端的 DOM 结构，导致用户操作执行了“意外”的动作。

### Example

```html
Select your language:

<select
  ><script>
    document.write("<OPTION value=1>" + document.location.href.substring(document.location.href.indexOf("default=") + 8) + "</OPTION>");

    document.write("<OPTION value=2>English</OPTION>");
  </script></select
>
…
```

网站 URL 则为这个样子：

```url
http://www.some.site/page.html?default=French
```

利用这个页面 DOM 结构的漏洞，向受害者发送下面的链接，点开这个链接就会将用户的 cookie 全部 alert 出来了：

```url
http://www.some.site/page.html?default=<script>alert(document.cookie)</script>
```

# How to Test

## Where

- 直接插入到 `script` 标签里
- 插入到 `html` 注释里
- 插入到 `html` 标签的属性名里
- 插入到 `html` 标签的属性值里
- 作为 `html` 标签的名字
- 直接插入到 `css` 里

### Manually

- 参数中提交 `xss payload` 代码
- 在所有可以提交参数并能在页面返回的位置上
  - `url` 的每一个参数
  - `url` 本身
  - 表单
  - 搜索框
  - ...

### Usual Scene

- 重灾区——评论区、留言区、个人信息、订单信息等
- 针对型——站内信、网页即时通讯、私信、意见反馈等
- 存在风险——搜索框、当前目录、图片属性等

# Payloads

https://github.com/pgaijin66/XSS-Payloads/blob/master/payload.txt
https://github.com/ismailtasdelen/xss-payload-list

# How to Avoid

## Basic

### 不要把不受信任的数据插入到原本允许 JavaScript 可以放置的地方

1. `<script>...永远不要把不受信任的数据放在这...</script>`：直接放在 script 标签内
2. `<!--...永远不要把不受信任的数据放在这...-->`：放在 HTML 注释内
3. `<div ...永远不要把不受信任的数据放在这...=test />`：做为一个属性名
4. `<永远不要把不受信任的数据放在这... href="/test" />`：做为一个标签名
5. `<style>...永远不要把不受信任的数据放在这...</style>`：直接放在 style 标签内复制代码原则 1——在向元素中插入不受信任的 HTML 代码之前一定要进行转义

### 在向元素中插入不受信任的 HTML 代码之前一定要进行转义

1. `<body>...将不受信任的数据转义后再放在这...</body>`
2. `<div>...将不受信任的数据转义后再放在这...</div>`
3. ...

常用的转义规则如下：

| 字符 | 转义后的字符 |
| :--: | :----------: |
| `&`  |   `&amp;`    |
| `<`  |    `&lt;`    |
| `>`  |    `&gt;`    |
| `"`  |   `&quot;`   |
| `'`  |   `&#x27;`   |
| `/`  |   `&#x2F;`   |

### 向元素的属性插入不受信任的 HTML 代码之前一定要进行转义

1. `<div attr=...将不受信任的数据转义后再放在这...>content</div>`：在没有加引号的属性值内
2. `<div attr='...将不受信任的数据转义后再放在这...'>content</div>`：在加了单引号的属性值内
3. `<div attr="...将不受信任的数据转义后再放在这...">content</div>`：在加了双引号的属性值内

### 用不受信任的数据向 JavaScript 代码赋值前，一定要进行转义

1. `<script>alert('...将不受信任的数据转义后再放在这...')</script>`：在一个字符串之内
2. `<script>x='...将不受信任的数据转义后再放在这...'</script>`：在表达式的一侧
3. `<div onmouseover="x='...将不受信任的数据转义后再放在这...'"</div>`：在事件处理函数内

有一些 JavaScript 函数永远无法安全的使用不受信任的数据作为输入：

```html
<script>
  window.setInterval("即使你做了转义，但是仍然可能被XSS攻击");
</script>
```

### 在 HTML 的上下文中对 JSON 值进行转义，并用 JSON.parse()方法来读取值

一定要确保 `http response` 中的头部信息的 `content-type` 为 `application/json`，而不是 `text/html`，因为那样的话，很可能会被人利用进行 XSS 攻击：

```
HTTP/1.1 200
Date: Wed, 06 Feb 2013 10:28:54 GMT
Server: Microsoft-IIS/7.5....
Content-Type: text/html; charset=utf-8 <-- bad
...
Content-Length: 373
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
{"Message":"No HTTP resource was found that matches the request URI 'dev.net.ie/api/pay/.html?HouseNumber=9&AddressLine
=The+Gardens<script>alert(1)</script>&AddressLine2=foxlodge+woods&TownName=Meath'.","MessageDetail":"No type was found
that matches the controller named 'pay'."}   <-- 这里script标签有可能会被执行
```

使用 `application/json` 就不会被利用：

```
HTTP/1.1 200
Date: Wed, 06 Feb 2013 10:28:54 GMT
Server: Microsoft-IIS/7.5....
Content-Type: application/json; charset=utf-8 <--good
...
```

### 将不受信任的数据作为 CSS 属性插入到文档之前一定要进行转义

1. `<style>selector { property : ...将不受信任的数据转义后再放在这...; } </style>`：属性值
2. `<style>selector { property : "...将不受信任的数据转义后再放在这..."; } </style>`：属性值
3. `<span style="property : ...将不受信任的数据转义后再放在这...">text</span>`：属性值

有一些 `css` 属性值对于不受信任的数据是无法确保万无一失的——即使做了转义，如下面的两个 `css` 属性：

```css
 {
  background-url: "javascript:alert(1)";
}
 {
  text-size: "expression(alert('XSS'))";
} // only in IE
```

应该确保所有 CSS 属性值引入的外部链接是由 `http` 开头的，而不是 `javascript` 开头的

### 向 HTML 的 URL 参数插入将不受信任的数据前，一定要将进行转义

```html
<a href="http://www.somesite.com?test=...将不受信任的数据转义后再放在这...">
  link
</a>
```

## Better

### 对于 cookie 使用 httpOnly 标识

使用 `httpOnly` 标识后的 `cookie JavaScript` 是无法获取的，又由于 `cookie` 是基于同源原则，所以一定程度上会防范那些利用客户 `cookie` 的 `XSS` 攻击。

### 在 http header 中使用 Content Security Policy

利用 `http header` 中的属性值 [`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) 来防范 `XSS`。`HTTP` 响应头中 `Content-Security-Policy` 允许站点管理者在指定的页面控制用户代理的资源。除了少数例外，这条政策将极大地指定服务源以及脚本端点。

### 使用自动转义模板系统

许多 Web 应用程序框架提供了自动的上下文转义功能，如 [`AngularJS` 严格的上下文转义](https://docs.angularjs.org/api/ng/service/sce)和 [`Go` 模板](https://golang.org/pkg/html/template/)。尽可能使用这些技术。

### 在 http header 中使用 X-XXS-Protection

`http header` 中 `X-XSS-Protection` 响应头是 `Internet Explorer`、`Chrome` 和 `Safari` 的一个功能，当检测到跨站脚本攻击时，浏览器将停止加载页面。虽然这些保护在现代浏览器中基本上是不必要的，当网站实施一个强大的 `Content-Security-Policy` 来禁用内联的 `JavaScript ('unsafe-inline')` 时, 他们仍然可以为尚不支持 [`CSP`](https://developer.mozilla.org/en-US/docs/Glossary/CSP) 的旧版浏览器的用户提供保护。

# Games

1. [alert(1) to win](https://alf.nu/alert1) ---> [alert(1) to win payloads](https://github.com/masazumi-github/alert-1-to-win)
2. [prompt(1) to win](http://prompt.ml/0) ---> [XSSChallengeWiki - prompt.ml](https://github.com/cure53/XSSChallengeWiki/wiki/prompt.ml)
3. [XSS game area](https://xss-game.appspot.com/) ---> [玩转 Google 的 XSS 游戏](https://www.freebuf.com/articles/web/36072.html)
4. [XSS Challenges](http://xss-quiz.int21h.jp/) ---> [Solutions to the wargame XSS Challenges](https://github.com/matachi/MaTachi.github.io/blob/master/src/pages/solutions-to-the-wargame-xss-challenges-at-xss-quiz-int21h-jp.md)

# Advanced

- [如何防止 XSS 攻击](https://juejin.im/post/5bad9140e51d450e935c6d64)
- [XSS with length restriction](https://blog.cm2.pw/length-restricted-xss/)
- [XSS 过滤绕过速查表](https://www.freebuf.com/articles/web/153055.html)
- [XSS 攻击进阶篇——那些年我们看不懂的 XSS](http://blog.nsfocus.net/xss-advance/)
- [XSS 攻击冷门花样玩法总结](https://www.freebuf.com/articles/web/61268.html)
- [戏耍 XSS 的一些技巧](https://www.freebuf.com/articles/web/74324.html)
- [Bypass xss 过滤的测试方法](https://wooyun.js.org/drops/Bypass%20xss%E8%BF%87%E6%BB%A4%E7%9A%84%E6%B5%8B%E8%AF%95%E6%96%B9%E6%B3%95.html)

# References

https://juejin.im/post/5bcc9487518825780e6eaf12
https://www.fooying.com/the-art-of-xss-1-introduction/
http://blog.nsfocus.net/xss-start-finish/
