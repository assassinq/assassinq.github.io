---
title: 从零开始认识跨站请求伪造（Cross-site Request Forgery）
date: 2019-08-20 13:51:34
tags: web
---

常常听到 CSRF，但不怎么了解它具体的机制，简单记录一下。

<!-- more -->

# What is CSRF

CSRF（跨站请求伪造，`Cross-site Request Forgery`）也被称为 `One-click Attack` 或者 `Session Riding`。简单的来说，就是**攻击者利用受害者的身份，以受害者的名义发送恶意请求**。

CSRF 这种攻击方式在 2000 年被国外的安全人员提出，但在国内，直到 2006 年才开始被关注。2008 年，国内外的多个大型社区和交互网站分别爆出 CSRF 漏洞，如：纽约时报，Metafilter，YouTube，百度等等。而现在，互联网的许多站点仍对此毫无防备，以至于安全业界称 CSRF 为“沉睡的巨人”。

![](/pics/从零开始认识跨站请求伪造/1.png)

首先比较一下 XSS 和 CSRF：

```
# XSS
攻击者发现XSS漏洞——构造代码——发送给受害人——受害人打开——攻击者获取受害人的cookie——完成攻击
XSS容易发现，因为攻击者需要登录后台完成攻击。管理员可以看日志发现攻击者
XSS的目的是获取用户的身份信息，攻击者窃取到的是用户的身份（session/cookie）
# CSRF
攻击者发现CSRF漏洞——构造代码——发送给受害人——受害人打开——受害人执行代码——完成攻击
CSRF的攻击一直是管理员自己实现的，攻击者只负责了构造代码
CSRF是利用用户当前的身份去做一些未经过授权的操作
```

用一个小故事简单的介绍一下什么是 CSRF：

1. 我们先假设支付宝存在 CSRF 漏洞，受害者的支付宝账号是 `alibaba`，攻击者的支付宝账号是 `hacker`
2. 然后我们通过网页请求的方式 `http://zhifubao.com/withdraw?account=alibaba&amount=10000&for=alibaba2` 可以把账号 `alibaba` 的 10000 元转到另外一个账号 `alibaba2` 上去。通常情况下，该请求发送到支付宝服务器后，服务器会先验证该请求是否来自一个合法的 `session` 并且该 `session` 的用户已经成功登陆
3. 攻击者在支付宝有账号 `hacker`，并且他知道上文中的 URL 可以进行转账操作，于是他可以发送一个请求 `http://zhifubao.com/withdraw?account=alibaba&amount=10000&for=hacker` 到支付宝后台。但是这个请求是来自攻击者而不是来自 `alibaba`，所以不能通过安全认证，因此该请求作废
4. 这时，攻击者 `hacker` 想到了用 CSRF 的方式，他自己做了个黄色网站，在网站中放了如下代码：`http://zhifubao.com/withdraw?account=alibaba&amount=10000&for=hacker`，并且通过黄色链接诱使受害者来访问他的网站。当受害者禁不住诱惑时就会点了进去，上述请求就会从受害者的浏览器发送到支付宝，而且这个请求会附带受害者的浏览器中的 `cookie`
5. 大多数情况下，该请求会失败，因为支付宝会要求受害者的认证信息，但是如果刚访问支付宝不久，还没有关闭支付宝页面，浏览器中的 `cookie` 仍然存有认证信息，这个请求就会得到响应，从受害者的账户中转 10000 元到 `hacker` 账户里，而受害者丝毫不知情，攻击者拿到钱后逍遥法外

# How to Attack

CSRF 有两种攻击方式，一种是基于 GET 请求方式的利用，另一种是基于 POST 请求方式的利用。

## Get Method

```
<img src='https://www.xxx.com/bank.php?transferTo=hacker' width='0' height='0' />
<a href='/test'>start</a>
```

## Post Method

```
<iframe style="display:none" name="csrf-frame"></iframe>
<form method='POST' action='https://www.xxx.com/bank.php' target="csrf-frame" id="csrf-form">
  <input type='hidden' name='id' value='3'>
  <input type='submit' value='submit'>
</form>
<script>document.getElementById("csrf-form").submit()</script>
```

# How to Prevent

防范 CSRF 攻击，其实本质就是要求网站能够识别出哪些请求是非正常用户主动发起的。这就要求我们在请求中嵌入一些额外的授权数据，让网站服务器能够区分出这些未授权的请求。

## Synchronizer token pattern

令牌同步模式（Synchronizer token pattern，简称 STP）是在用户请求的页面中的所有表单中嵌入一个 token，在服务端验证这个 token 的技术。token 可以是任意的内容，但是一定要保证无法被攻击者猜测到或者查询到。攻击者在请求中无法使用正确的 token，因此可以判断出未授权的请求

## Cookie-to-Header Token

对于使用 Js 作为主要交互技术的网站，将 CSRF 的 token 写入到 cookie 中

```
Set-Cookie: CSRF-token=i8XNjC4b8KVok4uw5RftR38Wgp2BFwql; expires=Thu, 23-Jul-2015 10:25:33 GMT; Max-Age=31449600; Path=/
```

然后使用 javascript 读取 token 的值，在发送 http 请求的时候将其作为请求的 header

```
X-CSRF-Token: i8XNjC4b8KVok4uw5RftR38Wgp2BFwql
```

最后服务器验证请求头中的 token 是否合法

## 验证码

使用验证码可以杜绝 CSRF 攻击，但是这种方式要求每个请求都输入一个验证码，显然没有哪个网站愿意使用这种粗暴的方式，用户体验太差，用户会疯掉的。

## 验证 HTTP Referer 字段

根据 HTTP 协议，在 HTTP 头部中有一个 Referer 字段，它记录了该 HTTP 请求所在的地址，表示 HTTP 请求从那个页面发出的。比如当访问 `http://zhifubao.com/withdraw?account=lyq&amount=10000&for=xxx`，用户必须先登录支付宝网站，然后通过点击页面的的按钮来触发转账事件。此时，转账请求的 Referer 值就是转账页面所在的 URL，通常是以 `zhifubao.com` 域名开头的地址。如果攻击者要实行 CSRF 攻击，那么他只能在自己的站点构造请求，此时 Referer 的值就指向黑客自己的网站。因此要防御 CSRF 攻击，支付宝只需要对每一个转账请求验证其 Referer 值，如果是以 `zhifubao.com` 开头的域名，则是合法请求，相反，则是非法请求并拒绝。

这种方法的好处就是简单易行，只需要在后台添加一个拦截器来检查 Referer 即可。然而这种办法并不是万无一失，Referer 的值是由浏览器提供的，一些低级的浏览器可以通过某种方式篡改 Referer 的值，这就给了攻击者可乘之机；而一些高级浏览器处于安全考虑，可以让用户设置发送 HTTP 请求时不再提供 Referer 值，这样当他们正常访问支付宝网站时，因为没有提供 Referer 值而被误认为 CERF 攻击，拒绝访问。实际应用中通常采用第二种方法来防御 CSRF 攻击。

## 尽量使用 POST，限制 GET

GET 接口能够直接将请求地址暴露给攻击者，所以要防止 CSRF 一定最好不要用 GET。当然 POST 并不是万无一失，攻击者只需要构造一个 form 表单就可以，但需要在第三方页面做，这样就增加了暴露的可能性。

## 在 HTTP 头部添加自定义属性

这种方法也是使用 token 并验证，但是它是把 token 放在 HTTP 请求头部中。通过使用 AJAX 我们可以在我们的请求头部中添加我们的自定义属性，但是这种方法要求我们将整个站的请求全部改成 AJAX，如果是新站还好，老站的话无疑是需要重写整个站点的，这是很不可取的。

# Challenges

- [RootMe 解题报告 [Web-Client : CSRF – 0 protection]](http://exp-blog.com/2019/01/13/pid-2927/)
- [RootMe 解题报告 [Web-Client : CSRF – token bypass]](http://exp-blog.com/2019/01/13/pid-2933/)

# References

https://www.freebuf.com/articles/web/55965.html
https://segmentfault.com/a/1190000008505616
https://www.jianshu.com/p/855395f9603b
https://juejin.im/post/5bc009996fb9a05d0a055192
https://www.cnblogs.com/hyddd/archive/2009/04/09/1432744.html
https://blog.techbridge.cc/2017/02/25/csrf-introduction/
