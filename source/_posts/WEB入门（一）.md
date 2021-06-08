---
title: WEB入门（一）
date: 2018-07-02 12:38:52
tags: [ctf, web]
---

今天上午是葛大佬的课，继续好好做笔记。

<!-- more -->

对数据库的概念更清楚了，通过自己搭建一个有注入的网页对 PHP 和 HTML 的基本函数有了更好的理解。

# PHP

PHP 脚本以`<?PHP`开头，以`?>`结尾，默认文件扩展名为`.php`。PHP 语句以分号`;`结尾。

## 注释

```PHP
// 单行注释
# 单行注释
/*
多行注释
*/
```

## 变量规则

- 变量以\$符号开头
- 变量名称必须以字母或下划线开头
- 变量名称不能以数字开头
- 变量名称只能包含字母数字字符和下划线（`A-Z`、`a-z`、`0-9`以及`_`）
- 变量名称对大小写敏感

```php
<?php
	$a = 'I am a';
	$b = 'I am b';
	echo '$a';
	echo '<br>';
	echo "$b";
?>
```

![](/pics/WEB集训/一/1.png)

# 三层架构中的信息流

![](/pics/WEB集训/一/2.png)

# URL

统一资源定位符，提供资源（通常是文档）的路径或位置。结构如下：

```
协议://授权/路径?查询
```

# GET 请求和 POST 请求

HTTP 中定义的客户端可以发送服务器的两种操作

## GET

从服务器查询数据方式：用?分割 url 和查询的数据

## POST

向服务器传递数据方式：通过 form 表单传递

# PHP 与 MYSQL

## GET 方法传递参数

```PHP
<?php
$id=$_GET['id'];
if(!is_numeric($id)){
    echo "U r a hacker!<br>";
}else{
    echo "Connecting database!<br>";
}
?>
```

PS：`<br>`为换行符

## POST 方法传递参数

```php
<form action="test.php" method="post">
Pls input ur id: <input type="text" name="id" />
<input type="submit" />
</form>
U r NO.<?php echo $_POST['id']; ?> visitor!
```

## 与 mysql 相关函数

### 连接数据库

```
mysql_connect(servername, username, password);
```

|    参数    |                               描述                               |
| :--------: | :--------------------------------------------------------------: |
| servername |         可选。规定要连接的服务器，默认是“localhost:3306”         |
|  username  | 可选。规定登陆所使用的用户名，默认是拥有服务器进程的用户名的名称 |
|  password  |                可选。规定登陆所用的密码，默认是“”                |

### 选取数据

```
mysql_query(query, connection);
```

|    参数    |            描述             |
| :--------: | :-------------------------: |
|   query    | 必需。规定要发送的 sql 查询 |
| connection |  可选。规定 sql 连接标识符  |

### 设置活动的数据库

```
mysql_select_db(database, connection);
```

|    参数    |                      描述                       |
| :--------: | :---------------------------------------------: |
|  database  |            必需。规定要选择的数据库             |
| connection | 可选。规定 mysql 连接，如未指定，使用上一个连接 |

### 获取数据

```
mysql_fetch_array(data, array_type);
```

|    参数    |            描述            |
| :--------: | :------------------------: |
|    data    | 可选。规定要使用的数据指针 |
| array_type |     可选。规定返回结果     |

# MYSQL 命令行指令

## 更改密码

```sql
update mysql.user set password=password('test') where username='root';
flush privileges;
```

## 查看数据库

```sql
show databases;
```

## 选择数据库

```sql
use mysql;
```

## 查看当前数据库所有数据表

```sql
show tables;
```

## 查看某张表所有字段信息

```sql
desc users;
```

## 创建数据库

```sql
create database mysql;
```

## 删除数据库

```sql
drop database mysql;
```

## 创建表名为 users 的数据表（其中 id 为主键自增）

```sql
create table users(
    id int auto_increment,
    username varchar(20),
    password varchar(50),
    primary key (`id`)
);
```

## 修改表名

```sql
alter table users rename to users2;
```

## 往表中插入数据

```sql
insert into users(...) value(...);
```

## 查询表中字段的数据类型

```sql
show create table mysql;
```

# MYSQL 相关命令及注释

## 命令

> - AND：所有由 AND 连接的条件都为 TRUE，SQL 语句才执行
> - OR：只要 OR 连接的条件里有一个是 TRUE，SQL 语句就会执行
> - UNION SELECT：联合查询
> - GROUP BY：表示按照第几列进行排序
> - GROUP_CONCAT：将查询结果以一行的形式输出

## 注释

```sql
-- 单行注释
# 单行注释
/*
多行注释
*/
```

# SQL 手注练习

![](/pics/WEB集训/一/3.png)

## 判断有无注入点

![](/pics/WEB集训/一/4.png)

## 判断注入类型

![](/pics/WEB集训/一/5.png)

## 判断表中字段数

![](/pics/WEB集训/一/6.png)

![](/pics/WEB集训/一/7.png)

## UNION 查询库名

![](/pics/WEB集训/一/8.png)

## UNION 查询表名

![](/pics/WEB集训/一/9.png)

## UNION 查询字段名

![](/pics/WEB集训/一/10.png)

## UNION 查询内容（得到 flag）

![](/pics/WEB集训/一/11.png)

# 自己搭建一个 POST 方式的字符型 SQL 注入网站

本地数据库如下：

![](/pics/WEB集训/一/12.png)

源码如下：

```php
<?PHP

$id = $_POST['id'];
$conn = mysql_connect('127.0.0.1', 'root', 'root');

if($conn){
	echo "Connected success!<br>";
}else{
	echo "Connected fail!<br>";
}

$db_selected = mysql_select_db('qf', $conn);
$sql = "select * from test1 where id='$id'";
$res = mysql_query($sql, $conn);

while($row = mysql_fetch_array($res)){
	echo "username: ".$row['username']."<br>";
	echo "age: ".$row['age']."<br>";
	echo "sex: ".$row['sex']."<br>";
}

mysql_close($conn);
echo "ur sql is:";
echo "select * from test1 where id='$id'";

?>
```

```html
<form action="" method="post">
  Pls input ur id: <input type="text" name="id" /><br />
  <input type="submit" name="" , value="submit" />
</form>
```

以下为在本地注入时的过程，与 get 方式的注入过程没有什么差别，所以省去了判断的过程，直接注入

## 查询库名

![](/pics/WEB集训/一/13.png)

## 查询表名

![](/pics/WEB集训/一/14.png)

## 查询字段名

![](/pics/WEB集训/一/15.png)

## 查询内容（得到 flag）

![](/pics/WEB集训/一/16.png)
