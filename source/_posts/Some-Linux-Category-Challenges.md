---
title: Some Linux Category Challenges
date: 2019-04-15 17:05:27
tags: [ctf, wp, linux]
---

在 Byte Bandits CTF 2019 和 WPICTF 2019 中又遇到了 Linux 题，记录一下。

<!-- more -->

# Byte Bandits CTF 2019

## bash-fu

```bash
$ nc 13.234.130.76 7002
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-4.4$ ls
ls
bash: LS: command not found
bash-4.4$ pwd
pwd
bash: PWD: command not found
```

显然 bash 是区分大小写的，而后台有一个程序把我们输入的命令改成了大写字母。谷歌一下可以找到[shell 如何将字母进行大小写转换](https://www.cyberciti.biz/faq/linux-unix-shell-programming-converting-lowercase-uppercase/)。然后定义一下变量，执行`${l,,}`就能执行小写的命令了。

```bash
bash-4.4$ l="ls /"
l="ls /"
bash-4.4$ ${l,,}
${l,,}
bin    etc    jail   media  opt    root   sbin   sys    usr
dev    home   lib    mnt    proc   run    srv    tmp    var
bash-4.4$ l="ls /jail/"
l="ls /jail/"
bash-4.4$ ${l,,}
${l,,}
flag.txt  jail
bash-4.4$ c="cat /jail/flag.txt"
c="cat /jail/flag.txt"
bash-4.4$ ${c,,}
${c,,}
flag{b@$h_jails_are_3asy_p3@sy}
```

看一下 `jail`，主要就是把小写字母替换成了大写：

```bash
bash-4.4$ cat jail
cat jail
preexec () {
    filtered=$(echo $BASH_COMMAND | tr '[:lower:]' '[:upper:]')
    eval $filtered
}
preexec_invoke_exec () {
    [ -n "$COMP_LINE" ] && return  # do nothing if completing
    [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return # don't cause a preexec for $PROMPT_COMMAND
    [ "$BASH_COMMAND" = "shopt -s extdebug" ] && return
    preexec
    return 1
}
shopt -s extdebug
set -o noglob
trap 'preexec_invoke_exec' DEBUG && shopt -s extdebug

# vim:ft=sh
```

还看到另外有一种做法是，用 `$0`：

```bash
bash-4.4$ $0
$0
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
bash-4.4$ cd /jail
cd /jail
bash-4.4$ ls
ls
flag.txt  jail
bash-4.4$ cat flag.txt
cat flag.txt
flag{b@$h_jails_are_3asy_p3@sy}
```

测试了一下发现 `$0` 表示当前使用的 shell：

```bash
root@152486b98e3d:~# echo $0
/bin/bash
root@152486b98e3d:~# $0
root@152486b98e3d:~# exit
root@152486b98e3d:~#
```

# WPICTF 2019

## suckmore-shell

```bash
$ ssh ctf@107.21.60.114
ctf@107.21.60.114's password:
SuckMORE shell v1.0.1. Note: for POSIX support update to v1.1.0
suckmore>ls
suckmore>ls -h
sleep: invalid option -- 'h'
Try 'sleep --help' for more information.
suckmore>dir
bin  boot  dev	etc  home  lib	lib64  lost+found  media  mnt  opt  proc  root	run  sbin  srv	sys  tmp  usr  var
suckmore>cd home
cal: failed to parse timestamp or unknown month name: home
```

`ls` 被 `alias` 成了 `sleep`，`cd` 也变成了 `cal`，可以用 `dir` 来代替 `ls`。尝试用 `$0` 无果：

```
suckmore>$0
SuckMORE shell v1.0.1. Note: for POSIX support update to v1.1.0
suckmore>sh
Why would you ever want to leave suckmore shell?
```

这里用 `exec` 来换 shell：

```bash
suckmore>exec /bin/sh
suckmore>ls
sh: /usr/bin/ls: Permission denied
suckmore>dir
bin  boot  dev	etc  home  lib	lib64  lost+found  media  mnt  opt  proc  root	run  sbin  srv	sys  tmp  usr  var
suckmore>cd home
suckmore>dir
ctf
suckmore>cd ctf
suckmore>dir
flag
suckmore>cat flag
sh: /usr/bin/cat: Permission denied
suckmore>sed '' flag
WPI{bash_sucks0194342}
```

## pseudo-random

```bash
$ ssh ctf@prand.wpictf.xyz
ctf@prand.wpictf.xyz's password:
sh-4.4$ ls
bin  boot  dev	etc  home  lib	lib64  lost+found  media  mnt  opt  proc  root	run  sbin  srv	sys  tmp  usr  var
sh-4.4$ cd home
sh-4.4$ ls
ctf
sh-4.4$ cd ctf
sh-4.4$ ls
sh-4.4$ ls -a
.  ..  .bash_logout  .bash_profile  .bashrc
sh-4.4$ cd /
sh-4.4$ ls
bin  boot  dev	etc  home  lib	lib64  lost+found  media  mnt  opt  proc  root	run  sbin  srv	sys  tmp  usr  var
sh-4.4$ cd dev
sh-4.4$ ls
console  core  fd  full  mqueue  null  ptmx  pts  random  shm  stderr  stdin  stdout  tty  urandom  zero
sh-4.4$ file *random
random:  openssl enc'd data with salted password
urandom: ASCII text
```

根据题目的提示，在 dev 目录下找到了一个不寻常的文件。通过 `openssl` 解密 `aes-256-cbc`，指定解密文件为 `random`，指定口令存放文件为 `urandom`：

```bash
sh-4.4$ openssl enc -d -aes-256-cbc -in random -kfile urandom
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
Being holy in our church means installing a wholly free operating system--GNU/Linux is a good choice--and not putting any non-free software on your computer. Join the Church of Emacs, and you too can be a saint!
And lo, it came to pass, that the neophyte encountered the Beplattered One and humbly posed the question "Oh great master, is it a sin to use vi?" And St. IGNUcuis dist thus reply unto him, "No, my young hacker friend, it is not a sin. It is a penance."
WPI{@11_Ur_d3v1c3s_r_b3l0ng_2_us}
```

## crond

```bash
$ ssh ctf@crond.wpictf.xyz
ctf@crond.wpictf.xyz's password:
sh-4.4$ ls
bin  boot  dev	etc  home  lib	lib64  lost+found  media  mnt  opt  proc  root	run  sbin  srv	sys  tmp  usr  var
sh-4.4$ cd home
sh-4.4$ ls
ctf
sh-4.4$ cd ctf
sh-4.4$ ls
sh-4.4$ ls -a
.  ..  .bash_logout  .bash_profile  .bashrc
sh-4.4$ cd /
```

找了一圈没什么收获，尝试看看进程下有什么特殊的地方：

```bash
sh-4.4$ ps
sh: ps: command not found
sh-4.4$ ls /proc
1    acpi	cpuinfo    execdomains	ioports    kmsg		mdstat	 net	       self	 sysrq-trigger	version
10   buddyinfo	crypto	   fb		irq	   kpagecgroup	meminfo  pagetypeinfo  slabinfo  sysvipc	version_signature
11   bus	devices    filesystems	kallsyms   kpagecount	misc	 partitions    softirqs  thread-self	vmallocinfo
320  cgroups	diskstats  fs		kcore	   kpageflags	modules  sched_debug   stat	 timer_list	vmstat
321  cmdline	dma	   interrupts	key-users  loadavg	mounts	 schedstat     swaps	 tty		xen
8    consoles	driver	   iomem	keys	   locks	mtrr	 scsi	       sys	 uptime		zoneinfo
sh-4.4$ cd proc
sh-4.4$ for i in `ls */cmdline`; do cat -A $i; echo ''; done
/bin/bash^@/bin/init_d^@
su^@ctf^@
sh^@
sleep^@1^@
cat: 1482/cmdline: No such file or directory

/bin/bash^@/usr/bin/fakecron^@
cat^@-A^@self/cmdline^@
cat^@-A^@thread-self/cmdline^@
```

尝试把每个进程的 `cmdline` 读出来，发现了跑着一个叫 `/usr/bin/fakcron` 的东西。`cron` 是运用 Linux 所不可缺少的工具，可用来定期的管理获取日志的软件，定期的检查系统状态，可用来监视进程或者其它主机是否正常运行。

```bash
sh-4.4$ sed '' /usr/bin/fakecron
#!/bin/bash
# Cron. But worse.
#
# Copyright (c) 2019, SuckMore Software, a division of WPI Digital Holdings Ltd.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyrig
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#    This product includes software developed by SuckMore Software, a division
#    of WPI Digital Holdings Ltd.
# 4. Neither the name of the SuckMore Software, a division of WPI Digital Holdings
#    Ltd, nor the names of its contributors may be used to endorse or promote
#    products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY SuckMore Software, a division of
# WPI Digital Holdings Ltd., ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# SuckMore Software, a division of WPI Digital Holdings Ltd.
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

file="/etc/deadline"

cron() {
    second=0
    minute=0
    hour=0
    day=1;
    month=1;
    year=2019;

    while true; do
        sleep 1;
        target_second=`cut -d " " -f 6 $file`
        target_minute=`cut -d " " -f 5 $file`
        target_hour=`cut -d " " -f 4 $file`
        target_day=`cut -d " " -f 3 $file`
        target_month=`cut -d " " -f 2 $file`
        target_year=`cut -d " " -f 1 $file`

        if [[ "$second" -eq 59 ]]; then
            minute=$((minute+1));
            second=0;
        elif [[ "$minute" -eq 59 ]]; then
            hour=$((hour+1));
            second=0;
            minute=0;
        else
            second=$((second+1));
        fi

        if [[ "$year" -eq "$target_year" ]] \
            && [[ "$month" -eq "$target_month" ]] \
            && [[ "$day" -eq "$target_day" ]] \
            && [[ "$hour" -eq "$target_second" ]] \
            && [[ "$minute" -eq "$target_minute" ]] \
            && [[ "$second" -eq "$target_hour" ]]; then
            # echo "WPI{}" > /home/ctf/flag.txt
            exec_flag
        fi

        rm /etc/faketimerc
        echo "$year-$month-$day $hour:$minute:$second" > /etc/faketimerc
    done
}

cron &
```

发现只要在 `/etc/faketimerc` 中的时间和 `/etc/deadline` 中的值相同的时候，就会在家目录生成 flag：

```bash
sh-4.4$ cat /etc/faketimerc
2019-1-1 0:0:11
sh-4.4$ cat /etc/deadline
2020 1 1 0 1 0
sh-4.4$ echo "2019 1 1 0 2 0" > /etc/deadline
sh-4.4$ cat /etc/faketimerc
2019-1-1 0:2:51
sh-4.4$ ls /home/ctf/
flag.txt
sh-4.4$ cat /home/ctf/flag.txt
"WPI{L1nUxH@ck3r01a4}"
```

# References

https://www.cyberciti.biz/faq/linux-unix-shell-programming-converting-lowercase-uppercase/
https://dark-lambda.com/2019/04/14/ctf/bytebandits-ctf-2019/bash-fu/
https://www.youtube.com/watch?v=RgcchGiTxpk
https://infosec.rm-it.de/2019/04/15/wpictf-2019-linux-category/
https://blog.51cto.com/shjia/1427138
https://www.netkiller.cn/cryptography/openssl/index.html
http://man.linuxde.net/openssl
https://www.cnblogs.com/wang_yb/p/3804200.html
