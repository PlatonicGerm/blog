## Begin
For level 0, we simply have to log on via `ssh` as `bandit0` at `bandit.labs.overthewire.org` on port `2220`. We are provided the password `bandit0` to accomplish this.
```
❯ ssh -p 2220 bandit0@bandit.labs.overthewire.org
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit0@bandit.labs.overthewire.org's password: 
...
bandit0@bandit:~$ 
```

## Level 0
The password for the next level is stored in a file named `readme`. We can just `cat readme` for the password.
```
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

## Level 1
The next password is located in a file called `-` in our `home` directory. Performing an `ls -l` will show that the file does exist in our `home` directory.
```
bandit1@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit2 bandit1 33 May  7  2020 -
```
Simply trying to `cat` the file will cause the command to attempt to read from `stdin`, however, we can we can append `./` to the file name to ensure the command uses are file for output.
```
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

## Level 2
The file containing the next password has spaces in the file name. 
```
bandit2@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit3 bandit2 33 May  7  2020 spaces in this filename
```
When giving the filename, we can escape the spaces by adding a `\` before each space, or by using quotes around the file name. Alternatively, we can also just use tab auto-complete to specify the file after typing the first few characters.
```
bandit2@bandit:~$ cat spaces\ in\ this\ filename 
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
bandit2@bandit:~$ cat "spaces in this filename"
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

## Level 3
The next password is stored in a hidden file inside of the `inhere` directory. Executing `ls -l` shows us the directory. Using `cd`, we can change into that directory.
```
bandit3@bandit:~$ ls -l
total 4
drwxr-xr-x 2 root root 4096 May  7  2020 inhere
bandit3@bandit:~$ cd inhere/
```
Executing `ls` inside the directory, however, makes it appear empty.
```
bandit3@bandit:~/inhere$ ls -l
total 0
```
To reveal hidden files, we need to append `-a` to `ls` to display all files. A file is made hidden on *nix systems when the filename is prepended with a `.`.
```
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 May  7  2020 .
drwxr-xr-x 3 root    root    4096 May  7  2020 ..
-rw-r----- 1 bandit4 bandit3   33 May  7  2020 .hidden
```
Since we now know the name of our hidden file, `.hidden`, we can use `cat` to grab the password.
```
bandit3@bandit:~/inhere$ cat .hidden 
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

## Level 4
This password is stored in the only human-readable format in the `inhere` directory. When we `cd` to the `inhere` directory and perform an `ls`, we find that there are 10 files in the directory.
```
bandit4@bandit:~$ cd inhere/
bandit4@bandit:~/inhere$ ls
-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09
```
If we try to cat a file that is not human-readable, we can recieve some wonky output.
```
bandit4@bandit:~/inhere$ cat ./-file00
/`2ғ%rL~5gbandit4@bandit:~/inhere$
```
Instead of guessing-and-checking, we can use the `file` command to find out which of these is human-readable.
```
bandit4@bandit:~/inhere$ file ./*
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
```
The `*` is a wildcard character, meaning match any-and-all-characters. This way, we could specify all the files in this directory in one command. Now that we know which file has the password, we just need `cat` to view it.
```
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

## Level 5
The password is in the `inhere` directory, but this time the file is not only human-readable, but also 1033 bytes in size and is not executable. `cd` to the `inhere` directory and running `ls` shows that there are now many directories our password could be hiding in.
```
bandit5@bandit:~$ cd inhere/
bandit5@bandit:~/inhere$ ls -l
total 80
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere00
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere01
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere02
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere03
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere04
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere05
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere06
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere07
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere08
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere09
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere10
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere11
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere12
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere13
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere14
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere15
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere16
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere17
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere18
drwxr-x--- 2 root bandit5 4096 May  7  2020 maybehere19
```
Running `ls` shows that each of these directories all contain multiple files.
```
bandit5@bandit:~/inhere$ ls maybehere00
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3
```
Using the `find` command, we can search all of these directories to return the file that matches our criteria.
```
bandit5@bandit:~/inhere$ find ./ -type f -size 1033c ! -executable
./maybehere07/.file2
```
Now we can grab the password.
```
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

## Level 6
This level is very similar to the previous challenge, however this time the file is stored somewhere on the server, and is now owned by user `bandit7`, owned by group `bandit6`, and is 33 bytes in size. We can once again use the `find` command to search for the file with the given criteria. We can additionally redirect all error messages, such as those specifying we don't have appropriate permissions to look in a directory, by appending `2> /dev/null` to the end of our command.
```
bandit6@bandit:~$ find / -size 33c -user bandit7 -group bandit6 2> /dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

## Level 7
The password is stored in a file named `data.txt`, next to the word `millionth`. Using `grep`, we can search the file for the word `millionth` to find the password.
```
bandit7@bandit:~$ grep millionth data.txt 
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

## Level 8
This time, our password is contained in `data.txt` and is the only line that occurs once. Executing `cat` on the file gives us a lot of output. Using `wc`, we can see that the file is infact 1001 lines long!
```
bandit8@bandit:~$ cat data.txt                    
VkBAEWyIibVkeURZV5mowiGg6i3m7Be0                                                                    
zdd2ctVveROGeiS2WE3TeLZMeL5jL7iM 
...
flyKxCbHB8uLTaIB5LXqQNuJj3yj00eh
w4zUWFGTUrAAh8lNkS8gH3WK2zowBEkA
bandit8@bandit:~$ wc -l data.txt 
1001 data.txt
```
Instead of manually searching the file, we can use `sort` and `pipe` the output to `uniq` to count the number of times each line occurs. Then, we can `pipe` that output to `grep` to search for lines beginning in `1` (indicating the number of times the line appears). It is important to `sort` the file first as `uniq` will filter based on adjacent lines.
```
bandit8@bandit:~$ sort data.txt | sort | uniq -c | grep '^ *1 '
      1 UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

## Level 9
Our password is stored in `data.txt`. However, this time, while the file does contain human-readable strings, the file does contain large amounts of random non human-readable data. We will first need to use `strings` to display the human-readable test, which can then be piped to `grep` for searching. Knowing the password contains multple `=` characters before the password, we can make a `grep` search for multiple instances of `==` occuring anywhere in the line to find the password.
```
bandit9@bandit:~$ strings data.txt | grep '.*==.*'
========== the*2i"4
========== password
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```

## Level 10
The password for this file is stored in `data.txt` and is `base64` encoded. Using `base64`, we can decode the file to retrieve the password.
```
bandit10@bandit:~$ base64 -d < data.txt 
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

## Level 11
The password is stored in `data.txt`, however all the characters have been shifted by 13 characters. This is also known as a `ceasar cipher` or `rot13`. We can easily decode the file using either online tools, or `tr`.
```
bandit11@bandit:~$ cat data.txt | tr a-zA-Z n-za-mN-ZA-M 
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

## Level 12
The password is contained in a `hex` dump of a file that has been compressed repeatedly. We must first reverse the `hex` dump and determine the type of file this was. We can use `xxd` and `file` to accomplish this. Note, we will need to create a directory in `/tmp` and `cp` the file there to work on this challenge.
```
bandit12@bandit:~$ mkdir /tmp/platonicgerm
bandit12@bandit:~$ cd /tmp/platonicgerm
bandit12@bandit:/tmp/platonicgerm$ cp ~/data.txt .
bandit12@bandit:/tmp/platonicgerm$ cat data.txt | xxd -r > data.bin
bandit12@bandit:/tmp/platonicgerm$ file data.bin 
data.bin: gzip compressed data, was "data2.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
```
Seeing we now have `gzip` file, we can rename the file and try to extract the contents.
```
bandit12@bandit:/tmp/platonicgerm$ mv data.bin data.gz
bandit12@bandit:/tmp/platonicgerm$ gunzip data.gz 
bandit12@bandit:/tmp/platonicgerm$ ls
data
```
This gives us another file, simply named `data`. Using `file`, we descover that this is now a `bzip2` file. Once again, we rename the file and extract it's contents.
```
bandit12@bandit:/tmp/platonicgerm$ mv data data.bz2
bandit12@bandit:/tmp/platonicgerm$ bunzip2 data.bz2 
bandit12@bandit:/tmp/platonicgerm$ ls
data
```
Once again, we have another file to examine. We can continue the process with `file`, renaming the file with the appropriate file extension, and extracting until we have the password.
```
bandit12@bandit:/tmp/platonicgerm$ file data
data: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/platonicgerm$ mv data data.gz
bandit12@bandit:/tmp/platonicgerm$ gunzip data.gz 
bandit12@bandit:/tmp/platonicgerm$ ls
data
bandit12@bandit:/tmp/platonicgerm$ file data
data: POSIX tar archive (GNU)
bandit12@bandit:/tmp/platonicgerm$ mv data data.tar
bandit12@bandit:/tmp/platonicgerm$ tar xf data.tar 
bandit12@bandit:/tmp/platonicgerm$ ls
data5.bin  data.tar
bandit12@bandit:/tmp/platonicgerm$ file data5.bin; rm data.tar
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/platonicgerm$ mv data5.bin data5.tar
bandit12@bandit:/tmp/platonicgerm$ tar xf data5.tar 
bandit12@bandit:/tmp/platonicgerm$ ls
data5.tar  data6.bin
bandit12@bandit:/tmp/platonicgerm$ file data6.bin; rm data5.tar 
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/platonicgerm$ mv data6.bin data6.bz2
bandit12@bandit:/tmp/platonicgerm$ bunzip2 data6.bz2 
bandit12@bandit:/tmp/platonicgerm$ ls
data6
bandit12@bandit:/tmp/platonicgerm$ file data6
data6: POSIX tar archive (GNU)
bandit12@bandit:/tmp/platonicgerm$ mv data6 data6.tar
bandit12@bandit:/tmp/platonicgerm$ tar xf data6.tar 
bandit12@bandit:/tmp/platonicgerm$ ls
data6.tar  data8.bin
bandit12@bandit:/tmp/platonicgerm$ file data8.bin; rm data6.tar 
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/platonicgerm$ mv data8.bin data8.gz
bandit12@bandit:/tmp/platonicgerm$ gunzip data8.gz 
bandit12@bandit:/tmp/platonicgerm$ ls
data8
bandit12@bandit:/tmp/platonicgerm$ file data8 
data8: ASCII text
bandit12@bandit:/tmp/platonicgerm$ cat data8 
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

## Level 13

The password is stored in `/etc/bandit_pass/bandit14`, however can only be read by `bandit14`. We do have a private `ssh` key to log in as `bandit14`. If we `ls`, we can find the file containing the private `ssh` key.
```
bandit13@bandit:~$ ls                                                                        [1/258]
sshkey.private                                                                                      
bandit13@bandit:~$ cat sshkey.private 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxkkOE83W2cOT7IWhFc9aPaaQmQDdgzuXCv+ppZHa++buSkN+
gg0tcr7Fw8NLGa5+Uzec2rEg0WmeevB13AIoYp0MZyETq46t+jk9puNwZwIt9XgB
...
qT1EvQKBgQDKm8ws2ByvSUVs9GjTilCajFqLJ0eVYzRPaY6f++Gv/UVfAPV4c+S0
kAWpXbv5tbkkzbS0eaLPTKgLzavXtQoTtKwrjpolHKIHUz6Wu+n4abfAIRFubOdN
/+aLoRQ0yBDRbdXMsZN/jvY44eM+xRLdRVyMmdPtP8belRi2E2aEzA==
-----END RSA PRIVATE KEY-----
```
We can use this private key to `ssh` into the host as `bandit14` to grab the password.
```
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.                              
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
...
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```

## Level 14
The next password can be retrieved by submitting the current level's password to `port 30000` on `localhost`. `nc` can be used to accomplish this task. Remember, the current password is stored at `/etc/bandit_pass/bandit14`.
```
bandit14@bandit:~$ echo "4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e" | nc -v localhost 30000
localhost [127.0.0.1] 30000 (?) open
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

## Level 15
This challenge is similar to the previous one, however this time `port 30001` uses `ssl` encryption. Simply trying to use `nc` as before will not work.
```
bandit15@bandit:~$ echo "BfMYroe26WYalil77FoDi9qh59eK5xNr" | nc -v localhost 30001
localhost [127.0.0.1] 30001 (?) open
```
This time, we need to use `openssl` to connect to the open port.
```
bandit15@bandit:~$ echo "BfMYroe26WYalil77FoDi9qh59eK5xNr" | openssl s_client -connect localhost:300
01                                                                                                  
CONNECTED(00000003)                                                                                 
depth=0 CN = localhost                                                                              
verify error:num=18:self signed certificate                                                         
verify return:1                                                                                     
depth=0 CN = localhost   
verify return:1                                                                                     
---                                               
Certificate chain                                                                                   
 0 s:/CN=localhost                                                                                  
   i:/CN=localhost                                                                                  
---                                                                                                 
Server certificate                                                                                  
-----BEGIN CERTIFICATE-----                                                                         
MIICBjCCAW+gAwIBAgIEZOzuVDANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls                                    
b2NhbGhvc3QwHhcNMjEwOTMwMDQ0NTU0WhcNMjIwOTMwMDQ0NTU0WjAUMRIwEAYD  
...
    Start Time: 1635949861
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
```

## Level 16
This time, we need to submit our current password on an open `ssl` port again, but this time the possible port ranges from `31000` to `32000`. We can use `nmap` to locate the open port using `ssl` to send our password to.
```
bandit16@bandit:~$ nmap -p31000-32000 -T5 -A localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2021-11-03 15:36 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00023s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2021-09-30T04:46:02
|_Not valid after:  2022-09-30T04:46:02
|_ssl-date: TLS randomness does not represent time 
31691/tcp open  echo
31790/tcp open  ssl/unknown
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LDAPSearchReq, LPDStri
ng, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq: 
|_    Wrong! Please enter the correct current password
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2021-09-30T04:46:02
|_Not valid after:  2022-09-30T04:46:02
|_ssl-date: TLS randomness does not represent time 
31960/tcp open  echo
...
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.37 seconds
```
From here, we can send the current password to `port 31790` using `openssl` to retrieve the password.
```
bandit16@bandit:~$ echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | openssl s_client -connect localhost:317
90 -ign_eof | tee                                                                                   
depth=0 CN = localhost                                                                              
verify error:num=18:self signed certificate                                                         
verify return:1                                                                                     
depth=0 CN = localhost                                                                              
verify return:1                                   
CONNECTED(00000003)                               
...
---
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
...
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```
However, this time we don't recieve the password, but a private `ssh` key. We can paste this key into a file in the `/tmp` directory using either `vi` or `nano`. We then need to `chmod` the file so that it has the correct permissions so that we can use `ssh` as the next user. The password is stored in /etc/bandit_pass/bandit17`.
```
bandit16@bandit:~$ vi /tmp/platonicgerm.key
bandit16@bandit:~$ cat /tmp/platonicgerm.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
...
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
bandit16@bandit:~$ chmod 600 /tmp/platonicgerm.key                                                  
bandit16@bandit:~$ ssh -i /tmp/platonicgerm.key bandit17@localhost
Could not create directory '/home/bandit16/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
...
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn
```

## Level 17
The password for the next user is stored in `passwords.new`, and is the only change between `passwords.old` and `passwords.new`. Using `diff`, we can easily spot the difference and retrieve the password.
```
bandit17@bandit:~$ ls -l
total 8
-rw-r----- 1 bandit18 bandit17 3300 May  7  2020 passwords.new
-rw-r----- 1 bandit18 bandit17 3300 May  7  2020 passwords.old
bandit17@bandit:~$ diff passwords.new passwords.old 
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
```

## Level 18
This password is stored in a file named `readme` in the user's home directory, however, `.bashrc` has been modified to kick us out when we log in using `ssh`.
```
❯ ssh -p 2220 bandit18@bandit.labs.overthewire.org                
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames          
                                                                                                    
bandit18@bandit.labs.overthewire.org's password:
...
Byebye !
Connection to bandit.labs.overthewire.org closed.
```
We can instead have `ssh` run a command after autenticating so that we may read the password.
```
❯ ssh -p 2220 bandit18@bandit.labs.overthewire.org "cat readme"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
Alternatively, if we required a full shell on the host, we can alter the command to launch `bash` without loading `.bashrc`, however, we will not have the regular prompt.
```
❯ ssh -p 2220 bandit18@bandit.labs.overthewire.org "/bin/bash -norc"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
uname -a; whoami
Linux bandit.otw.local 5.4.8 #1 SMP Sun May 3 12:31:45 UTC 2020 x86_64 GNU/Linux
bandit18
cat readme
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

## Level 19
We have a `suid` binary in our home directory. Executing it with no arguments reveals it will run a command as a different user.
```
bandit19@bandit:~$ ls -l
total 8
-rwsr-x--- 1 bandit20 bandit19 7296 May  7  2020 bandit20-do
bandit19@bandit:~$ ./bandit20-do 
Run a command as another user.
  Example: ./bandit20-do id
```
When we execute `bandit20-do`, it explains that it will run a command as another user. When we try the example given, it shows that `id` is ran as `bandit20`.
```
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
```
With this in mind, we can use `bandit20-do` to grab the password from `/etc/bandit_pass/bandit20`.
```
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

## Level 20
We are provided with another `suid` binary. This time, the application will connect to a port we specify on the host. It will read the incomming data, and if it matches `bandit20`'s password, will provide the next password. We can set up a `nc` listener that will send the password when the binary connects.
```
bandit20@bandit:~$ ls -l
total 12
-rwsr-x--- 1 bandit21 bandit20 12088 May  7  2020 suconnect
bandit20@bandit:~$ echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -lvnp 9001 &
[1] 5383
bandit20@bandit:~$ listening on [any] 9001 ...

bandit20@bandit:~$ ./suconnect 9001
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 51260
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

## Level 21
There is a `cron` job that is being executed that will assist in locating the next password. We can begin by examining which jobs are running on the host.
```
bandit21@bandit:~$ ls /etc/cron.d
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
```
There are a few different `cron` jobs available. We are interested in `cronjob_bandit22`. We can examine what this job is doing using `cat`.
```
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```
This `cron` job executes a script located at `/usr/bin/cronjob_bandit22.sh` at regular intervals. We can now try to examine this script to see what it is doing.
```
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh 
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
We can see that this script will `cat` the password into `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv`. Because of the permissions set on the file, we should be able to `cat` it ourselves to retrieve the password.
```
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

## Level 22
The password this time is hidden somewhere in a `cron` job. The `cron` job can be found in `cronjob_bandit23`.
```
bandit21@bandit:~$ ls /etc/cron.d
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
```
We can see that this job executes a script located at `/etc/bin/cronjob_bandit23.sh`. We can use `cat` to see what this script is doing.
```
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```
This script generates a `md5sum` of a `string` that is provided, and uses that `string` to determine where the file will be located, while saving the password for that user in the file. We can exploit this by manually executing the command that generates the filename by supplying `bandit23` in place of `$myname` to determine where the password has been saved.
```
bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

# Level 23
This is yet another `cron` job related challenge. As with the previous challenges, we need to determine what this `cron` job is doing.
```
bandit23@bandit:~$ ls /etc/cron.d/
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
bandit23@bandit:~$ cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
```
Now that we know what script the job is executing, we can try to take a look to see what it is doing.
```
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```
Examining the script, we see that it will `cd` to `/var/spool/$myname`, where `$myname` is the name of the user that the script is ran as. It will then attempt to execute all scripts in that directory. If we can plant a script in `/var/spool/bandit24` directory, then we can have a script placed in that directory to retrieve the password. First, we check to see if we are able to write into that directory.
```
bandit23@bandit:~$ ls -l /var/spool
total 12
drwxrwx-wx 35 root bandit24 4096 Nov  3 16:47 bandit24
drwxr-xr-x  3 root root     4096 May  3  2020 cron
lrwxrwxrwx  1 root root        7 May  3  2020 mail -> ../mail
drwx------  2 root root     4096 Jan 14  2018 rsyslog
```
Since we can write in `/var/spool/bandit24`, we can write a simple script to try to grab the password. We make a directory in `/tmp` for us to work in, and create our script and give it proper permissions before using `cp` to place it into `/var/spool/bandit24`.
```
bandit23@bandit:~$ mkdir -p /tmp/germ
bandit23@bandit:~$ cd /tmp/germ
bandit23@bandit:/tmp/germ$ touch password
bandit23@bandit:/tmp/germ$ vi password.sh
bandit23@bandit:/tmp/germ$ cat password.sh 
#!/bin/bash
cat /etc/bandit_pass/bandit24 >> /tmp/germ/password
bandit23@bandit:/tmp/germ$ chmod 777 password.sh
bandit23@bandit:/tmp/germ$ chmod 666 password 
bandit23@bandit:/tmp/germ$ cp password.sh /var/spool/bandit24/
```
After waiting for a short bit, we can `cat` `password` for the next password.
```
bandit23@bandit:/tmp/germ$ cat password
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

## Level 24
To retrieve the next password, we have to submit the password for `bandit24`, plus a 4-digit code, to the `daemon` listening on `port 30002`. Let's first try to send it something to see what it returns.
```
bandit24@bandit:~$ echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0000" | nc -v localhost 30002
localhost [127.0.0.1] 30002 (?) open
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Wrong! Please enter the correct pincode. Try again.
Timeout. Exiting.
```
Knowing this, we can create a simple script to generate a file containing a list of possible combinations to pass to `nc`.
```
bandit24@bandit:~$ mkdir -p /tmp/germ
bandit24@bandit:~$ cd /tmp/germ
bandit24@bandit:/tmp/germ$ vi brute.sh 
bandit24@bandit:/tmp/germ$ cat brute.sh 
#/bin/bash
for i in {0000..9999}
do
    echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i"
done
bandit24@bandit:/tmp/germ$ bash brute.sh > combinations.lst
bandit24@bandit:/tmp/germ$ nc localhost 30002 < combinations.lst 
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Wrong! Please enter the correct pincode. Try again.
Wrong! Please enter the correct pincode. Try again.
...
Wrong! Please enter the correct pincode. Try again.
Wrong! Please enter the correct pincode. Try again.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
```

## Level 25
For the next password, we are provided with a private `ssh` key for the next user in our home directory, however attempts to try to login result in being kicked out.
```
bandit25@bandit:~$ ls -l                           
total 4                                                                                             
-r-------- 1 bandit25 bandit25 1679 May  7  2020 bandit26.sshkey 
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost
Could not create directory '/home/bandit25/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
...
Connection to localhost closed.
```
Based on the level hint, we know that `bandit26` does not use `/bin/bash` as their `shell`. We can peak at `/etc/passwd` to see what their `shell` is.
```
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```
Now we can try to see what their `shell`, `/usr/bin/showtext`, does.
```
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```
When we long in, the `more` command is executed to display `text.txt`. Since the output of `text.txt` fills the entire terminal, the application then exits. We can force `more` to remain open by changing the number of rows our terminal has, then using `v` to enter an editor to try to view the password at `/etc/bandit_pass/bandit26` or to launch a `shell`.
```
bandit25@bandit:~$ stty rows 4
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost                                        
Could not create directory '/home/bandit25/.ssh'.                                                   
The authenticity of host 'localhost (127.0.0.1)' can't be established.                              
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.                        
Are you sure you want to continue connecting (yes/no)? yes
...
  _                     _ _ _   ___   __  
--More--(16%)
```
We can now press `v` to enter the editor, and enter the following to spawn a `bash` shell.
```
:set shell=/bin/bash
:shell
```
Now we can grab `bandit26`'s password.
```
bandit26@bandit:~$ cat /etc/bandit_pass/bandit26
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
```

## Level 26
The password for `bandit27` is simple. If you have not spawned a shell in the previous level, you will need to. Executing `ls` shows we have a `suid` binary. This binary appears to operate similarly to a previous challenge.
```
bandit26@bandit:~$ ls -l
total 12
-rwsr-x--- 1 bandit27 bandit26 7296 May  7  2020 bandit27-do
-rw-r----- 1 bandit26 bandit26  258 May  7  2020 text.txt
bandit26@bandit:~$ ./bandit27-do 
Run a command as another user.
  Example: ./bandit27-do id
```
We can use this to read `/etc/bandit_pass/bandit27` to grab the password.
```
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```

## Level 27
The next password is stored in a `git` repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo`. We can make a directory in `/tmp` and clone the repo.
```
bandit27@bandit:~$ mkdir -p /tmp/germ
bandit27@bandit:~$ cd /tmp/germ
bandit27@bandit:/tmp/germ$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit27/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
...
bandit27-git@localhost's password: 
remote: Counting objects: 3, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (3/3), done.
```
After we clone the repo, we can simply browse it to find the file containing the next password.
```
bandit27@bandit:/tmp/germ$ ls -l
total 4
drwxr-sr-x 3 bandit27 root 4096 Nov  3 18:24 repo
bandit27@bandit:/tmp/germ$ cd repo/
bandit27@bandit:/tmp/germ/repo$ ls -l
total 4
-rw-r--r-- 1 bandit27 root 68 Nov  3 18:24 README
bandit27@bandit:/tmp/germ/repo$ cat README 
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
```

## Level 28
We have another `git` repository that contains the password. We can begin with cloning this in `/tmp`
```
bandit28@bandit:~$ mkdir -p /tmp/germ
bandit28@bandit:~$ cd /tmp/germ
bandit28@bandit:/tmp/germ$ git clone ssh://bandit28-git@localhost/home/bandit28-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit28/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit28/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit28-git@localhost's password: 
remote: Counting objects: 9, done.
remote: Compressing objects: 100% (6/6), done.
Receiving objects: 100% (9/9), 795 bytes | 0 bytes/s, done.
remote: Total 9 (delta 2), reused 0 (delta 0)
Resolving deltas: 100% (2/2), done.
```
The repo only contains a single file when we quickly looking it over, but does not contain the password.
```
bandit28@bandit:/tmp/germ$ ls -l
total 4
drwxr-sr-x 3 bandit28 root 4096 Nov  3 18:28 repo
bandit28@bandit:/tmp/germ$ cd repo
bandit28@bandit:/tmp/germ/repo$ ls -l
total 4
-rw-r--r-- 1 bandit28 root 111 Nov  3 18:28 README.md
bandit28@bandit:/tmp/germ/repo$ cat README.md 
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```
However, since this is a `git` repo, we can try to see if there was any recent `commit`s that might be interesting. When we do this, we can find the next password.
```
bandit28@bandit:/tmp/germ/repo$ git show
commit edd935d60906b33f0619605abd1689808ccdd5ee
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    fix info leak

diff --git a/README.md b/README.md
index 3f7cee8..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: bbc96594b4e001778eee9975372716b2
+- password: xxxxxxxxxx
```

## Level 29
We are presented with another `git` repository. Once again, we clone this in `/tmp`.
```
bandit29@bandit:~$ mkdir -p /tmp/germ
bandit29@bandit:~$ cd /tmp/germ
bandit29@bandit:/tmp/germ$ git clone ssh://bandit29-git@localhost/home/bandit29-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit29/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit29-git@localhost's password: 
remote: Counting objects: 16, done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (16/16), done.
Resolving deltas: 100% (2/2), done.
```
Browsing the repo, there only appears to be a single file stating that no passwords are allowed in production.
```
bandit29@bandit:/tmp/germ$ ls -l
total 4
drwxr-sr-x 3 bandit29 root 4096 Nov  3 18:35 repo
bandit29@bandit:/tmp/germ$ cd repo/
bandit29@bandit:/tmp/germ/repo$ ls -l
total 4
-rw-r--r-- 1 bandit29 root 131 Nov  3 18:35 README.md
bandit29@bandit:/tmp/germ/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```
However, we can check which `git` branch is currently selected, and which `branches` are available. Doing so, we find a `dev` branch, so we switch to that.
```
bandit29@bandit:/tmp/germ/repo$ git branch -r
  origin/HEAD -> origin/master
  origin/dev
  origin/master
  origin/sploits-dev
bandit29@bandit:/tmp/germ/repo$ git branch
* master
bandit29@bandit:/tmp/germ/repo$ git checkout dev
Branch dev set up to track remote branch dev from origin.
Switched to a new branch 'dev'
```
Performing an `ls` on the directory is now a bit different. If we `cat` `README.md`, we can find the password.
```
bandit29@bandit:/tmp/germ/repo$ ls -l
total 8
drwxr-sr-x 2 bandit29 root 4096 Nov  3 18:38 code
-rw-r--r-- 1 bandit29 root  134 Nov  3 18:38 README.md
bandit29@bandit:/tmp/germ/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```

## Level 30
Being presented with another `git` repo, we clone this in `/tmp`
```
bandit30@bandit:~$ mkdir -p /tmp/germ
bandit30@bandit:~$ cd /tmp/germ
bandit30@bandit:/tmp/germ$ git clone ssh://bandit30-git@localhost/home/bandit30-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit30/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit30/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit30-git@localhost's password: 
remote: Counting objects: 4, done.
Receiving objects: 100% (4/4), done.
remote: Total 4 (delta 0), reused 0 (delta 0)
```
However, all of the previous techniques that has worked on previous levels do not work here.
```
bandit30@bandit:/tmp/germ/repo$ cat README.md 
just an epmty file... muahaha
bandit30@bandit:/tmp/germ/repo$ git show
commit 3aefa229469b7ba1cc08203e5d8fa299354c496b
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:54 2020 +0200

    initial commit of README.md

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..029ba42
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+just an epmty file... muahaha
bandit30@bandit:/tmp/germ/repo$ git log
commit 3aefa229469b7ba1cc08203e5d8fa299354c496b
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:54 2020 +0200

    initial commit of README.md
bandit30@bandit:/tmp/germ/repo$ git branch -r
  origin/HEAD -> origin/master
  origin/master
```
Instead, we can try to use `git tag` to enumerate `git` tags and attempt to view their contents.
```
bandit30@bandit:/tmp/germ/repo$ git tag
secret
bandit30@bandit:/tmp/germ/repo$ git show secret
47e603bb428404d265f59c42920d81e5
```

## Level 31
Yet another `git` repo. We clone this in `/tmp`.
```
bandit31@bandit:~$ mkdir -p /tmp/germ
bandit31@bandit:~$ cd /tmp/germ
bandit31@bandit:/tmp/germ$ git clone ssh://bandit31-git@localhost/home/bandit31-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit31/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password: 
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 4 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (4/4), done.
```
This time, the `README.md` file contains some interesting info.
```
bandit31@bandit:/tmp/germ$ cd repo/
bandit31@bandit:/tmp/germ/repo$ ls -l
total 4
-rw-r--r-- 1 bandit31 root 147 Nov  3 18:49 README.md
bandit31@bandit:/tmp/germ/repo$ cat README.md 
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```
We create our `key.txt` with the contents `May I come in?` and attempt to push the file, however it is unsuccessful.
```
bandit31@bandit:/tmp/germ/repo$ echo "May I come in?" > key.txt
bandit31@bandit:/tmp/germ/repo$ git add key.txt 
The following paths are ignored by one of your .gitignore files:
key.txt
Use -f if you really want to add them.
```
Given the output, it appears `.gitignore` is preventing us from pushing the key. However, we can just append `-f` to the command, and continue to push `key.txt` to recieve the password.
```
bandit31@bandit:/tmp/germ/repo$ git add -f key.txt 
bandit31@bandit:/tmp/germ/repo$ git commit -m "file upload"
[master 77cf54f] file upload
 1 file changed, 1 insertion(+)
 create mode 100644 key.txt
bandit31@bandit:/tmp/germ/repo$ git push origin master
Could not create directory '/home/bandit31/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password: 
Counting objects: 3, done.
Delta compression using up to 2 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 321 bytes | 0 bytes/s, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
...
```

## Level 32
Logging in presents us with an intereresting welcome message.
```
WELCOME TO THE UPPERCASE SHELL
>> 
```
Trying to execute any command appears to be translated to all-uppercase.
```
>> ls
sh: 1: LS: not found
>> whoami
sh: 1: WHOAMI: not found
```
We can try to execute `$0` to see if we can break out of the shell. `$0` expands the name of the `shell` or `shell script`, so this can help with breaking out of a restricted `shell` enviroment.
```
>> $0
$ whoami
bandit33
```
After breaking out and executing `whoami`, we notice we are actually running as user `bandit33`. Now we can grab the next password from `/etc/bandit_pass/bandit33`.
```
$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee
```
