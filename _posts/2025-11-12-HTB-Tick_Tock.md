---
title: "HackTheBox - TickTock"
author: DrLi
description: "Writeup of a medium-rated DFIR Sherlock from HackTheBox."
date: 2025-11-12 21:20:00 +0100
categories: [HackTheBox, Sherlocks]
tags: [hackthebox, sherlock, dfir, windows forensics, powershell, c2 analysis, teamviewer, event logs, bitlocker, malware, defender analysis]
img_path: /assets/img/HackTheBox/Sherlocks/TickTock
image:
    path: /assets/img/HackTheBox/Sherlocks/TickTock/ticktock.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

TickTock from [HackTheBox](https://www.hackthebox.com/) is a medium-difficulty DFIR Sherlock focused on investigating a social engineering‑assisted intrusion against Forela. By correlating activity across Windows event logs, PowerShell history, and Defender telemetry, we uncover how attackers gained remote access, deployed a C2 agent, and attempted data manipulation. The case emphasizes the importance of endpoint visibility and detailed log forensics in identifying post‑exploitation behavior.


### Description

<aside>
💡

**Gladys is a new joiner in the company, she has recieved an email informing her that the IT department is due to do some work on her PC, she is guided to call the IT team where they will inform her on how to allow them remote access. The IT team however are actually a group of hackers that are attempting to attack Forela.**

</aside>

### Questions

**What was the name of the executable that was uploaded as a C2 Agent?**

<aside>
💡

merlin.exe

</aside>

```bash
i was able to find this by just checking the prefetch files for any suspicious programs
```

**What was the session id for in the initial access?**

<aside>
💡

-2102926010

</aside>

```bash
since the hackers got remote access to the machine by the help of the victim so they used a legit program to connect to her machine 
and it is TeamViewer from the browser history we can see that teamviewer was recently downloaded 
and if we check the logs under C:\Users\gladys\Appdata\Local\TeamViewer\Logs 
we find the only successful connection and that's the ID we are looking for 
```

```bash
2023/05/04 11:35:27.432  5716       3108 D3   LoginDesktopWindowImpl::GuiThreadFunction(): ChangeThreadDesktop(): SetThreadDesktop to winlogon successful
2023/05/04 11:35:27.433  5716       5840 D3   SessionManagerDesktop::IncomingConnection: Connection incoming, sessionID = -2102926010
2023/05/04 11:35:27.433  5716       5840 D3   CParticipantManagerBase::SetMyParticipantIdentifier(): pid=[1764218403,-2102926010]
2023/05/04 11:35:27.434  5716       5840 D3!! InterProcessBase::ProcessControlCommand Command 39 not handled
2023/05/04 11:35:27.434  5716       5840 D3   IpcRouterClock: received router time: 20230504T103558.360315
2023/05/04 11:35:27.435  5716       4292 D3   CLogin::run(), session id: -2102926010
```

**The attacker attempted to set a bitlocker password on the** `C:` **drive what was the password?**

<aside>
💡

reallylongpassword

</aside>

```bash
we can find this by checking the PowerShell event logs 
```

![image.png](/assets/img/HackTheBox/Sherlocks/TickTock/image.png)

```bash
this decodes to:

$SecureString = ConvertTo-SecureString "reallylongpassword" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector
```

**What name was used by the attacker?**

<aside>
💡

fritjof olfasson

</aside>

```bash
this can be found in the TeamViewer logs we sow earlier
```

```bash
2023/05/04 11:35:31.958  5716       2436 D3   CParticipantManagerBase participant DESKTOP-R30EAMH (ID [1764218403,-2102926010]) was added with the role 3
2023/05/04 11:35:31.958  5716       2436 D3   New Participant added in CParticipantManager DESKTOP-R30EAMH ([1764218403,-2102926010])
2023/05/04 11:35:31.958  5716       2436 D3   CParticipantManagerBase participant fritjof olfasson (ID [1761879737,-207968498]) was added with the role 6
2023/05/04 11:35:31.958  5716       2436 D3   New Participant added in CParticipantManager fritjof olfasson ([1761879737,-207968498])
2023/05/04 11:35:31.960  5716       5840 D3   CParticipantManager::SynchronizationComplete: session=-2102926010, this=000000DB11B3E090
2023/05/04 11:35:31.961  5716       5840 D3   SendInfo() executed.
```

**What IP address did the C2 connect back to?**

<aside>
💡

52.56.142.81

</aside>

```bash
in the SYSON logs if we filter for the C2 binary "merlin" we will be able to find any connections made by it
```

![image.png](/assets/img/HackTheBox/Sherlocks/TickTock/image1.png)

**What category did Windows Defender give to the C2 binary file?**

<aside>
💡

VirTool:Win32/Myrddin.D

</aside>

```bash
searching through the Windows Defender event logs we can find 
```

![image.png](/assets/img/HackTheBox/Sherlocks/TickTock/image2.png)

**What was the filename of the powershell script the attackers used to manipulate time?**

<aside>
💡

Invoke-TimeWizard.ps1

</aside>

```bash
looking through the powershell history file located at C:\Users\gladys\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
we can find this
```

```bash
set-executionpolicy bypass
cd ..
cd ..
cd .\Users\
cd .\gladys\Desktop\
dir
.\Invoke-TimeWizard.ps1
```

**What time did the initial access connection start?**

<aside>
💡

**04/05/2023 11:35:27**

</aside>

```bash
in the same event we found earlier where we found the ip
the time of initial access is there
```

**What is the SHA1 and SHA2 sum of the malicious binary?**

<aside>
💡

ac688f1ba6d4b23899750b86521331d7f7ccfb69:42ec59f760d8b6a50bbc7187829f62c3b6b8e1b841164e7185f497eb7f3b4db9

</aside>

```bash
we can find in the windows defender logs in C:\ProgramData\Microsoft\Windows Defender\Support 
due to the previous Defender alerts. When defender fires an alert the SHA1 & 2 sums of the
malicious file are logged within MPLog-07102015-052145 log file.
```

**How many times did the powershell script change the time on the machine?**

<aside>
💡

2371

</aside>

```bash
this can be found in the System and Security event logs by filtering for "The system time was changed"
```

**What is the SID of the victim user?**

<aside>
💡

S-1-5-21-3720869868-2926106253-3446724670-1003

</aside>

```bash
this is easy to find using the autopsy OS accounts feature
```

![image.png](/assets/img/HackTheBox/Sherlocks/TickTock/image3.png)

DONE!