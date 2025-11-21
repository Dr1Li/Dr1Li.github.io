---
title: "HackTheBox - Jugglin"
author: DrLi
description: "Writeup of a medium-rated DFIR Sherlock from HackTheBox."
date: 2025-11-21 14:11:00 +0100
categories: [HackTheBox, Sherlocks]
tags: [hackthebox, sherlock, dfir, wsl2, windows forensics, api hooking, keystroke monitoring, powershell, rtlunicode, writfile, API Monitor]
img_path: /assets/img/HackTheBox/Sherlocks/Jugglin
image:
    path: /assets/img/HackTheBox/Sherlocks/Jugglin/jugglin.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

Jugglin from [HackTheBox](https://www.hackthebox.com/) is a medium-difficulty DFIR Sherlock investigating insider threat activity leveraging Windows Subsystem for Linux version 2 (WSL2). Analysis of API Monitor log files reveals the initial command execution ("whoami"), keystroke interception using key functions such as RtlUnicodeToUTF8N and WideCharToMultiByte, and monitoring execution via WriteFile. The insider interacts with a Kali Linux distribution inside WSL2, accessing sensitive files such as flag.txt and confidential.txt, with flags extracted from specific hooked API responses. Powershell's Invoke-WebRequest module is used for data extraction, and forensic artifacts include attacker commands, download links, and SHA1 hashes. This case highlights advanced API hooking techniques to detect elusive WSL2-based attacker activity.


### Description

<aside>
💡

**Forela Corporation heavily depends on the utilisation of the Windows Subsystem for Linux (WSL), and currently, threat actors are leveraging this feature, taking advantage of its elusive nature that makes it difficult for defenders to detect. In response, the red team at Forela has executed a range of commands using WSL2 and shared API logs for analysis.**

</aside>

### Questions

**What was the initial command executed by the insider?**

<aside>
💡

Whoami

</aside>

```bash
we have two files:
12/20/2023  12:36 PM         2,695,692 Attacker.apmx64
12/20/2023  12:36 PM         4,151,615 Insider.apmx64
```

```bash
this is my first time seeing these type of files and after reading about them 
i learned that these are API Monitor log files that capture Windows API calls made by executables during runtime.
and to investigate them we can use API monitor 
plus HackTheBox released a Blog talking about this: https://www.hackthebox.com/blog/tracking-wsl-activity-with-api-hooking
```

```bash
so to get the first command that was run from the blog we can see:
it is evident how the first keystroke from the command hostname was transformed into a new character string using Win32 functions such as WideCharToMultiByte and RtlUnicodeToUTF8N. Subsequently, after the translation, the keystroke “h” was written to the console using the Win32 function WriteFile.
the fourth argument from the function RtlUnicodeToUTF8N is the character we are looking for
and in our situation we have this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image.png)

```bash
if we follow the function we can finally get "whoami"
```

**Which string function can be intercepted to monitor keystrokes by an insider?**

<aside>
💡

RtlUnicodeToUTF8N, WideCharToMultiByte

</aside>

```bash
as the blog says these are the functions responsible for monitoring keystokes
```

**Which Linux distribution the insider was interacting with?**

<aside>
💡

kali

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image1.png)

```bash
the output of the whoami command returned Kali
```

**Which file did the insider access in order to read its contents?**

<aside>
💡

flag.txt

</aside>

```bash
using the same way we answerd question one we nee to follow the fourth argument of the function 
so we can see the attacker accessed the onedrive and desktop folders then he read the content of flag.txt
```

**Submit the first flag.**

<aside>
💡

HOOK_tH1$_apI_R7lUNIcoDet0utf8N

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image2.png)

**Which PowerShell module did the insider utilize to extract data from their machine?**

<aside>
💡

Invoke-WebRequest

</aside>

```bash
same stuff just follow we can find this
```

**Which string function can be intercepted to monitor the usage of Windows tools via WSL by an insider?**

<aside>
💡

RtlUTF8ToUnicodeN

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image3.png)

```bash
we can get the function used from the picture above
```

**The insider has also accessed 'confidential.txt'. Please provide the second flag for submission.**

<aside>
💡

H0ok_ThIS_@PI_rtlutf8TounICOD3N

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image4.png)

**Which command executed by the attacker resulted in a 'not found' response?**

<aside>
💡

lsassy

</aside>

```bash
openning the attacker file we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Jugglin/image5.png)

**Which link was utilized to download the 'lsassy' binary?**

<aside>
💡

[http://3.6.165.8/lsassy](http://3.6.165.8/lsassy)

</aside>

**What is the SHA1 hash of victim 'user' ?**

<aside>
💡

e8f97fba9104d1ea5047948e6dfb67facd9f5b73

</aside>

```bash
after the tools was dowloaded the attacker ran a command and the output shows the sha1 of the user
```

**When an attacker utilizes WSL2, which WIN32 API would you intercept to monitor its behavior?**

<aside>
💡

writefile

</aside>
DONE!