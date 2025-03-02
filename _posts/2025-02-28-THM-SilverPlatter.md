---
title: "TryHackMe - Silver Platter"
author: DrLi
description: "Writeup of an easy-rated Linux machine from TryHackMe"
date: 2025-02-28 07:00:00 +0000
categories : [TryHackMe]
tags: [tryhackme, linux, easy, cve, adm]
img_path: /assets/img/TryHackMe/SilverPlatter
image:
    path: /assets/img/TryHackMe/SilverPlatter/silverplatter.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Silver Platter](https://tryhackme.com/r/room/silverplatter) from [TryHackMe](https://tryhackme.com/signup?referrer=603949780215185dfb191142) We will be exploiting a known web application vulnerability that allowed authentication bypass, granting access without a password. Inside, we discovered SSH credentials, leading to an initial foothold. The compromised user was part of the adm group, enabling access to logs where we uncovered a database password. However, this password belonged to another user on the system. Fortunately, this second user had unrestricted sudo privileges, providing a straightforward path to root access.

## **Enumeration**

### nmap

We start a nmap scan to check what open ports we have.

![nmap](/assets/img/TryHackMe/SilverPlatter/1.png)

We found three open ports running on the system.

The first port is 22 running OpenSSH, second is port 80 running nginx web server and port 8080 seems to be an http proxy.

### Web

Let's check the web page on port 80.

![root](/assets/img/TryHackMe/SilverPlatter/2.png)

normal website that offer some security related services and after looking deep in we can find this

![contact](/assets/img/TryHackMe/SilverPlatter/3.png)

So we know that they use SliverPeas and we have a username “scr1ptkiddy”

let’s move on to port 8080 and see what’s there


![peas](/assets/img/TryHackMe/SilverPlatter/4.png)

nothing here and after trying directory fuzzing we actually got nothing so the next thing i thought about is to go search where can i find SliverPeas at

![burp](/assets/img/TryHackMe/SilverPlatter/5.png)


so after trying it on port 80 it didn’t work but it did on port 8080


![logged](/assets/img/TryHackMe/SilverPlatter/6.png)

### Authentication bypass

now we have to get access to it we have a username but we need a password, after searching on the web i found an exploit to bypass the authentication here is how it works

![logged](/assets/img/TryHackMe/SilverPlatter/7.png)

so let’s do it 
first we need to capture the request

![logged](/assets/img/TryHackMe/SilverPlatter/8.png)

and now just remove the password field from the request

![logged](/assets/img/TryHackMe/SilverPlatter/9.png)

after forwading the request we get access to the account

![logged](/assets/img/TryHackMe/SilverPlatter/10.png)

one of the most known features of SilverPeas is the messaging system
 let’s see if we have a message

![logged](/assets/img/TryHackMe/SilverPlatter/11.png)

it looks like there is another user “Tyler” and that’s it

but after searching again in the web for exploits i found this

![logged](/assets/img/TryHackMe/SilverPlatter/12.png)

there is too many exploits but the one i think is gonna give us something is the Broken Access Control to read All messages available 
so we might find something interesting

![logged](/assets/img/TryHackMe/SilverPlatter/13.png)
so all we have to do is go to that url and change the ID 
after doing we get this

![logged](/assets/img/TryHackMe/SilverPlatter/14.png)
there we go we got ssh credentials let’s connect


## **Foothold**
![logged](/assets/img/TryHackMe/SilverPlatter/15.png)

![logged](/assets/img/TryHackMe/SilverPlatter/16.png)

we can see there is two users and we can’t access the second user home directory we might need to get access to him

## **Privilege Escalation**
if we look at the id command we can see that we are a part of a group “adm” let’s see the privileges that it has
![logged](/assets/img/TryHackMe/SilverPlatter/17.png)

ok let’s check the logs and see if there is anything interesting 

![logged](/assets/img/TryHackMe/SilverPlatter/18.png)

we can read some of these files and there might be some passwords here

![logged](/assets/img/TryHackMe/SilverPlatter/19.png)

there we go the user Tyler connected to a database using a password 
it might be his SSH password let’s try it

![logged](/assets/img/TryHackMe/SilverPlatter/20.png)

and it worked and we can see that the user is part of the “sudo” group 


![logged](/assets/img/TryHackMe/SilverPlatter/21.png)

DONE!



