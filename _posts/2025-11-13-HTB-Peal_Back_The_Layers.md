---
title: "HackTheBox - Peel Back The Layers"
author: DrLi
description: "Writeup of an easy-rated Forensics challenge from HackTheBox"
date: 2025-11-13 12:30:00 +0000
categories : [HackTheBox, Challenges]
tags: [hackthebox, docker, forensics, backdoor, reverse shell, steampunk]
img_path: /assets/img/HackTheBox/Challenges/Peel_Back_The_Layers
image:
    path: /assets/img/HackTheBox/Challenges/forensics.png
---

The Peel Back The Layers challenge from [HackTheBox](https://www.hackthebox.com/) is an easy Docker forensics task where an attacker inserted a backdoor into a public Docker image using LD_PRELOAD. By investigating Docker image layers, extracting the deleted shared object, and analyzing its code, the backdoor's reverse shell payload was recovered along with the hidden flag.

# Peel Back The Layers (HTB Easy)

# Description

<aside>
💡

A well known hacker rival of ours, managed to gain access to our dockehub profile and insert a backdoor to one of our public docker images in order to distribute his malware and fullfil his soul purpose, which is to destroy our steampunk robot using his steam malware. When we started tracing him back he deleted his backdoor. Can you help us retrieve his backdoor? Docker Image: `steammaintainer/gearrepairimage`

</aside>

# Given

<aside>
💡

we only have the name of the docker image

</aside>

first we need to pull the image and investigate the history because Docker keeps track of everything in the history

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ docker pull steammaintainer/gearrepairimage

Using default tag: latest
latest: Pulling from steammaintainer/gearrepairimage
7b1a6ab2e44d: Pull complete 
858929a69ddb: Pull complete 
97239c492e4d: Pull complete 
Digest: sha256:10d7e659f8d2bc2abcc4ef52d6d7caf026d0881efcffe016e120a65b26a87e7b
Status: Downloaded newer image for steammaintainer/gearrepairimage:latest
docker.io/steammaintainer/gearrepairimage:latest
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ docker history steammaintainer/gearrepairimage --no-trunc

IMAGE                                                                     CREATED       CREATED BY                                                                                                                 SIZE      COMMENT
sha256:47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d   4 years ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bin/bash"]                                                                       0B        
<missing>                                                                 4 years ago   /bin/sh -c rm -rf /usr/share/lib/                                                                                          0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bin/bash"]                                                                       0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  ENV LD_PRELOAD=                                                                                         0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bin/bash"]                                                                       0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  ENV LD_PRELOAD=/usr/share/lib/librs.so                                                                  0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop) COPY file:0b1afae23b8f468ed1b0570b72d4855f0a24f2a63388c5c077938dbfdeda945c in /usr/share/lib/librs.so    16.4kB    
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bin/bash"]                                                                       0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop)  CMD ["bash"]                                                                                            0B        
<missing>                                                                 4 years ago   /bin/sh -c #(nop) ADD file:5d68d27cc15a80653c93d3a0b262a28112d47a46326ff5fc2dfbf7fa3b9a0ce8 in /                           72.8MB    
```

a few points stand out that can help locate the backdoor:

- One layer added a file at **`/usr/share/lib/librs.so`** of size 16.4kB, and right before that, there's an environment variable **`LD_PRELOAD`** set to **`/usr/share/lib/librs.so`**.
- The attacker likely used an LD_PRELOAD technique to inject malicious code by loading this shared object before other libraries.

let’s try to extract the binary

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ docker run -it --rm --entrypoint /bin/bash steammaintainer/gearrepairimage

root@37ac9d0e945b:/# ls -la /usr/share/lib/librs.so
ls: cannot access '/usr/share/lib/librs.so': No such file or directory
```

this confirms that the file is deleted

so let’s manually extract and explore each image layer to locate the deleted file

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ docker save steammaintainer/gearrepairimage -o gearrepairimage.tar

┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ mkdir image_layers
tar -xf gearrepairimage.tar -C image_layers

┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers]
└─$ tree -r .               
.
├── repositories
├── oci-layout
├── manifest.json
├── index.json
└── blobs
    └── sha256
        ├── ff26ebc5902675b2764f7d6c70f4cf073d2c9ee50ad929648d2769871cafe441
        ├── f0eda15f5a0d6d7464539e6b573bb652a90ff37efc4c5bd15e79b458908176a3
        ├── e06ce4c30a8f3a703d9411b6a98d3774ac3edba4433c639cd1df7c9011c3c048
        ├── 9f54eef412758095c8079ac465d494a2872e02e90bf1fb5f12a1641c0d1bb78b
        ├── 47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d
        ├── 4211bfa3fdb7a405a180f3fa4910bd36b7235857410fe88baf96e3b04a677447
        ├── 1d1e0a0fc435c24e7c70ba5ffb786b1b69bcdda8b6a7c20eeb306544e921a7c1
        └── 0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26

3 directories, 12 files
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers]
└─$ for layer in blobs/sha256/*; do
  tar -tf "$layer" | grep "usr/share/lib/librs.so" && echo "Found in $layer"
done
usr/share/lib/librs.so
Found in blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26
tar: This does not look like a tar archive
tar: Exiting with failure status due to previous errors
tar: This does not look like a tar archive
tar: Skipping to next header
tar: Exiting with failure status due to previous errors
tar: This does not look like a tar archive
tar: Skipping to next header
tar: Exiting with failure status due to previous errors
tar: This does not look like a tar archive
tar: Skipping to next header
tar: Exiting with failure status due to previous errors
tar: This does not look like a tar archive
tar: Exiting with failure status due to previous errors
```

so we got a hit all we need to do is extract the layer that has the binary

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers]
└─$ file blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26

blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26: POSIX tar archive
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers]
└─$ tar -xf blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26 -C extracted_layer

┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers]
└─$ cd extracted_layer 
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/sf_kalisharedfolder/image_layers/extracted_layer]
└─$ cd usr/share/lib  
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/…/extracted_layer/usr/share/lib]
└─$ ll
total 20
-rwxrwx--- 1 root vboxsf 16440 Nov 12  2021 librs.so
                                                                                                                                                                                                                                            
┌──(drli㉿kali)-[/media/…/extracted_layer/usr/share/lib]
└─$ file librs.so                                                                     
librs.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=b6e2da9852ab0b8f7aa409d6c5cf0f3c133b5ed7, not stripped
```

if we open the binary in ghidra

we can find this

![image.png](/assets/img/HackTheBox/Challenges/Peel_Back_The_Layers/image.png)

The C code looks like a classic reverse shell backdoor.

and the hex strings in the code translates to

```bash
HTB{1_r34lly_l1k3_st34mpunk_r0b0ts!!!}
```

DONE!