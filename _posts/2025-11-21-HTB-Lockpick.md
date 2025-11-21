---
title: "HackTheBox - Lockpick"
author: DrLi
description: "Writeup of an easy-rated malware analysis Sherlock from HackTheBox."
date: 2025-11-21 13:59:00 +0100
categories: [HackTheBox, Sherlocks]
tags: [hackthebox, sherlock, ransomware, malware-analysis, reverse engineering, ghidra, c, decryption, xor ciphertext, file recovery]
img_path: /assets/img/HackTheBox/Sherlocks/Lockpick
image:
    path: /assets/img/HackTheBox/Sherlocks/Lockpick/lockpick.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

Lockpick from [HackTheBox](https://www.hackthebox.com/) is an easy-difficulty malware analysis Sherlock focused on reversing a ransomware targeting UNIX servers. Through static analysis using Detect It Easy and Ghidra, we identify the malware as a C program employing XOR encryption with a repeating key to encrypt files with the ".24bes" extension. By extracting the hardcoded encryption key and reversing the encryption algorithm, we successfully decrypt multiple files including applicant databases and asset inventories. The investigation also reveals attacker emails, insider trading evidence, and other forensic details, supporting full recovery and attribution efforts.

### Description

<aside>
💡

**Forela needs your help! A whole portion of our UNIX servers have been hit with what we think is ransomware. We are refusing to pay the attackers and need you to find a way to recover the files provided. **Warning** This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. Once the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.**

</aside>

### Question

**Please confirm the encryption key string utilised for the encryption of the files provided?**

<aside>
💡

bhUlIshutrea98liOp

</aside>

```bash
we have some encrypted files with the extension .24bes and we have the ransomware when we open it with DIE we can see the programming language and other stuff
```

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image.png)

```bash
and since this is written in C we can open it with Ghidra and in the main function we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image1.png)

```bash
if we check the function "process_directory" we cna understand that the second parametre is used in the encryption and it's actually the Key
```

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image2.png)

```bash
as we can see here the first parameter is the directory to encrypt and the sencond is the key
```

**We have recently recieved an email from [wbevansn1@cocolog-nifty.com](mailto:wbevansn1@cocolog-nifty.com) demanding to know the first and last name we have him registered as. They believe they made a mistake in the application process. Please confirm the first and last name of this applicant.**

<aside>
💡

Walden Bevans

</aside>

```bash
to get the answer we need to decrypt the files we have 
so we need to reverse the encryption and since we found the KEY we only need to understand what type of encryption is used and how
and from the function called "encrypt_file" we can see this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image3.png)

```bash
so basically it's just XOR with the key we found and the encrpyted files are created with a new extension "24bes"
```

```bash
to reverse the encryption we can use this script:
```

```python
#!/usr/bin/env python3
import os
import sys

def decrypt_file(encrypted_file, key):
    """
    Decrypt a file encrypted with XOR cipher using repeating key
    """
    try:
        # Read the encrypted file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt using XOR with repeating key
        decrypted_data = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(encrypted_data):
            # XOR each byte with corresponding key byte (repeating)
            decrypted_byte = byte ^ ord(key[i % key_len])
            decrypted_data.append(decrypted_byte)
        
        # Generate output filename by removing .24bes extension
        if encrypted_file.endswith('.24bes'):
            output_file = encrypted_file[:-6]  # Remove '.24bes'
        else:
            output_file = encrypted_file + '.decrypted'
        
        # Write decrypted data
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"[+] Successfully decrypted: {encrypted_file} -> {output_file}")
        return True
        
    except FileNotFoundError:
        print(f"[-] Error: File not found: {encrypted_file}")
        return False
    except Exception as e:
        print(f"[-] Error decrypting {encrypted_file}: {str(e)}")
        return False

def decrypt_directory(directory, key):
    """
    Decrypt all .24bes files in a directory
    """
    count = 0
    for filename in os.listdir(directory):
        if filename.endswith('.24bes'):
            filepath = os.path.join(directory, filename)
            if decrypt_file(filepath, key):
                count += 1
    
    print(f"\n[+] Total files decrypted: {count}")

if __name__ == "__main__":
    # Decryption key
    KEY = "bhUlIshutrea98liOp"
    
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <encrypted_file.24bes>         # Decrypt single file")
        print(f"  {sys.argv[0]} <directory>                    # Decrypt all .24bes files in directory")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if os.path.isfile(target):
        decrypt_file(target, KEY)
    elif os.path.isdir(target):
        decrypt_directory(target, KEY)
    else:
        print(f"[-] Error: {target} is not a valid file or directory")
        sys.exit(1) 
```

```bash
the file that has the information we are looking for is "forela_uk_applicants.sql.24bes"
so after decryption we can find this:
```

```bash
(830,'Walden','Bevans','wbevansn1@cocolog-nifty.com','Male','Aerospace Manufacturing','2023-02-16'),
```

**What is the MAC address and serial number of the laptop assigned to Hart Manifould?**

<aside>
💡

E8-16-DF-E7-52-48, 1316262

</aside>

```bash
to find this we need to decrypt "it_assets.xml.24bes"
inside we can find this:
```

```xml
<MAC>E8-16-DF-E7-52-48</MAC><asset_type>laptop</asset_type><serial_number>1316262</serial_number><purchase_date>8/3/2022</purchase_date><last_patch_date>1/6/2023</last_patch_date><patch_status>pending</patch_status><assigned_to>Hart Manifould</assigned_to>
```

**What is the email address of the attacker?**

<aside>
💡

[bes24@protonmail.com](mailto:bes24@protonmail.com)

</aside>

```bash
with each encrypted file we have this note with it 
```

```bash
This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com  to discuss payment for us providing you the decryption software.
```

**City of London Police have suspiciouns of some insider trading taking part within our trading organisation. Please confirm the email address of the person with the highest profit percentage in a single trade alongside the profit percentage.**

<aside>
💡

[fmosedale17a@bizjournals.com](mailto:fmosedale17a@bizjournals.com), 142303.1996053929628411706675436

</aside>

```bash
for this we need to decrypt the file "trading-firebase_bkup.json.24bes"
using this script to get the highest profit percentage:
```

```python
#!/usr/bin/env python3
import json
import sys

# Load JSON file
with open(sys.argv[1], 'r') as f:
    data = json.load(f)

# Find maximum profit percentage
max_trader = max(data.values(), key=lambda x: float(x['profit_percentage']))

# Print results
print(f"Email: {max_trader['email']}")
print(f"Profit Percentage: {max_trader['profit_percentage']}%")
print(f"Name: {max_trader['first_name']} {max_trader['last_name']}")
print(f"Stock: {max_trader['stock_name']} ({max_trader['stock_symbol']})")
```

```bash
here is the output:
└─$ python3 get_trading.py trading-firebase_bkup.json
Email: fmosedale17a@bizjournals.com
Profit Percentage: 142303.19960539296%
Name: Farah Mosedale
Stock: Pennsylvania Real Estate Investment Trust (PEI^A)
```

**Our E-Discovery team would like to confirm the IP address detailed in the Sales Forecast log for a user who is suspected of sharing their account with a colleague. Please confirm the IP address for Karylin O'Hederscoll.**

<aside>
💡

8.254.104.208

</aside>

```bash
we need to decrpyt "sales_forecast.xlsx.24bes"
inside we have:
```

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image4.png)

**Which of the following file extensions is not targeted by the malware? `.txt, .sql,.ppt, .pdf, .docx, .xlsx, .csv, .json, .xml`**

<aside>
💡

**.ppt**

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Lockpick/image5.png)

```bash
these are the only files the ransomware encrypts 
```

**We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the applicants DB.**

<aside>
💡

f3894af4f1ffa42b3a379dddba384405

</aside>

**We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the trading backup.**

<aside>
💡

87baa3a12068c471c3320b7f41235669

</aside>

**We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the complaints file.**

<aside>
💡

c3f05980d9bd945446f8a21bafdbf4e7

</aside>

```bash
we already have the decrypted files just calculate the  MD5 hashes
```

DONE!