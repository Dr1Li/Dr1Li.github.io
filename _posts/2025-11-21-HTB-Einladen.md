---
title: "HackTheBox - Einladen"
author: DrLi
description: "Writeup of a medium-rated DFIR Sherlock from HackTheBox."
date: 2025-11-21 14:21:00 +0100
categories: [HackTheBox, Sherlocks]
tags: [hackthebox, sherlock, dfir, phishing, malware-analysis, network-capture, bash, csharp, decryption, scheduled-task, registry, anti-debugging]
img_path: /assets/img/HackTheBox/Sherlocks/Einladen
image:
    path: /assets/img/HackTheBox/Sherlocks/Einladen/einladen.png
---

<div align="center"><script src="https://tryhackme.com/badge/2794771"></script></div>

---

Einladen from [HackTheBox](https://www.hackthebox.com/) is a medium-difficulty DFIR Sherlock centered on analysis of a phishing campaign targeting an organization via malicious email attachments. The investigation involves analyzing an HTML downloader, a malicious HTA file that writes a signed Microsoft binary, and a C# malware with AES-256 encrypted configuration variables. The malware communicates with a Zulip chat domain hosted on an AWS EC2 instance, and sets persistence using Windows scheduled tasks with the highest run level. Anti-debugging measures target dnspy. Forensic artifacts include download hashes, scheduled task registry keys (revealed reversed), network domain and DNS records, as well as decrypted configuration details such as C2 ports and hosts. The case highlights multi-layered malware techniques combining social engineering, network covert channels, and code obfuscation.

### Description

<aside>
💡

**Our staff recently received an invite to the German embassy to bid farewell to the Germany Ambassador. We believe this invite was a phishing email due to alerts that fired on our organisation's SIEM tooling following the receipt of such mail. We have provided a wide variety of artifacts inclusive of numerous binaries, a network capture, DLLs from the host system and also a .hta file. Please analyse and complete the questions detailed below! Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. Once the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.**

</aside>

### Questions

**The victim visited a web page. The HTML file of the web page has been provided as ‘downloader.html’ sample file.The web page downloads a ZIP file named 'Invitation_Farewell_DE_EMB.zip'. What is the SHA-256 hash of the ZIP file?**

<aside>
💡

5d4bf026fad40979541efd2419ec0b042c8cf83bc1a61cbcc069efe0069ccd27

</aside>

```bash
we already have the Zip file provided to us so just calculate the hash
```

**The downloaded ZIP file contains a HTA file, which creates multiple files. One of those files is a signed fileby Microsoft Corporation. In HTA file, which variable’s value was the content of that signed file?**

<aside>
💡

msoev

</aside>

```bash
looking at the HTA file we can find this 
```

```bash
   var content2 = '';
    for(var i = 0x0; i < msoev['length']; i++) {
        content2 += String['fromCharCode'](msoev[i]);
    }

    var f = new ActiveXObject('scripting.filesystemobject');
    var msoevpath = f.GetFolder("C:\\windows\\tasks") + '\\msoev.exe';

    var a3 = f['opentextfile'](msoevpath, 0x2, 0x1, 0x0);

    a3['write']('MZ');
    a3['close']();
    var a4 = f['opentextfile'](msoevpath, 0x8, 0x1, -0x1);
    a4['write'](content2);
    a4['close']();
```

```bash
"msoev" is a legit windows binary.
```

**The threat actor was acting as an embassy of a country. Which country was that?**

<aside>
💡

Germany

</aside>

```bash
in the HTML file we have: "<title>Invitation_Farewell_DE_EMB</title>" the DE is contry code and it's germany
```

**The malware communicated with a chatting platform domain. What is the domain name (inclusive of sub domain) the malware connects to?**

<aside>
💡

[toyy.zulipchat.com](http://toyy.zulipchat.com/)

</aside>

```bash
we can find this in the PCAP we have since we know the malware here is "msoev.exe" and we have a corresponding PCAP named after the malware this means that wa can find the traffic the malware resulted in.
inside the pcap we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image.png)

**How many DNS A records were found for that domain?**

<aside>
💡

6

</aside>

```bash
DNS A records map a domain name to its corresponding IPv4 address and from the PCAP we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image1.png)

**It seems like the chatting service was running on a very known cloud service using a FQDN, where the FQDN contains the IP address of the chatting domain in reversive format somehow. What is the FQDN?**

<aside>
💡

[ec2-35-171-197-55.compute-1.amazonaws.com](http://ec2-35-171-197-55.compute-1.amazonaws.com/)

</aside>

```bash
AWS EC2 hostname format. Based on the documentation, AWS EC2 public hostnames follow this format: ec2-X-X-X-X.region.compute.amazonaws.com
and in the next packet we can find the answer
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image2.png)

**What was the parent PID (PPID) of the malware?**

<aside>
💡

4156

</aside>

```bash
we have a PML file which includes Process information and we can find the malware
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image3.png)

**What was the computer name of the victim compute?**

<aside>
💡

DESKTOP-O88AN4O

</aside>

```bash
from the above image the hostname is available in the user field
```

**What was the username of the victim computer?**

<aside>
💡

TWF

</aside>

**How many times were the Windows Registry keys set with a data value?**

<aside>
💡

11

</aside>

```bash
in the PML file we need to filter for the Process name and the Operation "RegSetValue" which shows when the any registru key was given a value.
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image4.png)

**Did the malicious mso.dll load by the malware executable successfully?**

<aside>
💡

Yes

</aside>

```bash
we need to filter for the Operation "Load Image"
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image5.png)

**The JavaScript file tries to write itself as a .bat file. What is the .bat file name (name+extension) it tries to write itself as?**

<aside>
💡

**`richpear.bat`**

</aside>

```bash
this can be found in the obfuscated javascript code and this portion is responsible for the filename generation:
```

```bash
adviserake['faceelite'] +           // r
adviserake['pigutopian'] +          // i
adviserake['countfield'] +          // c
adviserake['gunarrange'] +          // h
adviserake['attemptpassenger'] +    // p
adviserake['laughablepancake'] +    // e
adviserake['campshrill'] +          // a
adviserake['faceelite'] +           // r
'.' +                                // .
adviserake['looselighten'] +        // b
adviserake['campshrill'] +          // a
adviserake['lineshake']             // t
```

**The JavaScript file contains a big text which is encoded as Base64. If you decode that Base64 text and write its content as an EXE file. What will be the SHA256 hash of the EXE?**

<aside>
💡

db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc

</aside>

```bash
we need to extract the base64 payload from the javascript and use this script to create the binary
```

```python
import base64

# Read the base64 encoded data from a file
def decode_base64_to_binary(input_file, output_file):
    """
    Read base64 encoded data from input_file and write the decoded binary to output_file
    
    Args:
        input_file: Path to the file containing base64 encoded data
        output_file: Path where the decoded binary will be saved
    """
    try:
        # Read the base64 encoded data from file
        with open(input_file, 'r', encoding='utf-8') as f:
            base64_data = f.read()
        
        # Remove any whitespace/newlines that might be present
        base64_data = base64_data.strip()
        
        # Decode the base64 data to binary
        binary_data = base64.b64decode(base64_data)
        
        # Write the binary data to output file
        with open(output_file, 'wb') as f:
            f.write(binary_data)
        
        print(f"Successfully decoded {len(base64_data)} bytes of base64 data")
        print(f"Written {len(binary_data)} bytes to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
    except Exception as e:
        print(f"Error during decoding: {e}")

# Usage
if __name__ == "__main__":
    input_filename = "base_exe.txt"  # Your base64 file
    output_filename = "decoded_binary.exe"  # Output binary file (change extension as needed)
    
    decode_base64_to_binary(input_filename, output_filename)
```

```bash
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ bash3 decrypt-pass.py
Successfully decoded 83968 bytes of base64 data
Written 62976 bytes to decoded_binary.exe
                                                                                                                                                                                                                                           
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ file decoded_binary.exe 
decoded_binary.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386 Mono/.Net assembly, 3 sections
                                                                                                                                                                                                                                           
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ sha256sum decoded_binary.exe 
db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc  decoded_binary.exe
```

**The malware contains a class Client.Settings which sets different configurations. It has a variable ‘Ports’ where the value is Base64 encoded. The value is decrypted using Aes256.Decrypt. After decryption, what will be its value (the decrypted value will be inside double quotation)?**

<aside>
💡

666,777,111,5544

</aside>

```bash
we need to reverse the malware so can decrypt the variable they talking about 
first we need to get some knowledge about the malware using DIE we can find this
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image6.png)

```bash
so it's a C# malware 
we can use ILSpy to decompile it 
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image7.png)

```bash
we found the variable they talking about we should find encryption details so we can attempt to decrpyt it
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image8.png)

```bash
we might of found the Key for decryption 
and also we have an AES256 class which has more information about encryption
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image9.png)

```bash
and using the decryption function we can understand how we can decrypt everything
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image10.png)

```bash
using this script we can decrypt the PORTS variable
```

```python
import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad

class Aes256:
    def __init__(self, master_key):
        # Salt used in the C# code
        self.salt = bytes([
            191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
            2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
            210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
            57, 65
        ])
        
        # Encode master_key to bytes if it's a string
        if isinstance(master_key, str):
            master_key = master_key.encode('utf-8')
        
        # In C#, calling GetBytes(32) then GetBytes(64) on the same Rfc2898DeriveBytes
        # is equivalent to calling GetBytes(96) once and splitting the result
        # This is KEY to matching the C# implementation!
        derived = PBKDF2(master_key, self.salt, dkLen=96, count=50000, hmac_hash_module=SHA1)
        
        # Split into encryption key (first 32 bytes) and auth key (next 64 bytes)
        self.key = derived[:32]
        self.auth_key = derived[32:96]
    
    def decrypt(self, encrypted_data):
        """
        Decrypt AES-256-CBC encrypted data with HMAC-SHA256 authentication
        
        The encrypted data structure is:
        [HMAC (32 bytes)][IV (16 bytes)][Ciphertext (variable)]
        """
        # Decode from base64
        data = base64.b64decode(encrypted_data)
        
        # Extract components
        hmac_tag = data[:32]  # First 32 bytes are HMAC-SHA256
        iv = data[32:48]      # Next 16 bytes are IV
        ciphertext = data[48:] # Rest is ciphertext
        
        # Verify HMAC (computed over IV + ciphertext)
        computed_hmac = hmac.new(self.auth_key, iv + ciphertext, hashlib.sha256).digest()
        
        if not self._compare_constant_time(hmac_tag, computed_hmac):
            raise ValueError("Invalid HMAC - data may be corrupted or tampered with")
        
        # Decrypt using AES-256-CBC
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        decrypted = unpad(decrypted_padded, AES.block_size)
        
        return decrypted.decode('utf-8')
    
    def _compare_constant_time(self, a, b):
        """Constant-time comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

# Main decryption code
if __name__ == "__main__":
    # The base64 encoded key from the C# code
    key_b64 = "d0cyOFJwZlBBSXBnalhEVFd2bEdiVHRkQnpybnRBeVM="
    
    # Decode the key from base64 to get the master key string
    master_key = base64.b64decode(key_b64).decode('utf-8')
    
    print(f"Master Key: {master_key}")
    
    # Initialize AES cipher with the master key
    aes_cipher = Aes256(master_key)
    
    # The encrypted Ports value from the C# code
    encrypted_ports = "Yhc6k+R99kweya1xRMDhAdRjrYVuSxpgA2Lefoj5KOsbK3OcJtOpNfDubKUTCiWHoVrnnwqj70kyfYTLboawyVxN0W+L/MRchSITSNbbgXE="
    
    try:
        # Decrypt the Ports value
        decrypted_ports = aes_cipher.decrypt(encrypted_ports)
        print(f"\nDecrypted Ports value: \"{decrypted_ports}\"")
        
    except Exception as e:
        print(f"Error during decryption: {e}")
        import traceback
        traceback.print_exc()
    
    # You can also decrypt other values if needed
    print("\n--- Decrypting other configuration values ---")
    
    encrypted_values = {
        "Hosts": "+Pbo5xZMrhjJHx3HhdYJHkdh+q2pyg1yYZl97b022jvSVzHjr+oe/3vVbtUvDCoDAsW+jMBLbtKBffWq8x27DFTDV3EK9RJnd3SY6OBD8Go=",
        "Version": "ssb/v81WeADBRfbe9M/7eSpC2s49+mveJLfx7kOUI3B4diuHskGJkI1FzeqxWu7qeRnDraPW61pNhdmLsJ+grg==",
        "Install": "sfeC87COnALdrHVVCDxlHJEB1uRr3rJ0QctWWhGh8YUdP4s5OYNe5E+/sAANdDv8qNEYnkUbyIG6lkL9eKRlNw==",
        "Group": "1Rqjrd4tIw4x02NJDtCWYAPP3wCjYTxB2EN1xAHJIIh9VfCf+agEtHh2SmZY3xd0HQm833sW5sY+EihxLts2kw=="
    }
    
    for name, encrypted in encrypted_values.items():
        try:
            decrypted = aes_cipher.decrypt(encrypted)
            print(f"{name}: \"{decrypted}\"")
        except Exception as e:
            print(f"{name}: Error - {e}")

```

```bash
here is what we get:
┌──(drli㉿kali)-[/media/sf_kalisharedfolder]
└─$ bash3 aes_dec.py
Master Key: wG28RpfPAIpgjXDTWvlGbTtdBzrntAyS

Decrypted Ports value: "666,777,111,5544"

--- Decrypting other configuration values ---
Hosts: "127.0.0.1,194.37.80.5"
Version: "Empire 0.1"
Install: "false"
Group: "Default"
```

**The malware sends a HTTP request to a URI and checks the country code or country name of the victim machine. To which URI does the malware sends request for this?**

<aside>
💡

[http://ip-api.com/json/](http://ip-api.com/json/)

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image11.png)

**After getting the country code or country name of the victim machine, the malware checks some country codes and a country name. In case of the country name, if the name is matched with the victim machine’s country name, the malware terminates itself. What is the country name it checks with the victim system?**

<aside>
💡

Russia

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image12.png)

**As an anti-debugging functionality, the malware checks if there is any process running where the process name is a debugger. What is the debugger name it tries to check if that’s running?**

<aside>
💡

dnspy

</aside>

```bash
we can find the answer if we look for the start function
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image13.png)

```bash
we can see that it checks for using "RunAntiAnalysis"
and inside it we can find
```

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image14.png)

**For persistence, the malware writes a Registry key where the registry key is hardcoded in the malware in reversed format. What is the registry key after reversing?**

<aside>
💡

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image15.png)

**The malware sets a scheduled task. What is the Run Level for the scheduled task/job it sets?**

<aside>
💡

highest

</aside>

![image.png](/assets/img/HackTheBox/Sherlocks/Einladen/image16.png)

DONE!