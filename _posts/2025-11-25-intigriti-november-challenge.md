---
layout: post
title: "Intigriti's November 2025 Challenge"
date: 2025-11-25
tags: web
description: Write-up for Intigriti's November 2025 Challenge.
image: /assets/img/2025-11-25-intigriti-november-challenge/intigriti-preview.png
---

## PoC

AquaCommerce is an e-commerce website for buying aquarium goods. Users can register themselves on the platform and are assigned the low-privileged user role. 

## JWT none algorithm supported

The web server is misconfigured to accept unsigned JWTs. An attacker can tamper the JWT by changing the "alg" header to "none", make arbitrary claims on the JWT token and it would be gladly accepted by the server. Here, we can tamper our current user's JWT to impersonate as the admin user to escalate privileges.


![](/assets/img/2025-11-25-intigriti-november-challenge/intigriti-jwt.png)

Use the crafted JWT without signature on the website to gain access as admin.

![](/assets/img/2025-11-25-intigriti-november-challenge/intigriti-admin.png)


## Server-side template injection (SSTI)

A SSTI vulnerability exists in the admin's "My Profile Page". The admin can inject SSTI payloads in the "Display Name" field and when the changes are saved, the server renders the unsanitised display name in the "Current Display Name" using a vulnerable Jinja template. This allows us to gain remote code execution (RCE) on the web server and read the flag.

Payload used: 

```{% raw %}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat .aquacommerce/*').read() }}
```{% endraw %}

![](/assets/img/2025-11-25-intigriti-november-challenge/intigriti-flag.png)

Flag: `INTIGRITI{019a82cf-ca32-716f-8291-2d0ef30bea32}`

## Impact

JWT none algorithm supported:
- When a web server is misconfigured to support unsigned JWTs, tokens without valid signatures will be accepted. This allows an attacker to make arbitrary claims in their JWT payload, leading to privilege escalation or impersonation of other users.

Server-side template injection (SSTI):
- SSTI vulnerabilities expose websites to significant risk depending on the template engine used. In most cases, SSTI vulnerabilities can be exploited to achieve cross-site scripting (XSS), and in certain cases even cause remote-code execution (RCE). This can result in an attacker gaining full compromise over the web server.

## Recommendation

- It is recommended to implement server-side validation to ensure that only JWTs with valid signatures are accepted. The use of none algorithm in JWT headers should be restricted.
- It is recommended to use `render_template` with a predefined template instead of rendering untrusted input using `render_template_string`. `render_template` would allow the Flask engine to escape user inputs automatically and prevent malicious inputs from being executed as code.
- To prevent SSTI vulnerabilities, it is suggested to sanitise untrusted inputs for dangerous characters such as `${{<%[%'"}}%\.` before they are rendered in templates. If sanitising the dangerous characters is not feasible due to business requirements, it is recommended to use a sandbox environment for hosting the application.