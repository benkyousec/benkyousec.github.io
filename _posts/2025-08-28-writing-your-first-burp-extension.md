---
layout: post
title: "RE:UN10N Sharing Session - Writing Your First Burp Extension"
date: 2025-08-28
tags:
  - coding
description: I shared how you can write your own Burp extension for testing APIs that require request signing.
image: 
---

One of the problems that I faced early on in my pentesting journey is needing to test an API that required request signing.
Turns out, this is a very common requirement for APIs, especially those that deal with financial transactions as it acts as an additional measure against MiTM and replay attacks.

In my case, the API that I was testing required me to set the `Timestamp` (approx. 10 seconds from the time the request was made to the server), `UniqueRefNo` (a unique ID to identify the tester and request for auditing), and `Signature` (HMAC signature of our request signed with API key) headers.
This meant that I couldn't work directly in Burp as our request would get rejected without the correct headers.

I mentioned this in my presentation, but the trivial solution was to calculate the headers manually using a Python script to fulfill the requirement.

> I forgot to include this in my presentation. But if you're just using Postman, you can achieve the similar results using a pre-request script. Example [here](https://www.postman.com/postman/postman-answers/request/mfn4siv/hmac?tab=scripts).

However, this isn't ideal for reasons:
1. It doesn't scale. What if you have 10, 20, 30+ endpoints in scope, and each endpoint had many parameters? It's not practical to calculate manually and you'll run into a wall.
2. You can't use other tools, i.e for fuzzing, brute forcing, sqlmap, etc.

That's where knowing how to write your own Burp extension comes in handy!
For this, we can write an extension that does the heavy lifting for us, and all requests that gets proxied through Burp will work transparently.

All the source code and materials are available on [GitHub](https://github.com/benkyousec/writing-your-first-burp-extension).

## The Presentation

{% include embed/youtube.html id='JzxkIna0gnY' %}

## Some Corrections on My Part

During the live demo, I made a little mistake that resulted in the API rejecting my requests despite having the right signature.
This was due to how I was verifying the request body after the signatures matched.

On line 139 in main.go, I did this by decoding the payload from the `Signature` header, and comparing it against the raw JSON from the request body.
My extension wasn't working as expected because Postman inserted newline characters in the JSON payload after beautifying, this led to a mismatch because the decoded payload was minified.
Just another lesson to always read the specification when implementing an extension for your target API :)

```go
// Verify the body
decodedPayload, err := base64.RawStdEncoding.DecodeString(tokens[1])
if err != nil {
  return false, errors.New("jws: invalid payload in token")
}

fmt.Println("Decoded payload from token: ", string(decodedPayload))
fmt.Println("Payload from request: ", string(data))

if bytes.Equal(decodedPayload, data) {
  return true, nil
}

return false, nil
```

![](/assets/img/2025-08-28-writing-your-first-burp-extension/badreq.png)
_Postman beautified our JSON_

![](/assets/img/2025-08-28-writing-your-first-burp-extension/badreq-newline.png)
_Newline characters gets inserted that breaks the check after the signatures are matched_

![](/assets/img/2025-08-28-writing-your-first-burp-extension/goodreq.png)
_Expected minified payload_

![](/assets/img/2025-08-28-writing-your-first-burp-extension/goodreq2.png)
_Working as expected :D_

Then you can proxy sqlmap requests through Burp to retrieve the flag.

```
python3 sqlmap.py -r ../test.req -p id --proxy=http://127.0.0.1:8080 --batch --dbms=sqlite --dump -T flag
```

Flag: `reunion{i_Do_nOt_uNdErStAnD_JaVa}`
