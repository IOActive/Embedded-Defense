## Description
This is a sample PHP implementation for Apache of the whitepaper "Embedding Defense in Server-Side Applications". It may be used at your own risk as the barebones for a defense implementation. Along with the functionalities, a testing has also been provided to exemplify the usage. 

It should be noted that the SQLite database connector only serves as an example, since it was not meant to be used concurrently.

### Usage
1) Execute `php test-defense.php`

### Main File/s
class-defense.php

### Testing File/s
test-defense.php

### Example Output
```
$ php test-defense.php
The last attack from the user was: Blacklisted HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Vulnerability scanner in URL. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: /?nessus
Parameter: a:0:{}

The last attack from the user was: Incorrect HTTP Version. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Incorrect hostname. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Invalid URI (potential path traversal). The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Non existing file. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: /nonexistingresource
Parameter: a:0:{}


Warning: SQLite3Stmt::execute(): Unable to execute statement: database is locked in /Users/fear/Documents/iaaa/The art of application defense/code/php/class-defense.php on line 281
The last attack from the user was: Non existing backup file. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: /existingresource.bak
Parameter: a:0:{}

The last attack from the user was: Existing resource accessed by a non-authenticated user. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Authenticated user without permission. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Vulnerability scanner in user-agent. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: User-agent changed during user session. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: The IP address of the user changed for the cookie. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 2.2.2.2
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Fake robots.txt entry. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Fake hidden URL access. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: False cookie modified. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Fake input modified. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:1:{s:7:"passkey";s:43:"a value different than the one I am testing";}

The last attack from the user was: Incorrect HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Missing parameter. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Extra parameters. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Unexpected value. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Path traversal detected. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Anti-XSRF token invalid. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Geo location is forbidden. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Exception divided by zero should never happen. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Password attempt. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Passwords leaked. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Files leaked. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}

The last attack from the user was: Too much time. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: 
Cookie: 
File: test-defense.php
URI: 
Parameter: a:0:{}
```
