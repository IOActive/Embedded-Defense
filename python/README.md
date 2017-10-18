## Description
This is a sample Python implementation for Django of the whitepaper "Embedding Defense in Server-Side Applications". It may be used at your own risk as the barebones for a defense implementation. Along with the functionalities, a testing has also been provided to exemplify the usage. 

It should be noted that the SQLite database connector only serves as an example, since it was not meant to be used concurrently.

### Usage
1) Execute `python manage.py test`

### Main File/s
middleware.py

### Testing File/s
test.py

### Example Output
```
$ python manage.py test
The last attack from the user was: Vulnerabiliry scanner in URL. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/&

The last attack from the user was: Vulnerabiliry scanner in URL. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/x.bacKup&

The last attack from the user was: Non existing file. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/x.bacKup&

The last attack from the user was: Incorrect HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/&

The last attack from the user was: Vulnerabiliry scanner in URL. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/&

The last attack from the user was: Incorrect HTTP Version. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/&

The last attack from the user was: Vulnerability scanner is user-agent. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/&

The last attack from the user was: Incorrect hostname. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/&

The last attack from the user was: Non existing file. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
URI: /admin/login/
Parameter: next=/admin/acunetix/x.bacKup&

The last attack from the user was: The Ip address of the user changed for the cookie. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.2
URI: /admin/login/
Parameter: next=/admin/&

The last attack from the user was: Fake input modified. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
URI: /
Parameter: input_name=i am value&

Creating test database for alias 'default'...

----------------------------------------------------------------------
Ran 0 tests in 0.000s

OK
Destroying test database for alias 'default'...
```
