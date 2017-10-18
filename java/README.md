## Description
This is a sample Java implementation for Jetty of the whitepaper "Embedding Defense in Server-Side Applications". It may be used at your own risk as the barebones for a defense implementation. Along with the functionalities, a testing has also been provided to exemplify the usage. This is a maven application, built to be used with jetty.

It should be noted that the SQLite database connector only serves as an example, since it was not meant to be used concurrently.

### Usage
1) Install maven: apt-get install maven
2) Execute the service: `mvn clean compile test jetty:run` (or just `mvn jetty:run` if it was previously compiled)
3) Or execute the tests execute: `mvn clean compile test` (or just `mvn test` if it was previously compiled)

### Main File/s
Defense.java

### Testing File/s
DefenseTest.java
FakeCookieDefenseFilter.java
FakeInputDefenseFilter.java

### Example Output
```
# mvn test
[INFO] Scanning for projects...
[INFO]                                                                         
[INFO] ------------------------------------------------------------------------
[INFO] Building Jetty HelloWorld 0.1-SNAPSHOT
[INFO] ------------------------------------------------------------------------
[INFO] 
[INFO] --- maven-resources-plugin:2.3:resources (default-resources) @ hello-world ---
[WARNING] Using platform encoding (UTF-8 actually) to copy filtered resources, i.e. build is platform dependent!
[INFO] Copying 2 resources
[INFO] 
[INFO] --- maven-compiler-plugin:3.5.1:compile (default-compile) @ hello-world ---
[INFO] Nothing to compile - all classes are up to date
[INFO] 
[INFO] --- maven-resources-plugin:2.3:testResources (default-testResources) @ hello-world ---
[WARNING] Using platform encoding (UTF-8 actually) to copy filtered resources, i.e. build is platform dependent!
[INFO] skip non existing resourceDirectory /srv/defense/src/test/resources
[INFO] 
[INFO] --- maven-compiler-plugin:3.5.1:testCompile (default-testCompile) @ hello-world ---
[INFO] Nothing to compile - all classes are up to date
[INFO] 
[INFO] --- maven-surefire-plugin:2.10:test (default-test) @ hello-world ---
[INFO] Surefire report directory: /srv/defense/target/surefire-reports

-------------------------------------------------------
 T E S T S
-------------------------------------------------------
Running TestSuite
  -=- Case 01...
No database was found and was initialized with default values.
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:21.803, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Fake hidden URL access, score=100}
The last attack from the user was: Fake hidden URL access. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 01 :: No assertions
  -=- Case 02...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:21.965, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Fake robots.txt entry, score=100}
The last attack from the user was: Fake robots.txt entry. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 02 :: No assertions
  -=- Case 03...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:21.978, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={path: [/somedir/.././somefile]}, attack=Path traversal detected, score=100}
The last attack from the user was: Path traversal detected. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {path: [/somedir/.././somefile]}


     -=- Case 03 :: No assertions
  -=- Case 04...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:21.990, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Passwords leaked, score=100}
The last attack from the user was: Passwords leaked. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 04 :: SUCCESS: secret admin account leakage returned ATTACK.
  -=- Case 05...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.016, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Files leaked, score=100}
The last attack from the user was: Files leaked. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 05 :: SUCCESS: secret hidden directory leakage returned ATTACK.
  -=- Case 06...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.023, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Too many requests, score=100}
The last attack from the user was: Too many requests. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 06 :: SUCCESS: Speed check analysis result ATTACK.
  -=- Case 07...
     -=- Case 07 :: SUCCESS: Speed check analysis result OK.
  -=- Case 08...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.053, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=False cookie modified, score=100}
The last attack from the user was: False cookie modified. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 08 :: SUCCESS: Test Cookie was altered and analysis result in ATTACK.
  -=- Case 09...
     -=- Case 09 :: SUCCESS: Test Cookie stoodd the same and analysis result OK.
  -=- Case 10...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.101, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Too much time, score=20}
The last attack from the user was: Too much time. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 10 :: SUCCESS: Execution time check returned ATTACK.
  -=- Case 11...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.113, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Extra parameters, score=20}
The last attack from the user was: Extra parameters. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 11 :: No assertions
  -=- Case 12...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.140, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Geo location is forbidden, score=100}
The last attack from the user was: Geo location is forbidden. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 12 :: No assertions
  -=- Case 13...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.156, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Invalid URI (potential path traversal), score=20}
The last attack from the user was: Invalid URI (potential path traversal). The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 13 :: No assertions
  -=- Case 14...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.170, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Incorrect hostname, score=100}
The last attack from the user was: Incorrect hostname. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 14 :: SUCCESS: hostname was changed and returned ATTACK.
  -=- Case 15...
     -=- Case 15 :: SUCCESS: hostname was unchanged and returned OK.
  -=- Case 16...
     -=- Case 16 :: SUCCESS: hostname was undefined and returned ERROR.
  -=- Case 17...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.190, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Incorrect HTTP method, score=25}
The last attack from the user was: Incorrect HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 17 :: SUCCESS: HttpMethod doesn't match and analysis result ATTACK.
  -=- Case 18...
     -=- Case 18 :: SUCCESS: HTTP protocol version isn't defined and returned ERROR.
  -=- Case 19...
     -=- Case 19 :: SUCCESS: HTTP protocol is right and returned OK.
  -=- Case 20...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.207, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={passkey: [a value different than the one I am testing]}, attack=Fake input modified, score=100}
The last attack from the user was: Fake input modified. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {passkey: [a value different than the one I am testing]}


     -=- Case 20 :: SUCCESS: Test Input was altered and analysis result in ATTACK.
  -=- Case 21...
     -=- Case 21 :: SUCCESS: Test Cookie stoodd the same and analysis result OK.
  -=- Case 22...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.215, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Anti-XSRF token invalid, score=100}
The last attack from the user was: Anti-XSRF token invalid. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 22 :: No assertions
  -=- Case 23...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.221, application=test-defense, ip=1.1.1.1, user=null, cookie=null, uri=, parameter={}, attack=The IP address of the user changed for the cookie, score=25}
The last attack from the user was: The IP address of the user changed for the cookie. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 1.1.1.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 23 :: SUCCESS: IP was changed and returned ATTACK.
  -=- Case 24...
     -=- Case 24 :: SUCCESS: IP was undefined/null and returned ERROR.
  -=- Case 25...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.230, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Missing parameter, score=100}
The last attack from the user was: Missing parameter. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 25 :: No assertions
  -=- Case 26...
     -=- Case 26 :: No assertions
  -=- Case 27...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.249, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={numeric_string: [alphanum3r1c]}, attack=Unexpected value, score=100}
The last attack from the user was: Unexpected value. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {numeric_string: [alphanum3r1c]}


     -=- Case 27 :: No assertions
  -=- Case 28...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.259, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={user: [user],pass: [pass]}, attack=Password attempt, score=10}
The last attack from the user was: Password attempt. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {user: [user],pass: [pass]}


     -=- Case 28 :: No assertions
  -=- Case 29...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.279, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Incorrect HTTP method, score=25}
The last attack from the user was: Incorrect HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 29 :: SUCCESS: HTTP method was not_valid and did not match expected get and result in ATTACK.
  -=- Case 30...
     -=- Case 30 :: SUCCESS: HTTP method was blank and result in ERROR.
  -=- Case 31...
Opened database successfully.
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.311, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Blacklisted HTTP method, score=25}
The last attack from the user was: Blacklisted HTTP method. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 31 :: SUCCESS: HTTP method not_valid does not exist among accepted methods and result in ATTACK.
  -=- Case 32...
Opened database successfully.
     -=- Case 32 :: SUCCESS: HTTP method was a valid one and attack analysis turned out OK.
  -=- Case 33...
     -=- Case 33 :: SUCCESS: HTTP method was a valid and matched expected and attack analysis turned out OK.
  -=- Case 34...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.322, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Existing resource accessed by a non-authenticated user, score=20}
The last attack from the user was: Existing resource accessed by a non-authenticated user. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 34 :: No assertions
  -=- Case 35...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.328, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Authenticated user without permission, score=100}
The last attack from the user was: Authenticated user without permission. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 35 :: No assertions
  -=- Case 36...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.333, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={invert: [0]}, attack=Exception divided by zero should never happen, score=20}
The last attack from the user was: Exception divided by zero should never happen. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {invert: [0]}


     -=- Case 36 :: No assertions
  -=- Case 37...
Opened database successfully.
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.341, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=http://someurl/nikto, parameter={}, attack=Vulnerability scanner in URL, score=10}
The last attack from the user was: Vulnerability scanner in URL. The user was mark as an attacker because of a series of events.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: http://someurl/nikto
Parameter: {}


     -=- Case 37 :: SUCCESS: URL <http://someurl/nikto> contains denied part <nikto> and returned ATTACK.
  -=- Case 38...
     -=- Case 38 :: SUCCESS: URL is blank and result was ERROR.
  -=- Case 39...
Opened database successfully.
     -=- Case 39 :: SUCCESS: URL is not denieable and result was OK.
  -=- Case 40...
Opened database successfully.
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.359, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=User-agent changed during user session, score=100}
The last attack from the user was: User-agent changed during user session. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 40 :: SUCCESS: UserAgent was modified and returned ATTACK.
  -=- Case 41...
Opened database successfully.
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.370, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Vulnerability scanner in user-agent, score=100}
The last attack from the user was: Vulnerability scanner in user-agent. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 41 :: SUCCESS: UserAgent was an attacker and returned ATTACK.
  -=- Case 42...
Opened database successfully.
     -=- Case 42 :: SUCCESS: UserAgent was not an attacker and returned OK.
  -=- Case 43...
     -=- Case 43 :: SUCCESS: UserAgent was undefined/null and returned ERROR.
  -=- Case 44...
Opened database successfully.
Attack log complete whith arguments: {timestamp=2016-03-29 10:50:22.382, application=test-defense, ip=127.0.0.1, user=null, cookie=null, uri=, parameter={}, attack=Incorrect HTTP Version, score=100}
The last attack from the user was: Incorrect HTTP Version. The user was automatically mark as an attacker.
Attacker details:
IP: 127.0.0.1
User: null
Cookie: null
URI: 
Parameter: {}


     -=- Case 44 :: SUCCESS: HTTP protocol version isn't right and returned ATTACK.
Opened database successfully.
|id|timestamp|application|ip|user|cookie|filename|uri|parameter|attack|score|
|1|2016-03-29 10:50:21.803|test-defense|127.0.0.1|null|null||{}|Fake hidden URL access|100|null|
|2|2016-03-29 10:50:21.965|test-defense|127.0.0.1|null|null||{}|Fake robots.txt entry|100|null|
|3|2016-03-29 10:50:21.978|test-defense|127.0.0.1|null|null||{path: [/somedir/.././somefile]}|Path traversal detected|100|null|
|4|2016-03-29 10:50:21.990|test-defense|127.0.0.1|null|null||{}|Passwords leaked|100|null|
|5|2016-03-29 10:50:22.016|test-defense|127.0.0.1|null|null||{}|Files leaked|100|null|
|6|2016-03-29 10:50:22.023|test-defense|127.0.0.1|null|null||{}|Too many requests|100|null|
|7|2016-03-29 10:50:22.053|test-defense|127.0.0.1|null|null||{}|False cookie modified|100|null|
|8|2016-03-29 10:50:22.101|test-defense|127.0.0.1|null|null||{}|Too much time|20|null|
|9|2016-03-29 10:50:22.113|test-defense|127.0.0.1|null|null||{}|Extra parameters|20|null|
|10|2016-03-29 10:50:22.140|test-defense|127.0.0.1|null|null||{}|Geo location is forbidden|100|null|
|11|2016-03-29 10:50:22.156|test-defense|127.0.0.1|null|null||{}|Invalid URI (potential path traversal)|20|null|
|12|2016-03-29 10:50:22.170|test-defense|127.0.0.1|null|null||{}|Incorrect hostname|100|null|
|13|2016-03-29 10:50:22.190|test-defense|127.0.0.1|null|null||{}|Incorrect HTTP method|25|null|
|14|2016-03-29 10:50:22.207|test-defense|127.0.0.1|null|null||{passkey: [a value different than the one I am testing]}|Fake input modified|100|null|
|15|2016-03-29 10:50:22.215|test-defense|127.0.0.1|null|null||{}|Anti-XSRF token invalid|100|null|
|16|2016-03-29 10:50:22.221|test-defense|1.1.1.1|null|null||{}|The IP address of the user changed for the cookie|25|null|
|17|2016-03-29 10:50:22.230|test-defense|127.0.0.1|null|null||{}|Missing parameter|100|null|
|18|2016-03-29 10:50:22.249|test-defense|127.0.0.1|null|null||{numeric_string: [alphanum3r1c]}|Unexpected value|100|null|
|19|2016-03-29 10:50:22.259|test-defense|127.0.0.1|null|null||{user: [user],pass: [pass]}|Password attempt|10|null|
|20|2016-03-29 10:50:22.279|test-defense|127.0.0.1|null|null||{}|Incorrect HTTP method|25|null|
|21|2016-03-29 10:50:22.311|test-defense|127.0.0.1|null|null||{}|Blacklisted HTTP method|25|null|
|22|2016-03-29 10:50:22.322|test-defense|127.0.0.1|null|null||{}|Existing resource accessed by a non-authenticated user|20|null|
|23|2016-03-29 10:50:22.328|test-defense|127.0.0.1|null|null||{}|Authenticated user without permission|100|null|
|24|2016-03-29 10:50:22.333|test-defense|127.0.0.1|null|null||{invert: [0]}|Exception divided by zero should never happen|20|null|
|25|2016-03-29 10:50:22.341|test-defense|127.0.0.1|null|null|http://someurl/nikto|{}|Vulnerability scanner in URL|10|null|
|26|2016-03-29 10:50:22.359|test-defense|127.0.0.1|null|null||{}|User-agent changed during user session|100|null|
|27|2016-03-29 10:50:22.370|test-defense|127.0.0.1|null|null||{}|Vulnerability scanner in user-agent|100|null|
|28|2016-03-29 10:50:22.382|test-defense|127.0.0.1|null|null||{}|Incorrect HTTP Version|100|null|
Tests run: 44, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 2.181 sec

Results :

Tests run: 44, Failures: 0, Errors: 0, Skipped: 0

[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 8.233s
[INFO] Finished at: Tue Mar 29 10:50:22 EDT 2016
[INFO] Final Memory: 8M/20M
[INFO] ------------------------------------------------------------------------
```
