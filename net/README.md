## Description
This is a sample C Sharp implementation for IIS of the whitepaper "Embedding Defense in Server-Side Applications". It may be used at your own risk as the barebones for a defense implementation. Along with the functionalities, a testing has also been provided to exemplify the usage. 

It should be noted that the SQLite database connector only serves as an example, since it was not meant to be used concurrently.

### Usage
1) Refer to Microsoft guidelines on how to deploy .NET applications

### Main File/s
Defense.cs

### Testing File/s
HomeController.cs

### Example Output
```
Defense 1.3

- Blacklisted HTTP method
- Vulnerability scanner in URL
- Incorrect HTTP Version
- Incorrect hostname
- Blacklisted HTTP method
- Non existing file
- Non existing backup file
- Existing resource accessed by a non-authenticated user
- Authenticated user without permission
- Vulnerability scanner in user-agent
- User-agent changed during user session
- Fake robots.txt entry
- Fake hidden URL access
- False cookie modified
- Incorrect HTTP method
- Missing parameter
- Extra parameters
- Unexpected value
- Authenticity check failed
- Path traversal detected
- Anti-XSRF token invalid
- Geo location is forbidden
- Exception divided by zero should never happen
- Password attempt
- Passwords leaked
- Files leaked
- Too much time
```
