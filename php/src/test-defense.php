<?php
require_once("class-defense.php");
$defense = new defense();
set_exception_handler(array($defense, "exception_handler"));

// 1) Pre-execution control: Check valid HTTP method 
$tmp1 = $_SERVER;
$_SERVER["REQUEST_METHOD"] = "FAKE";
$defense->checkHttpMethod();
$_SERVER = $tmp1;

// 2) Pre-execution control: Check if the URL contains a vulnerability scanner string
$tmp = $_SERVER;
$_SERVER['REQUEST_URI'] = "/?nessus";
$defense->checkURI();
$_SERVER = $tmp;

// 3) Pre-execution control: Check if a valid HTTP protocol version is being used
$tmp = $_SERVER;
$_SERVER['SERVER_PROTOCOL'] = "HTTP/8.0";
$defense->checkHTTPVersion();
$_SERVER = $tmp;

// 4) Pre-execution control: Check if the user entered the correct domain name
$defense->checkHostname("www.example.com");

// 5) Pre-execution control: Forced browsing: invalid URI
$defense->attackDetected("Invalid URI (potential path traversal)", 20);

// 6) Pre-execution control: Forced browsing: check if they are trying to access a non-existing resource
$tmp = $_SERVER;
$_SERVER["REQUEST_URI"] = "/nonexistingresource";
$defense->nonExistingFile();
$_SERVER = $tmp;

// 7) Pre-execution control: Forced browsing: check if they are trying to access a backup file
$tmp = $_SERVER;
$_SERVER["REQUEST_URI"] = "/existingresource.bak";
$defense->nonExistingFile();
$_SERVER = $tmp;

// 8) Pre-execution control: Forced browsing: check if a non-authenticated user is accessing a privileged resource without permission
// if(!user->isLogged())
$defense->attackDetected("Existing resource accessed by a non-authenticated user", 20);

// 9) Pre-execution control: Forced browsing: check if an authenticated user is accessing a privileged resource without permission
// if (user->isLogged() and !user->isAuthorized())
$defense->attackDetected("Authenticated user without permission", 100);

// 10) Pre-execution control: Check if the User-Agent is a vulnerability scanner
$tmp = $_SERVER;
$_SERVER["HTTP_USER_AGENT"] = "Something Nikto";
$defense->checkUserAgent();
$_SERVER = $tmp;

// 11) Pre-execution control: Check if the User-Agent has changed
$tmp1 = $_SESSION;
$tmp2 = $_SERVER;
$_SESSION["HTTP_USER_AGENT"] = "The original user agent"; // value set when the user logged in
$_SERVER["HTTP_USER_AGENT"] = "A different user agent";
$defense->checkUserAgent();
$_SESSION = $tmp1;
$_SERVER = $tmp2;

// 12) Pre-execution control: Check if the IP address changed for the cookie
// if(login(user, pass))
//   $_SESSION["ip"] = $_SERVER['REMOTE_ADDR']
$tmp1 = $_SESSION;
$tmp2 = $_SERVER;
$_SESSION["REMOTE_ADDR"] = "1.1.1.1"; // original ip address
$_SERVER["REMOTE_ADDR"] = "2.2.2.2"; // current ip address
$defense->checkConcurrentSession();
$_SESSION = $tmp1;
$_SERVER = $tmp2;

// 13) Pre-execution control: Trap: check if a user is accessing a fake robots.txt entry
$defense->attackDetected("Fake robots.txt entry", 100);

// 14) Pre-execution control: Trap: check if a user is accessing a fake hidden URL within a document
$defense->attackDetected("Fake hidden URL access", 100);

// 15) Pre-execution control: Trap: check if a user is modifying a fake cookie
$tmp = $_COOKIE;
$_COOKIE["admin"] = "true";
$defense->checkFakeCookie("admin", "false");
$_COOKIE = $tmp;

// 16) Pre-execution control: Trap: check if a user is modifying a fake input field
$tmp1 = $_SESSION;
$tmp2 = $_REQUEST;
$_SESSION["passkey"] = "674441960ca1ba2de08ad4e50c9fde98"; // value set for that specific user session
$_REQUEST["passkey"] = "a value different than the one I am testing"; // parameter value changed by the user
$defense->checkFakeInput("passkey", $_SESSION["passkey"]);
$_SESSION = $tmp1;
$_REQUEST = $tmp2;

// 17) Execution control: check if they are using the correct HTTP verb
$tmp1 = $_SERVER;
$_SERVER["REQUEST_METHOD"] = "GET";
$defense->checkHttpMethod("POST");
$_SERVER = $tmp1;

// 18) Execution control: check if any parameter is missing
if(!isset($_POST["this_parameter_should_not_be_missing"]))
  $defense->attackDetected("Missing parameter", 100);

// 19) Execution control: check if there are any extra parameters
if(count($_POST) != 999)
  $defense->attackDetected("Extra parameters", 20);

// 20) Execution control: check if they are sending unexpected values on any parameter
if(!isset($_POST["id"]) || is_numeric($_POST["id"]))
  $defense->attackDetected("Unexpected value", 100);

// 21) Execution control: check when functions may be susceptible to MiTM attacks
/*
$connection = ssh2_connect("scanme.nmap.org", 22, array("hostkey"=>"ssh-rsa"));
try {
  if(!ssh2_auth_pubkey_file($connection, "username", "/etc/hosts", "/etc/hosts", "secret")) {
    $defense->attackDetected("Authenticity check failed", 100);
  }
} catch (Exception $e) {
  $defense->attackDetected("Authenticity check failed", 100);
} */ 

// 22) Execution control: check if the canonical path differs from the path entered by the user (path traversal attack)
$tmp = "/somedir/.././somefile";
if($tmp != realpath($tmp))
  $defense->attackDetected("Path traversal detected", 100);

// 23) Execution control: check if the anti Cross-Site Request Forgery (CSRF) token differs from the original
// if(!verifyAntiXSRF(anti-xsrf-token))
$defense->attackDetected("Anti-XSRF token invalid", 100);

// 24) Execution control: check if the origin is forbidden for the user's session
// if(isGeoLocationForbidden($session))
$defense->attackDetected("Geo location is forbidden", 100);


// 25) if (login($user, $pass) && )
date_default_timezone_set('UTC');
if (date('H') < 8 || date('H') > 20)
  $defense->alertAdmin("The user logged in outside business hours");

// 26) Execution control: check if the user triggered an unexpected catch statement
function inverse($x) {
  if (!$x)
    throw new Exception("Division by zero.");
  return 1/$x;}

try {
    echo inverse(0) . "\n";
} catch (Exception $e) {
  $defense->attackDetected("Exception divided by zero should never happen", 20);
}

// 27) Execution control: check if there are any uncaught exceptions
//throw new Exception("this is an uncaught exception");

// 28) Execution control: check if they are looping through passwords
// if (!login($user, $pass))
$defense->attackDetected("Password attempt", 10);

// 29) Execution control: check how fast they are
$defense->checkSpeed();

// 30.1) Post-execution control: check if the fake secret admin acccount has been leaked 
$response = "0,secrethiddenadminaccount,1...";
if(strstr($response, "secrethiddenadminaccount"))
  $defense->attackDetected("Passwords leaked", 100);
// 30.2) Post-execution control: check if the fake secret directory  has been leaked 
$response = "/var/www/html/secrethiddendirectory";
if(strstr($response, "secrethiddendirectory"))  // fake file/directory
  $defense->attackDetected ("Files leaked", 100);

// 31) Post-execution control: check if the request took too much time
$start_time = time();
if( ($start_time+0) <= time()) // if it takes more than 0 seconds..
  $defense->attackDetected("Too much time", 20);
?>
