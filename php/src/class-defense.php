<?php
class defense {
    const OK = 1;
    const ERROR = 0;
    const ATTACK = -1;
    const BAN = 100;
    const DEBUG = true;
    const DB = "attackers.db";
    const NEWLINE = "\n";

  // Check that the user is using the correct HTTP method
  function checkHttpMethod($method="") {
    $attack = "Incorrect HTTP method";
    $score = "25";

    if(isset($_SERVER["REQUEST_METHOD"]) && $method == "") {
      $db = $this->getDb();
      $results = $db->query("SELECT method FROM acceptHttpMethod");
      $found = false;
      while ($row = $results->fetchArray()) {
        if(strpos(strtolower($_SERVER["REQUEST_METHOD"]), $row['method'])) {
          $found = true;
          $results->finalize();
          break;
        }
      }
      if($found) {
        return self::OK;
      }
      else {
        $attack = "Blacklisted HTTP method";
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } elseif(isset($_SERVER["REQUEST_METHOD"]) && $method != "") {
      if($_SERVER["REQUEST_METHOD"] != $method) {
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } else
      return self::ERROR;
    return self::OK;
  }

  // Check if the URL contains a string flagged as an attacker
  function checkURI() {
    $attack = "Vulnerability scanner in URL";
    $score = 10;
    
    if(isset($_SERVER["REQUEST_URI"])) {
      $db = $this->getDb();
      $results = $db->query("SELECT string FROM denyUrlString");
      while ($row = $results->fetchArray()) {
        if(strpos(strtolower($_SERVER["REQUEST_URI"]), $row['string']) !== false) {
          $results->finalize();
          $this->attackDetected($attack, $score);
          return self::ATTACK;
        }
      }
    } else
      return self::ERROR;
    return self::OK;
  }

  // Check the current HTTP Version
  function checkHTTPVersion() {
    $attack = "Incorrect HTTP Version";
    $score = 100;

    if(isset($_SERVER['SERVER_PROTOCOL'])) {
      if($_SERVER['SERVER_PROTOCOL'] != "HTTP/1.1") {
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } else
      return self::ERROR;
    return self::OK;      
  }

  // Check if the correct hostname is being used
  function checkHostname($hostname) {
    $attack = "Incorrect hostname";
    $score = 100;

    if(isset($hostname)) {
      if(!isset($_SERVER["HTTP_HOST"]) || $_SERVER["HTTP_HOST"] != $hostname) {
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } else
      return self::ERROR;
    return self::OK;
  }

  // Check what type of non existing file the user tried to access
  function nonExistingFile() {
    $attack = "Non existing file";
    $score = 5;

    if(isset($_SERVER["REQUEST_URI"])) {
      $path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
      $path = explode("/", $path);
      $file = $path[count($path)-1];
      $file = explode(".", $file);      
      $extension = $file[count($file)-1];
      $db = $this->getDb();
      $results = $db->query("SELECT extension FROM denyExtension");
      while ($row = $results->fetchArray()) {
        if($extension == $row['extension']) {
          $attack = "Non existing backup file";
          $score = 100;
          break;
        }
      }
      $this->attackDetected($attack, $score);
      return self::ATTACK;
    } else
      return self::ERROR;
    return self::OK;
  }

  // Check if the User-Agent is flagged as an attacker
  function checkUserAgent() {
    $attack = "Vulnerability scanner in user-agent";
    $score = 100;
    
    if(isset($_SERVER["HTTP_USER_AGENT"])) {
      $db = $this->getDb();
      $results = $db->query("SELECT useragent FROM denyUserAgent");
      while ($row = $results->fetchArray()) {
        if(strpos(strtolower($_SERVER["HTTP_USER_AGENT"]), $row['useragent']) !== false) {
          $results->finalize();
          $this->attackDetected($attack, $score);
          return self::ATTACK;
        }
      }
    } else
      return self::ERROR;
    if(isset($_SESSION["HTTP_USER_AGENT"]) && isset($_SERVER["HTTP_USER_AGENT"])) {
      if($_SESSION["HTTP_USER_AGENT"] != $_SERVER["HTTP_USER_AGENT"]) {
        $attack = "User-agent changed during user session";
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    }
    return self::OK;
  }

  // Check if the IP address for the same cookie has changed
  function checkConcurrentSession() {
    $attack = "The IP address of the user changed for the cookie";
    $score = "25";

    if(isset($_SESSION["REMOTE_ADDR"]) && isset($_SERVER['REMOTE_ADDR'])) {
      if($_SESSION["REMOTE_ADDR"] != $_SERVER['REMOTE_ADDR']) {
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } else
      return self::ERROR;
    return self::OK;
  }

  // Define a cookie to the user, that in case it is changed, it will be flagged as an attacker
  function checkFakeCookie($cookie_name = "admin", $cookie_value = "false") {
    $attack = "False cookie modified";
    $score = "100";

    if(isset($_COOKIE[$cookie_name]) && $_COOKIE[$cookie_name]!=$cookie_value) {
      $this->attackDetected($attack, $score);
      return self::ATTACK;
    } else {
      setcookie($cookie_name, $cookie_value);
      return self::OK; // or error..
    }
  }

  // Define a fake input field in a form and save the fake value in the session. If it is changed, consider it an attack.
  function checkFakeInput($input, $value) {
    $attack = "Fake input modified";
    $score = "100";

    if(isset($input) && isset($value) && isset($_REQUEST[$input])) {
      if($_REQUEST[$input] != $value) {
        $this->attackDetected($attack, $score);
        return self::ATTACK;
      }
    } else
      return self::ERROR;
    return self::OK;
  }

  // Check how many requests per minute the user sends
  function checkSpeed() {
    $attack = "Too many requests";
    $score = 100;

    if(!isset($_SESSION["requests_last_minute"]) || $_SESSION["requests_last_minute"] < (time()-60) ) {
      $_SESSION["requests_last_minute"] = time();
      $_SESSION["amount_requests_last_minute"] = 0;
    }
    $_SESSION["amount_requests_last_minute"] += 1;
    if($_SESSION["amount_requests_last_minute"] > 100) { // Sample max value
      $this->attackDetected("Too many requests per minute", 100);
      return self::ATTACK;
    }
    return self::OK;
  }

  // Catch unhandled exceptions
  function exception_handler($exception) {
    $attack = "Uncaught exception";
    $score = "100";

    $attack = $attack.". Exception message: ".$exception->getMessage();
    $this->attackDetected($attack, $score);
    return self::ATTACK;
  }

  // Logout user and destroy the session
  function logoutSession() {
    // ...
  }
  
  // Check what is the current score for the session (ip, user and/or cookie)
  function isAttacker() {
    $ban_in_seconds = 60 * 60 * 24;

    $db = $this->getDb();
    $session_parameters = $this->getSessionParameters();
    $extra = "";
    if($session_parameters['user'])
      $extra = $extra."or user = :user";
    if($session_parameters['cookie'])
      $extra = $extra."or cookie = :cookie";
    $stmt = $db->prepare('SELECT SUM(score) AS total FROM attacker WHERE timestamp > :timestamp AND (ip = :ip '.$extra.')');
    $stmt->bindValue(':timestamp', time()-$ban_in_seconds);
    $stmt->bindValue(':ip', $session_parameters['ip']);
    if($session_parameters['user'])
      $stmt->bindValue(':user', $session_parameters['user']);
    if($session_parameters['cookie'])
      $stmt->bindValue(':cookie', $session_parameters['cookie']);
    $result = $stmt->execute();

    if($result->fetchArray()['total'] >= self::BAN)
      return true;
    else
      return false;
  }

  // Get the session stuff: IP, user (optional), cookie (optional)
  function getSessionParameters() {
    $user = "";
    if(isset($_SESSION["user"]))
      $user = $_SESSION["user"];
    $ip = "127.0.0.1";
    if(isset($_SERVER["REMOTE_ADDR"]))
      $ip = $_SERVER["REMOTE_ADDR"];
    $cookie = "";
    if(isset($_COOKIE["cookie"]))
      $cookie = $_COOKIE["cookie"];

    return array('user'=>$user, 'ip'=>$ip, 'cookie'=>$cookie);
  }

  // Log the attack into the database
  function logAttack($attack, $score) {
    $db = $this->getDb();
    $session_parameters = $this->getSessionParameters();
    $stmt = $db->prepare('INSERT INTO attacker (timestamp, application, ip, user, cookie, filename, uri, parameter, attack, score) VALUES (:timestamp, :application, :ip, :user, :cookie, :filename, :uri, :parameter, :attack, :score)');
    $stmt->bindValue(':timestamp', time());
    $stmt->bindValue(':application', 'test-defense.php');
    $stmt->bindValue(':ip', $session_parameters['ip']);
    $stmt->bindValue(':user', $session_parameters['user']);
    $stmt->bindValue(':cookie', $session_parameters['cookie']);
    $stmt->bindValue(':filename', $_SERVER["SCRIPT_FILENAME"]);
    $stmt->bindValue(':uri', $_SERVER["REQUEST_URI"]);
    $stmt->bindValue(':parameter', serialize($_REQUEST));
    $stmt->bindValue(':attack', $attack);
    $stmt->bindValue(':score', $score);
    $result = $stmt->execute();
  }

  // Save the attack...
  function attackDetected($attack, $score) {
    $this->logAttack($attack, $score);
    //if($this->isAttacker()) {
      $this->logoutSession();
      $alert_info = "The last attack from the user was: ".$attack;
      if($score >= self::BAN) {
        $alert_info = $alert_info.". The user was automatically mark as an attacker";
      } else {
        $alert_info = $alert_info.". The user was mark as an attacker because of a series of events";
      }
      $session_parameters = $this->getSessionParameters();
      $alert_info = $alert_info.".".self::NEWLINE."Attacker details:".self::NEWLINE;
      $alert_info = $alert_info."IP: ".$session_parameters['ip'].self::NEWLINE;
      $alert_info = $alert_info."User: ".$session_parameters['user'].self::NEWLINE;
      $alert_info = $alert_info."Cookie: ".$session_parameters['cookie'].self::NEWLINE;
      $alert_info = $alert_info."File: ".$_SERVER["SCRIPT_FILENAME"].self::NEWLINE;
      $alert_info = $alert_info."URI: ".$_SERVER["REQUEST_URI"].self::NEWLINE;
      $alert_info = $alert_info."Parameter: ".serialize($_REQUEST).self::NEWLINE;
      $this->alertAdmin($alert_info);
    //}
  }

  // Provide an alert
  function alertAdmin($alert_info) {
    if(self::DEBUG)
      echo $alert_info.self::NEWLINE;
  }

  // Get the database handle, replace this with the DB of your choice
  function getDb() {
    if (!file_exists(self::DB)) {
      $db = new SQLite3(self::DB);
      $results = $db->exec("CREATE TABLE attacker (id INTEGER PRIMARY KEY, timestamp TEXT, application TEXT, ip TEXT, user TEXT, cookie TEXT, filename TEXT, uri TEXT, parameter TEXT, attack TEXT, score INTEGER)");
      $results = $db->exec("CREATE TABLE denyUserAgent (id INTEGER PRIMARY KEY, useragent TEXT)");
      $results = $db->exec("INSERT INTO denyUserAgent (useragent) VALUES ('burpcollaborator'), ('dirbuster'), ('nessus'), ('nikto'), ('nmap'), ('paros'), ('python-urllib'), ('qualysguard'), ('sqlmap'), ('useragent'), ('w3af')");
      $results = $db->exec("CREATE TABLE denyUrlString (id INTEGER PRIMARY KEY, string TEXT)");
      $results = $db->exec("INSERT INTO denyUrlString (string) VALUES ('acunetix'), ('burpcollab'), ('nessus'), ('nikto'), ('parosproxy'), ('qualys'), ('vega'), ('ZAP')");
      $results = $db->exec("CREATE TABLE acceptHttpMethod (id INTEGER PRIMARY KEY, method TEXT)");
      $results = $db->exec("INSERT INTO acceptHttpMethod (method) VALUES ('HEAD'), ('GET'), ('POST'), ('OPTIONS')");
      $results = $db->exec("CREATE TABLE denyExtension (id INTEGER PRIMARY KEY, extension TEXT)");
      $results = $db->exec("INSERT INTO denyExtension (extension) VALUES ('bac'), ('BAC'), ('backup'), ('BACKUP'), ('bak'), ('BAK'), ('conf'), ('cs'), ('csproj'), ('inc'), ('INC'), ('ini'), ('java'), ('log'), ('lst'), ('old'), ('OLD'), ('orig'), ('ORIG'), ('sav'), ('save'), ('temp'), ('tmp'), ('TMP'), ('vb'), ('vbproj')");
    } else
      $db = new SQLite3(self::DB);
    return $db;
  }
} ?>
