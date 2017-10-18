using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Web;

namespace TestDefense.Models.Defense
{
    public class AttackDescription {
        public string User;
        public string Ip;
        public string Attack;
    }

    public class SessionParameters {
        public string User;
        public string Ip;
        public string Cookie;
        public string File;
        public string Uri;
        public string Parameter;

        public SessionParameters(string user, string ip, string cookie, string file, string uri, string parameter) {
            User = user;
            Ip = ip;
            Cookie = cookie;
            File = file;
            Uri = uri;
            Parameter = parameter;
        }
    }

    public class Defense
    {
        public int OK = 1;
        public int ERROR = 0;
        public int ATTACK = -1;
        public int BAN = 100;
        public int MAX_REQUESTS_MINUTE = 100;
        public bool DEBUG = true;
        public int banSeconds = 60 * 60 * 24;
        public string DB = "c:\\temp\\attackers12.db";
        protected SQLiteConnection DBConnection { get; set; }
        public Delegate LogoutMethod { get; set; }


        // Constructor
        public Defense() {
            initDb();
        }

        // Data getters
        protected String ServerVariable(String value) {
            return HttpContext.Current.Request.ServerVariables[value];
        }

        protected String RequestVariable(String key) {
            return HttpContext.Current.Request.Form[key];
        }

        protected object SessionVariable(String key) {
            return HttpContext.Current.Session[key];
        }

        protected void SessionVariableSet(String key, object value) {
            HttpContext.Current.Session[key] = value;
        }

        protected String GetCookie(String key) {
            var value = HttpContext.Current.Request.Cookies[key];
            if (value == null) return null;
            return value.Value;
        }

        protected void SetCookie(String key, String value)
        {
            var cookie = HttpContext.Current.Request.Cookies[key];
            if (cookie == null)
                HttpContext.Current.Request.Cookies.Add(new HttpCookie(key, value));
            else
                cookie.Value = value;
        }

        // Helpers
        protected bool IsSet(object value) {
            return (value != null) && ((String) value != "");
        }

        protected bool IncludesString(string source, string value) {
            return source.ToLower().Contains(value.ToLower());
        }

        // DB Helper methods
        protected void initDb()
        {
            if (DBConnection != null)
                return;

            if (!File.Exists(DB))
            {
                SQLiteConnection.CreateFile(DB);
                DBConnection = new SQLiteConnection("data source=" + DB);
                DBConnection.Open();
                executeNonQuery("CREATE TABLE attacker (id INTEGER PRIMARY KEY, timestamp TEXT, application TEXT, ip TEXT, user TEXT, cookie TEXT, filename TEXT, attack TEXT, score INTEGER)");
                executeNonQuery("CREATE TABLE denyUserAgent (id INTEGER PRIMARY KEY, useragent TEXT)");
                executeNonQuery("INSERT INTO denyUserAgent (useragent) VALUES ('burpcollaborator'), ('dirbuster'), ('nessus'), ('nikto'), ('nmap'), ('paros'), ('python-urllib'), ('qualysguard'), ('sqlmap'), ('useragent'), ('w3af')");
                executeNonQuery("CREATE TABLE denyUrlString (id INTEGER PRIMARY KEY, string TEXT)");
                executeNonQuery("INSERT INTO denyUrlString (string) VALUES ('acunetix'), ('burpcollab'), ('nessus'), ('nikto'), ('parosproxy'), ('qualys'), ('vega'), ('ZAP')");
                executeNonQuery("CREATE TABLE acceptHttpMethod (id INTEGER PRIMARY KEY, method TEXT)");
                executeNonQuery("INSERT INTO acceptHttpMethod (method) VALUES ('HEAD'), ('GET'), ('POST'), ('OPTIONS')");
                executeNonQuery("CREATE TABLE denyExtension (id INTEGER PRIMARY KEY, extension TEXT)");
                executeNonQuery("INSERT INTO denyExtension (extension) VALUES ('bac'), ('BAC'), ('backup'), ('BACKUP'), ('bak'), ('BAK'), ('conf'), ('cs'), ('csproj'), ('inc'), ('INC'), ('ini'), ('java'), ('log'), ('lst'), ('old'), ('OLD'), ('orig'), ('ORIG'), ('sav'), ('save'), ('temp'), ('tmp'), ('TMP'), ('vb'), ('vbproj')");
            }
            else {
                DBConnection = new SQLiteConnection("data source=" + DB);
                DBConnection.Open();
            }
        }

        public void Clear() {
            executeNonQuery("delete from attacker");
        }

        public IList<AttackDescription> getAttacks()
        {
            var results = executeQuery("SELECT id, timestamp, application, ip, user, attack FROM attacker");
            var result = new List<AttackDescription>();

            while (results.Read()) {
                var attack = new AttackDescription() {
                    User = (String) results["user"],
                    Ip = (String) results["ip"],
                    Attack = (String) results["attack"]
                };
                result.Add(attack);
            }
            
            return result;
        }

        protected int executeNonQuery(String query)
        {
            using (var command = new SQLiteCommand(DBConnection))
            {
                command.CommandText = query;
                command.CommandType = CommandType.Text;
                //try
                //{
                return command.ExecuteNonQuery();
                //}
                //catch
                //{
                //return 0;
                //}
            }
        }

        protected SQLiteDataReader executeQuery(String query)
        {
            using (var command = new SQLiteCommand(DBConnection))
            {
                command.CommandText = query;
                command.CommandType = CommandType.Text;
                return command.ExecuteReader();
            }
        }

        // Catch unhandled exceptions
        void exception_handler(Exception exception)
        {
            var str = "Uncaught exception found. Exception message: " + exception.Message + "\n";
            Console.WriteLine(str);
            attackDetected("Uncaught exception", 100);
        }

        void logoutSession()
        {
            if (LogoutMethod != null)
                LogoutMethod.DynamicInvoke();
        }

        public bool isSessionBanned()
        {
            var parameters = getSessionParameters();
            var extra = "";
            var total = (long)0;

            if (IsSet(parameters.User)) extra += "OR user = :user";
            if (IsSet(parameters.Cookie)) extra += "OR cookie = :cookie";

            using (var command = new SQLiteCommand(DBConnection))
            {
                command.CommandText = "SELECT ifnull(SUM(score), 0) AS total FROM attacker WHERE timestamp > :timestamp AND (ip = :ip " + extra + ")";
                command.Parameters.Add(new SQLiteParameter(":timestamp", banSeconds));
                command.Parameters.Add(new SQLiteParameter(":ip", parameters.Ip));
                if (IsSet(parameters.User)) command.Parameters.Add(new SQLiteParameter(":user", parameters.User));
                if (IsSet(parameters.Cookie)) command.Parameters.Add(new SQLiteParameter(":cookie", parameters.Cookie));
                var result = command.ExecuteReader();

                using (result)
                {
                    result.Read();
                    total = (long)result["total"];
                }
            }

            return total >= BAN;
        }

        // Helper methods
        protected DateTime GetTime() {
            return DateTime.Now;
        }

        // Get the session stuff: IP, user (optional), cookie (optional)
        public SessionParameters getSessionParameters()
        {
            string parameter = "", uri = "", file = "", cookie = "", ip = "127.0.0.1", user = "";
            if (IsSet(SessionVariable("user"))) user = (String) SessionVariable("user");
            if (IsSet(ServerVariable("REMOTE_ADDR"))) ip = ServerVariable("REMOTE_ADDR");
            if (IsSet(GetCookie("cookie"))) cookie = GetCookie("cookie");
            if (IsSet(ServerVariable("SCRIPT_FILENAME"))) file = ServerVariable("SCRIPT_FILENAME");
            if (IsSet(ServerVariable("REQUEST_URI"))) uri = ServerVariable("REQUEST_URI");
            if (IsSet(ServerVariable("ALL_RAW"))) parameter = ServerVariable("ALL_RAW");
            return new SessionParameters(user, ip, cookie, file, uri, parameter);
        }

        public void alertAdmin(AlertInfo alert) {
            if (DEBUG) Console.WriteLine("%1-%2-%3-%4\n", alert.Cookie, alert.Ip, alert.User, alert.Description);
        }

        public void alertAdmin(string alert)
        {
            if (DEBUG) Console.WriteLine("%1\n", alert);
        }

        protected void logAttack(String attack, int score)
        {
            using (var command = new SQLiteCommand(DBConnection))
            {
                var parameters = getSessionParameters();
                command.CommandText = "INSERT INTO attacker (timestamp, application, ip, user, cookie, filename, attack, score) VALUES (:timestamp, :application, :ip, :user, :cookie, :filename, :attack, :score)";
                command.Parameters.Add(new SQLiteParameter(":timestamp", GetTime()));
                command.Parameters.Add(new SQLiteParameter(":application", "test-defense.php"));
                command.Parameters.Add(new SQLiteParameter(":ip", parameters.Ip));
                command.Parameters.Add(new SQLiteParameter(":user", parameters.User));
                command.Parameters.Add(new SQLiteParameter(":cookie", parameters.Cookie));
                command.Parameters.Add(new SQLiteParameter(":filename", ServerVariable("SCRIPT_FILENAME")));
                command.Parameters.Add(new SQLiteParameter(":uri", ServerVariable("REQUEST_URI")));
                command.Parameters.Add(new SQLiteParameter(":parameter", HttpContext.Current.Request["ALL_RAW"]));
                command.Parameters.Add(new SQLiteParameter(":attack", attack));
                command.Parameters.Add(new SQLiteParameter(":score", score));
                //try
                //{
                command.ExecuteNonQuery();
                //}
                //catch { }
                //}
            }
        }

        public void attackDetected(String message, int score) {
            logAttack(message, score);
            if (isSessionBanned())
            {
                var description = "The last attack from the user was: " + message + ". ";
                if (score >= BAN)
				    description += "The user was automatically mark as an attacker";
			    else
				    description += "The user was mark as an attacker because of a series of events";

                var parameters = getSessionParameters();
                alertAdmin(new AlertInfo(parameters.Ip, parameters.User, parameters.Cookie, parameters.File, parameters.Uri, parameters.Parameter, description));
            }
        }

        // Checks
        public int checkUserAgent()
        {
            var attack = "Vulnerability scanner in user-agent";
            var score = 100;

            if (IsSet(ServerVariable("HTTP_USER_AGENT")))
                using (var results = executeQuery("SELECT useragent FROM denyUserAgent")) { 
                    while (results.Read())
                        if (IncludesString(ServerVariable("HTTP_USER_AGENT"), (String) results["useragent"]))
                        {
                            attackDetected(attack, score);
                            return ATTACK;
                        }
                }
            else
                return ERROR;

            if (IsSet(SessionVariable("user_agent")) && IsSet(ServerVariable("HTTP_USER_AGENT")))
                if ((String) SessionVariable("user_agent") != ServerVariable("HTTP_USER_AGENT")) {
                    attack = "User-agent changed during user session";
                    attackDetected(attack, score);
                    return ATTACK;
                }

            return OK;
        }

        public int checkConcurrentSession()
        {
            var attack = "The IP address of the user changed for the cookie";
            var score = 25;

            if (IsSet(SessionVariable("REMOTE_ADDR")) && IsSet(ServerVariable("REMOTE_ADDR")))
            {
                if (String.Equals(SessionVariable("REMOTE_ADDR"), ServerVariable("REMOTE_ADDR"))) {
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else
                return ERROR;
            return OK;
        }

        public int checkURI()
        {
            var attack = "Vulnerability scanner in URL";
            var score = 10;

            if (IsSet(ServerVariable("REQUEST_URI")))
                using (var results = executeQuery("SELECT string FROM denyUrlString"))
                {
                    while (results.Read())
                        if (IncludesString(ServerVariable("REQUEST_URI"), (String)results["string"]))
                        {
                            attackDetected(attack, score);
                            return ATTACK;
                        }
                }
            else
                return ERROR;
            return OK;
        }

        public int checkHTTPVersion()
        {
            var attack = "Incorrect HTTP Version";
            var score = 100;
            var result = ServerVariable("SERVER_PROTOCOL");

            if (result != "") {
                if (result != "HTTP/1.1") {
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else
                return ERROR;
            return OK;
        }

        public int checkHostname(String hostname)
        {
            var attack = "Incorrect hostname";
            var score = 100;

            if (IsSet(hostname))
            {
                if (!IsSet(ServerVariable("HTTP_HOST")) || (ServerVariable("HTTP_HOST") != hostname))
                {
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else
                return ERROR;
            return OK;
        }

        public int checkNonExistingFile()
        {
            var attack = "Non existing file";
            var score = 5;
            var value = ServerVariable("REQUEST_URI");

            if (IsSet(value))
            {
                var path = System.Web.Hosting.HostingEnvironment.MapPath(value);
                var file = Path.GetFileName(path);
                var fileParts = file.Split('.');

                var extension = "";
                if (fileParts.Length > 1) 
                    extension = fileParts.Last<string>();

			    var results = executeQuery("SELECT extension FROM denyExtension");
                while (results.Read()) {
                    if (String.Equals(extension, (String) results["extension"])) {
                        attack = "Non existing backup file";
                        score = 100;
                        break;
                    }
                }

                attackDetected(attack, score);
                return ATTACK;
            }
            else
                return ERROR;
        }

        public int checkSpeed()
        {
            var time = GetTime();
            long value;

            if (!(SessionVariable("requests_last_minute") != null) || 
                ((long) SessionVariable("requests_last_minute") < (time.AddSeconds(-60).ToFileTimeUtc()))) {
                SessionVariableSet("requests_last_minute", time.ToFileTimeUtc());
                SessionVariableSet("amount_requests_last_minute", (long) 0);
            }

            // Increment request counter
            value = (long) SessionVariable("amount_requests_last_minute") + 1;
            SessionVariableSet("amount_requests_last_minute", value);
            // Maximum value reached
            if (value > MAX_REQUESTS_MINUTE) {
                attackDetected("Too many requests per minute", 100);
                return ATTACK;
            }

            return OK;
        }

        public int checkFakeCookie(string cookie_name = "admin", string cookie_value = "false")
        {
            var attack = "False cookie modified";
            var score = 100;

            if (IsSet(GetCookie(cookie_name)) && (GetCookie(cookie_name) != cookie_value)) {
                attackDetected(attack, score);
                return ATTACK;
            } 
		    else {
                SetCookie(cookie_name, cookie_value);
                return OK; // or error..
            }
        }

        public int checkFakeInput(String input, String value)
        {
		    var attack = "Fake input modified";
		    var score = 100;

            if (IsSet(input) && IsSet(value) && IsSet(RequestVariable(input)) && IsSet(SessionVariable(input)))
            {
                if (RequestVariable(input) != (String) SessionVariable(input)) {
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else
                return ERROR;
            return OK;
        }

        public int checkHTTPMethod(String method = "")
        {
		    var attack = "Incorrect HTTP method";
		    var score = 25;
            var value = ServerVariable("REQUEST_METHOD");

            if (IsSet(value) && method == "") {
		        var results = executeQuery("SELECT method FROM acceptHttpMethod");
		        var found = false;

                using (results)
                    while (results.Read())
                        if (String.Equals(value.ToLower(), ((String) results["method"]).ToLower())) { 
			                found = true;
                            break;
                        }

                if (found)
                    return OK;
		        else {
                    attack = "Blacklisted HTTP method";
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else if (IsSet(value) && (method != "")) {
                if (value != method) {
                    attackDetected(attack, score);
                    return ATTACK;
                }
            }
            else
		        return ERROR;
            return OK;
        }
    }
}
