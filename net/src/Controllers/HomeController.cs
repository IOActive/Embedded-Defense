using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Mvc;
using TestDefense.Models;
using TestDefense.Models.Defense;

namespace TestDefense.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            Test();
            return View();
        }

        public ActionResult RunTests()
        {
            Test();
            ViewBag.results = GetLastResults();
            return View("RunTests");
        }

        protected IList<AttackDescription> GetLastResults()
        {
            return (new Defense()).getAttacks();
        }

        protected void Test() {
            var defense = new Defense();
            int result;

            defense.Clear();

            // 1: Pre-execution control: Check valid HTTP Verb
            var original = HttpContext.Request.ServerVariables["REQUEST_METHOD"];
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = "FAKE";
            result = defense.checkHTTPMethod();
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = original;

            // 2: Pre-execution control: Check if the URL contains a vulnerability scanner string
            var originalServer = HttpContext.Request.ServerVariables["REQUEST_URI"];
            HttpContext.Request.ServerVariables["REQUEST_URI"] = "/?nessus";
            result = defense.checkURI();
            HttpContext.Request.ServerVariables["REQUEST_URI"] = originalServer;

            // 3: Pre-execution control: Check if a valid HTTP version is being used
            originalServer = HttpContext.Request.ServerVariables["SERVER_PROTOCOL"];
            HttpContext.Request.ServerVariables["SERVER_PROTOCOL"] = "HTTP/8.0";
            result = defense.checkHTTPVersion();
            HttpContext.Request.ServerVariables["SERVER_PROTOCOL"] = originalServer;

            // 4: Pre-execution control: Check if the user entered the correct domain name
            result = defense.checkHostname("www.example.com");

            // 5: Pre-execution control: Check valid HTTP Verb
            original = HttpContext.Request.ServerVariables["REQUEST_METHOD"];
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = "FAKE";
            result = defense.checkHTTPMethod();
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = original;

            // 6: Pre-execution control: Forced browsing: check if they are trying to access a non-existing resource
            originalServer = HttpContext.Request.ServerVariables["REQUEST_URI"];
            HttpContext.Request.ServerVariables["REQUEST_URI"] = "/nonexistingresource";
            result = defense.checkNonExistingFile();
            HttpContext.Request.ServerVariables["REQUEST_URI"] = originalServer;

            // 7: Pre-execution control: Forced browsing: check if they are trying to access a backup file
            originalServer = HttpContext.Request.ServerVariables["REQUEST_URI"];
            HttpContext.Request.ServerVariables["REQUEST_URI"] = "/existingresource.bak";
            result = defense.checkNonExistingFile();
            HttpContext.Request.ServerVariables["REQUEST_URI"] = originalServer;

            // 8: Pre-execution control: Forced browsing: check if a non-authenticated user is accessing a privileged resource without permission
            if (!(User.Identity.IsAuthenticated && (HttpContext.User != null)))
                defense.attackDetected("Existing resource accessed by a non-authenticated user", 20);

            // 9: Pre-execution control: Forced browsing: check if an authenticated user is accessing a privileged resource without permission
            //if (!(User.Identity.IsAuthenticated && (HttpContext.User != null)))
                defense.attackDetected("Authenticated user without permission", 100);

            // 10: Pre-execution control: Check if the User-Agent is a vulnerability scanner
            original = HttpContext.Request.ServerVariables["HTTP_USER_AGENT"];
            HttpContext.Request.ServerVariables["HTTP_USER_AGENT"] = "Something Nikto";
            result = defense.checkUserAgent();
            HttpContext.Request.ServerVariables["HTTP_USER_AGENT"] = original;

            // 11: Pre-execution control: Check if the User-Agent has changed
            var originalClient = HttpContext.Session["HTTP_USER_AGENT"];
            originalServer = HttpContext.Request.ServerVariables["HTTP_USER_AGENT"];
            HttpContext.Session["user_agent"] = "The original user agent";
            HttpContext.Request.ServerVariables["HTTP_USER_AGENT"] = "A different user agent";
            result = defense.checkUserAgent();
            HttpContext.Session["user_agent"] = originalClient;
            HttpContext.Request.ServerVariables["HTTP_USER_AGENT"] = originalServer;

            // 12: Pre-execution control: Check if the IP address changed for the cookie
            originalClient = HttpContext.Session["REMOTE_ADDR"];
            originalServer = HttpContext.Request.ServerVariables["REMOTE_ADDR"];
            HttpContext.Session["REMOTE_ADDR"] = "1.1.1.1";
            HttpContext.Request.ServerVariables["REMOTE_ADDR"] = "2.2.2.2";
            defense.checkConcurrentSession();
            HttpContext.Session["REMOTE_ADDR"] = originalClient;
            HttpContext.Request.ServerVariables["REMOTE_ADDR"] = originalServer;

            // 13: Pre-execution control: Trap: check if a user is accessing a fake robots.txt entry
            defense.attackDetected("Fake robots.txt entry", 100);

            // 14: Pre-execution control: Trap: check if a user is accessing a fake hidden URL within a document
            defense.attackDetected("Fake hidden URL access", 100);

            // 15: Pre-execution control: Trap: check if a user is modifying a fake cookie
            var existsCookie = HttpContext.Request.Cookies.AllKeys.Contains("admin");
            var cookieValue = "";

            if (existsCookie) {
                cookieValue = HttpContext.Request.Cookies["admin"].Value;
                HttpContext.Request.Cookies["admin"].Value = "true";
            }
            else
                HttpContext.Request.Cookies.Add(new HttpCookie("admin", "true"));

            result = defense.checkFakeCookie("admin", "false");

            if (existsCookie)
                HttpContext.Request.Cookies["admin"].Value = cookieValue;
            else
                HttpContext.Request.Cookies.Remove("admin");

            // 16: Pre-execution control: Trap: check if a user is modifying a fake input field
            original = HttpContext.Request.Form["passkey"];
            var originalSession = HttpContext.Session["passkey"];
            HttpContext.Session["passkey"] = "674441960ca1ba2de08ad4e50c9fde98";
            //HttpContext.Request.Form["passkey"] = "a value different than the one I am testing";
            result = defense.checkFakeInput("passkey", "674441960ca1ba2de08ad4e50c9fde98");
            //HttpContext.Request.Form["passkey"] = original;
            HttpContext.Session["passkey"] = originalSession;

            // 17: Execution control: check if they are using the correct HTTP verb
            original = HttpContext.Request.ServerVariables["REQUEST_METHOD"];
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = "GET";
            result = defense.checkHTTPMethod("POST");
            HttpContext.Request.ServerVariables["REQUEST_METHOD"] = original;

            // 18: Execution control: check if any parameter is missing
            if (HttpContext.Request.Form["this_parameter_should_not_be_missing"] == null)
                defense.attackDetected("Missing parameter", 100);

            // 19: Execution control: check if there are any extra parameters
            if (HttpContext.Request.Form.Count != 3)
                defense.attackDetected("Extra parameters", 20);

            // 20: Execution control: check if they are sending unexpected values on any parameter
            var postValue = HttpContext.Request.Form["id"];
            int postParseResult;
            var parseResult = Int32.TryParse(postValue, out postParseResult);
            if ((postValue == null) || (parseResult == false))
                defense.attackDetected("Unexpected value", 100);

            // 21: Execution control: check when functions may be susceptible to MiTM attacks
            var ConnNfo = new ConnectionInfo("scanme.nmap.org", 22, "username",
               new AuthenticationMethod[] {
                new PrivateKeyAuthenticationMethod("username", new PrivateKeyFile[]{
                    new PrivateKeyFile(@"c:\\temp\\openssh.key", "password")
                }
                )});

            try
            {
                using (var sshclient = new SshClient(ConnNfo))
                {
                    sshclient.Connect();
                    sshclient.Disconnect();
                }
            }
            catch (SshAuthenticationException e)
            {
                defense.attackDetected("Authenticity check failed", 100);
            }

            // 22: Execution control: check if the canonical path differs from the path entered by the user (path traversal attack)
            var file = @"C:\Program files\..\Windows\aaa.txt";
            if (file != System.IO.Path.GetFullPath(file))
                defense.attackDetected("Path traversal detected", 100);

            // 23: Execution control: check if the anti Cross-Site Request Forgery (CSRF) token differs from the original
            // if(!verifyAntiXSRF(anti-xsrf-token))
            defense.attackDetected("Anti-XSRF token invalid", 100);

            // 24: Execution control: check if the origin is forbidden for the user's session
            // if(isGeoLocationForbidden($session))
            defense.attackDetected("Geo location is forbidden", 100);

            // 25: 
            var time = DateTime.UtcNow;
            if (time.Hour > 20 || time.Hour < 8)
                defense.alertAdmin("The user logged in outside business hours");

            // 26: Execution control: check if the user triggered an unexpected catch statement
            var a = 0;
            try
            {
                a = a / a;
            }
            catch (Exception)
            {
                defense.attackDetected("Exception divided by zero should never happen", 20);
            }

            // 27: Execution control: check if there are any uncaught exceptions
            //throw new Exception("this is an uncaught exception");

            // 28: Execution control: check if they are looping through passwords
            defense.attackDetected("Password attempt", 10);

            // 29: Execution control: check how fast they are
            defense.checkSpeed();
            
            // 30.1: Post-execution control: check if the fake secret admin acccount has been leaked 
            HttpContext.Response.Write("0,secrethiddenadminaccount,1...");
            HttpContext.Response.Flush();
            var filter = (OutputFilterStream) HttpContext.Items["Filter"];
            if (filter.ReadStream().Contains("secrethiddenadminaccount"))
                defense.attackDetected("Passwords leaked", 100);

            // 30.2: Post-execution control: check if the fake secret directory has been leaked 
            HttpContext.Response.Write("/var/www/html/secrethiddendirectory");
            HttpContext.Response.Flush();
            if (filter.ReadStream().Contains("secrethiddendirectory"))
                defense.attackDetected("Files leaked", 100);

            // 31: Post-execution control: check if the request took too much time
            time = DateTime.Now;
            Thread.Sleep(2000);
            if (DateTime.Now.Subtract(time).TotalSeconds > 1)
                defense.attackDetected("Too much time", 20);
        }
    }
}