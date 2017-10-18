using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using TestDefense.Models;

namespace TestDefense
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }

        protected void Application_Error(Object sender, EventArgs e)
        {
            var ex = Server.GetLastError();
            var defense = new TestDefense.Models.Defense.Defense();
            defense.attackDetected("Uncaught exception", 50);
            // TODO Continue normal flow
        }

        internal void Application_BeginRequest(object sender, EventArgs e)
        {
            HttpResponse response = HttpContext.Current.Response;
            OutputFilterStream filter = new OutputFilterStream(response.Filter);
            HttpContext.Current.Items["Filter"] = filter;
            response.Filter = filter;
        }

        internal void Application_EndRequest(object sender, EventArgs e)
        {
            var filter = (OutputFilterStream) HttpContext.Current.Items["Filter"];
            var responseText = filter.ReadStream();
            var result = responseText.Contains("/var/www/html/secrethiddendirectory");
        }
    }
}
