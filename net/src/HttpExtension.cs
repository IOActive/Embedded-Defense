
namespace System.Web
{
    using System.IO;

    /// <summary>
    /// Extension methods for HTTP Request.
    /// <remarks>
    /// See the HTTP 1.1 specification http://www.w3.org/Protocols/rfc2616/rfc2616.html
    /// for details of implementation decisions.
    /// </remarks>
    /// </summary>
    public static class HttpRequestExtensionsX
    {
        /// <summary>
        /// Dump the raw http request to a string. 
        /// </summary>
        /// <param name="request">The <see cref="HttpRequest"/> that should be dumped.       </param>
        /// <returns>The raw HTTP request.</returns>
        public static string ToRaw(this HttpRequest request, HttpResponse response)
        {
            StringWriter writer = new StringWriter();

            WriteStartLine(request, writer);
            WriteHeaders(request, writer);
            WriteBody(request, response, writer);

            return writer.ToString();
        }

        private static void WriteStartLine(HttpRequest request, StringWriter writer)
        {
            const string SPACE = " ";

            writer.Write(request.HttpMethod);
            writer.Write(SPACE + request.Url);
            writer.WriteLine(SPACE + request.ServerVariables["SERVER_PROTOCOL"]);
        }

        private static void WriteHeaders(HttpRequest request, StringWriter writer)
        {
            foreach (string key in request.Headers.AllKeys)
            {
                writer.WriteLine(string.Format("{0}: {1}", key, request.Headers[key]));
            }

            writer.WriteLine();
        }

        private static void WriteBody(HttpRequest request, HttpResponse response, StringWriter writer)
        {
            StreamReader reader = new StreamReader(request.InputStream);
            //StreamReader reader = new StreamReader(response.Output);

            try
            {
                string body = reader.ReadToEnd();
                writer.WriteLine(body);
            }
            finally
            {
                reader.BaseStream.Position = 0;
            }
        }
    }
}
