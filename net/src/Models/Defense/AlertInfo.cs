namespace TestDefense.Models.Defense
{
    public class AlertInfo
    {
        public string Ip { get; set; }
        public string User { get; set; }
        public string Cookie { get; set; }
        public string Description { get; set; }
        public string File { get; set;  }
        public string Uri { get; set; }
        public string Parameter { get; set; }

        public AlertInfo(string ip, string user, string cookie, string file, string uri, string parameter, string description) {
            Ip = ip;
            User = user;
            Cookie = cookie;
            File = file;
            Uri = uri;
            Parameter = parameter;
            Description = description;
        }
    }
}