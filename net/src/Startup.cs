using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(TestDefense.Startup))]
namespace TestDefense
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
