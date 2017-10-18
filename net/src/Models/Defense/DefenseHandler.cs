using System;
using System.Web;

namespace HttpModules
{
    public class LoggingHttpModule : IHttpModule
    {
        #region Members
        
        #endregion

        #region IHttpModule Members

        public void Dispose()
        {
            //if (_writer != null)
            //{
            //    _writer.Dispose();
            //}
        }

        public void Init(HttpApplication context)
        {
            //CreateLogWriter();
            context.BeginRequest += new EventHandler(context_BeginRequest);
            context.EndRequest += new EventHandler(context_EndRequest);
        }

        /*
        private void CreateLogWriter()
        {
            ConfigureEnterpriseLibraryContainer();
            _writer = EnterpriseLibraryContainer.Current.GetInstance<LogWriter>();
        }

        private void ConfigureEnterpriseLibraryContainer()
        {
            var builder = new ConfigurationSourceBuilder();
            builder.ConfigureInstrumentation().EnableLogging();
            builder.ConfigureLogging().WithOptions
                   .LogToCategoryNamed("General")
                     .WithOptions
                     .SetAsDefaultCategory()
                     .SendTo
                     .FlatFile("Log File")
                     .FormatWith(new FormatterBuilder()
                     .TextFormatterNamed("Textformatter"))
                         .ToFile("file.log");

            var configSource = new DictionaryConfigurationSource();
            builder.UpdateConfigurationWithReplace(configSource);
            EnterpriseLibraryContainer.Current =
              EnterpriseLibraryContainer.CreateDefaultContainer(configSource);
        }
        */

        void context_BeginRequest(object sender, EventArgs e)
        {
            //_writer.Write(new LogEntry
            //{
            //    Message = "BeginRequest"
            //});
        }

        void context_EndRequest(object sender, EventArgs e)
        {
            //_writer.Write(new LogEntry
            //{
            //    Message = "EndRequest"
            //});
        }

        #endregion
    }
}