using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace EwpApi.Constants
{
    /// <summary>
    /// HttpSigSettings contains the necessary information which stores in 
    /// HttpSig section in appsettings.json
    /// to authenticate by Http Signature Method    
    /// </summary>
    public class HttpSigSettings
    {
        private HttpSig _httpSigInSettingsJson;
        private Dictionary<string, Servers> servers;
                
        private HttpSigSettings(HttpSig httpSig)
        {
            _httpSigInSettingsJson = httpSig;
            servers = new Dictionary<string, Servers>();            
            foreach (Servers server in httpSig.Servers)
            {
                servers.Add(server.HeiId, server);
            }
        }

        private static HttpSigSettings _instance;

        public static HttpSigSettings GetInstance()
        {            
            if(_instance == null)
            {
                var builder = new ConfigurationBuilder()
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddJsonFile("appSettings.json");
                IConfiguration appsettingsConfig = builder.Build();

                
                HttpSig httpSig = new HttpSig();
                var section = appsettingsConfig.GetSection(nameof(HttpSig));
                section.Bind(httpSig);

                _instance = new HttpSigSettings(httpSig);
                
                
            }
            return _instance;
        }

        public string GetCatalogFilePath()
        {
            return _httpSigInSettingsJson.CatalogFilePath;
        }

        public String GetPublicKey(string heiId)
        {
            return String.Join("", servers[heiId].PublicKey); ;
        }

        public String GetPrivateKey(string heiId)
        {
            return String.Join("", servers[heiId].PrivateKey); ;
        }

        public string GetKeyId(string heiId)
        {
            return servers[heiId].KeyId;
        }
        
    }
}
