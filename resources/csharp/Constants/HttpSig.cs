using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EwpApi.Constants
{
    /// <summary>
    /// HttpSig stores the data in section HttpSig in appsettings.json
    /// </summary>
    public class HttpSig
    {
        public string CatalogFilePath { get; set; }
        public List<Servers> Servers { get; set; }
    }

    public class Servers
    {
        public string HeiId { get; set; }
        public string KeyId { get; set; }
        public List<string> PublicKey { get; set; }
        public List<string> PrivateKey { get; set; }
    }
}
