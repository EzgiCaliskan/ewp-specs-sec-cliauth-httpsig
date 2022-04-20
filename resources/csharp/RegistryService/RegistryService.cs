using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EwpApi.Service
{
    public class RegistryService
    {
        private RegistryClient _client;
        public RegistryService()
        {
            _client = new RegistryClient();
            _client.DownloadCatalog();
        }

        public string GetCertificateByRSAKey(string keyId)
        {      
            string certificate = _client.SearchForSingleResult(@"//r:binaries/r:rsa-public-key[@sha-256=""" + keyId + @"""]");

            if (String.IsNullOrEmpty(certificate))
                return null;
            return certificate;
        }

        public bool CheckIsServerKey(string keyId)
        {
            string serverKey = _client.SearchForServerKey(@"//r:server-credentials-in-use/r:rsa-public-key[@sha-256=""" + keyId + @"""]");
            return !String.IsNullOrEmpty(serverKey);
        }


        public List<string> GetHeiIdsByRSAKey(string keyId)
        {
            //hei-id[text()=\"uni-bremen.de\"]/../../apis-implemented/e2:echo" // /../r:institutions-covered/r:hei-id
            //r:client-credentials-in-use/r:rsa-public-key[@sha-256="X"]/../../r:institutions-covered/r:hei-id
            List<string> heiId = _client.SearchForMultipleResult(@"//r:client-credentials-in-use/r:rsa-public-key[@sha-256=""" + keyId + @"""]/../../r:institutions-covered/r:hei-id");
            if (heiId == null)
                return null;
            return heiId;
        }

        public string GetHeiIdByCertificate(string certificate)
        {
            string heiId = null;

            return heiId;
        }
    }
}
