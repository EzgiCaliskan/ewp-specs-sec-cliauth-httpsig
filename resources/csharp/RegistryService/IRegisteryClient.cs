using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace EwpApi.Service
{
    public interface IRegisteryClient
    {

        public bool isCertificateKnown(string clientCert);


        public bool isClientKeyKnown(string rsaKey);


        public bool isHeiCoveredByCertificate(String heiId, string clientCert);


        public bool isHeiCoveredByClientKey(String heiId, string rsaKey);
    


    }
}
