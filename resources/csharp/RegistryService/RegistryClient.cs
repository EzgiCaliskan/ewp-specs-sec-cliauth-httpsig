using EwpApi.Constants;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.XPath;

namespace EwpApi.Service
{
    /// <summary>
    /// The class manages the catalog file search operations
    /// </summary>
    public class RegistryClient
    {
        public void DownloadCatalog()
        {
            string host = @"https://dev-registry.erasmuswithoutpaper.eu/catalogue-v1.xml"; 
            string strRegistryAPICatalog = "";

            try
            {
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(host);
                Request.Headers.Add(HttpRequestHeader.Accept.ToString(), "application/xml");
                Request.UserAgent = "Registry Client Sample";
                Request.Method = "GET";
                HttpWebResponse resp = (HttpWebResponse)Request.GetResponse();


                Stream stream = resp.GetResponseStream();
                using (StreamReader reader = new StreamReader(stream))
                {
                    string lines = reader.ReadToEnd();
                    if (lines != null)
                    {
                        strRegistryAPICatalog = lines;
                        File.WriteAllText(HttpSigSettings.GetInstance().GetCatalogFilePath(), strRegistryAPICatalog, Encoding.UTF8);
                    }
                    reader.Close();
                }                
                stream.Close();
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex);
                return;
            }
        }

        public string SearchForServerKey(string xPathExpression)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(HttpSigSettings.GetInstance().GetCatalogFilePath());
                var namespaceManager = new XmlNamespaceManager(doc.NameTable);
                namespaceManager.AddNamespace("r", "https://github.com/erasmus-without-paper/ewp-specs-api-registry/tree/stable-v1");
                XmlNode root = doc.DocumentElement;
                XmlNode node = root.SelectSingleNode(xPathExpression, namespaceManager);

                if (node != null)
                {

                    if (node.Attributes != null && node.Attributes.Count > 0)
                    {
                        return node.Attributes[0].InnerText;
                    }

                }

            }
            catch
            {
            }
            return null;
        }

        public string SearchForSingleResult(string xPathExpression)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(HttpSigSettings.GetInstance().GetCatalogFilePath());
                var namespaceManager = new XmlNamespaceManager(doc.NameTable);
                namespaceManager.AddNamespace("r", "https://github.com/erasmus-without-paper/ewp-specs-api-registry/tree/stable-v1");
                XmlNode root = doc.DocumentElement;
                XmlNode node = root.SelectSingleNode(xPathExpression, namespaceManager);

                if (node == null) { }
                else
                {
                    return node.InnerText;
                }
            }
            catch
            {
            }
            return null;
        }

        public List<string> SearchForMultipleResult(string xPathExpression)
        {
            List<string> dataList = null;
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(HttpSigSettings.GetInstance().GetCatalogFilePath());
                var namespaceManager = new XmlNamespaceManager(doc.NameTable);
                namespaceManager.AddNamespace("r", "https://github.com/erasmus-without-paper/ewp-specs-api-registry/tree/stable-v1");
                XmlNode root = doc.DocumentElement;
                XmlNodeList nodeList = root.SelectNodes(xPathExpression, namespaceManager);

                if (nodeList == null) { }
                else
                {
                    dataList = new List<string>();
                    foreach (XmlNode node in nodeList)
                    {
                        dataList.Add(node.InnerText);
                    }
                }
            }
            catch
            {
            }

            return dataList;
        }

        //public X509Certificate GetCertificateKnownInEwpNetwork(X509Certificate certificateInRequest)
        //{
        //    string rawData = SearchForSingleResult(certificateInRequest.GetCertHashString());
        //    if (string.IsNullOrEmpty(rawData))
        //        return null;

        //    X509Certificate certificateInEwp = null;
        //    byte[] bytes = Convert.FromBase64String(rawData);
        //    certificateInEwp = new X509Certificate(bytes);

        //    return certificateInEwp;
        //}
    }
}
