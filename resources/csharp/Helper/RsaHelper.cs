using EwpApi.Constants;
using EwpApi.Service.Exception;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EwpApi.Helper
{
    public class RsaHelper
    {
        /// <summary>
        /// Signs the context by using SHA256withRSA algorithm
        /// </summary>
        /// <param name="content">data to be signed</param>
        /// <param name="privateKey">RSA key</param>
        /// <returns></returns>
        public string Sign(string content, string privateKey)
        {
            try
            {
                if (!privateKey.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
                    privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" + privateKey + "\n-----END RSA PRIVATE KEY-----";


                RsaPrivateCrtKeyParameters privateKeyParameters = (RsaPrivateCrtKeyParameters)GetAsymmetricKeyParameterFromPem(privateKey, true);

                ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
                signer.Init(true, privateKeyParameters);
                byte[] dataToSign = Encoding.UTF8.GetBytes(content);
                signer.BlockUpdate(dataToSign, 0, dataToSign.Length);
                byte[] signatureCalculated = signer.GenerateSignature();
                string strSignatureCalculated = Convert.ToBase64String(signatureCalculated);

                bool calculatedSignatureVerified = VerifySign(content, HttpSigSettings.GetInstance().GetPublicKey("iyte.edu.tr"), strSignatureCalculated);
                Log.Information("Calculated signature for response is verifing: " + calculatedSignatureVerified);

                return strSignatureCalculated;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error occured by signing: " + ex.Message);
                throw new EwpSecWebApplicationException("Server authorizing error", System.Net.HttpStatusCode.InternalServerError);
            }

        }

        /// <summary>
        /// Verifies the signed data 
        /// 
        /// </summary>
        /// <param name="content">Content</param>
        /// <param name="publicKey">RSA public key</param>
        /// <param name="signData">Signature field</param>
        /// <returns></returns>
        public static bool VerifySign(string content, string publicKey, string signData)
        {
            try
            {
                publicKey = publicKey.TrimStart().TrimEnd().Replace("\n", "").Replace("\r", "").Replace(" ", "");

                var signer = SignerUtilities.GetSigner("SHA256withRSA");
                var publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
                signer.Init(false, publicKeyParam);
                var signBytes = Convert.FromBase64String(signData);
                var plainBytes = Encoding.UTF8.GetBytes(content);
                signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
                var ret = signer.VerifySignature(signBytes);
                return ret;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        private static AsymmetricKeyParameter GetAsymmetricKeyParameterFromPem(string pem, bool isPrivate)
        {
            PemReader pemReader = new PemReader(new StringReader(pem));
            object key = pemReader.ReadObject();

            return isPrivate ? ((AsymmetricCipherKeyPair)key).Private : (AsymmetricKeyParameter)key;
        }

        public static string ComputeSha256Hash(string content)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(content));

                // Convert byte array to a string   
                string hashedData = Convert.ToBase64String(bytes);

                return hashedData;
            }
        }
    }
}
