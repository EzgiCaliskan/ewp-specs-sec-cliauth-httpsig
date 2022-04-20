using EwpApi.Dto;
using EwpApi.Helper;
using EwpApi.Service;
using EwpApi.Service.Exception;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Primitives;
using System.Threading.Tasks;
using Serilog;

namespace EwpApi.Validators
{
    public class RequestValidator
    {

        public RequestValidator()
        {

        }
        public virtual async Task<bool> VerifyHttpSignatureRequest(HttpRequest request)
        {
            HeaderParser parser = new HeaderParser();
            AuthRequest authRequest = parser.ParseHeader(request);
            String body = await BodyReader.ReadRequestBody(request);

            IHeaderDictionary reqHeaders = request.Headers;
            StringValues authorization;
            if (!reqHeaders.TryGetValue("Authorization", out authorization))
                throw new EwpSecWebApplicationException("Authorization header is missing", HttpStatusCode.Unauthorized);
            Log.Information("Authorization header is found");

            if (!authorization.ToString().ToLower().StartsWith("signature"))
                throw new EwpSecWebApplicationException("Signature in Authorization header is missing", HttpStatusCode.Unauthorized);
            Log.Information("signature header is found");

            if (string.IsNullOrEmpty(authRequest.Algorithm))
                throw new EwpSecWebApplicationException("Algorithm field is missing", HttpStatusCode.BadRequest);
            if (!authRequest.Algorithm.ToLower().Contains("rsa-sha256"))
                throw new EwpSecWebApplicationException("Only signature algorithm rsa-sha-256 is supported", HttpStatusCode.Unauthorized);
            Log.Information("Algorithm header test is successful");

            string[] authHeaders = { "(request-target)", "host", "date|original-date", "digest", "x-request-id" };
            if (!CheckRequiredSignedHeaders(authRequest, authHeaders))
                throw new EwpSecWebApplicationException("Missing required signed headers", HttpStatusCode.BadRequest);
            Log.Information("Signed headers test is successful");

            if (string.IsNullOrEmpty(authRequest.Host))
                throw new EwpSecWebApplicationException("Host header is missing", HttpStatusCode.BadRequest);
            if (!authRequest.Host.Equals(request.Host.Host))
                throw new EwpSecWebApplicationException("Host does not match", HttpStatusCode.BadRequest);
            Log.Information("Host header test is successful");

            if (string.IsNullOrEmpty(authRequest.XRequestId))
                throw new EwpSecWebApplicationException("X-Request-Id header is missing", HttpStatusCode.BadRequest);

            Regex rgx = new Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
            if (!rgx.IsMatch(authRequest.XRequestId))
                throw new EwpSecWebApplicationException("Authentication with non-canonical X-Request-ID", HttpStatusCode.BadRequest);
            Log.Information("XRequestId header test is successful");

            if (String.IsNullOrEmpty(authRequest.Date))
                throw new EwpSecWebApplicationException("The date cannot be parsed or the date does not match your server clock within a certain treshold of datetime", HttpStatusCode.BadRequest);
            if (!isDateWithinTimeThreshold(authRequest.Date))
                throw new EwpSecWebApplicationException("The date cannot be parsed or the date does not match your server clock within a certain treshold of datetime", HttpStatusCode.BadRequest);
            Log.Information("Date header test is successful");

            if (!String.IsNullOrEmpty(authRequest.GetHeaderValue("date"))
                && !String.IsNullOrEmpty(authRequest.GetHeaderValue("original-date"))
                && !isOriginalDateWithinTimeThreshold(authRequest.GetHeaderValue("date"), authRequest.GetHeaderValue("original-date")))
                throw new EwpSecWebApplicationException("The date is unsynchronized with original date", HttpStatusCode.BadRequest);

            if (String.IsNullOrEmpty(authRequest.Signature))
                throw new EwpSecWebApplicationException("Signature in Authorization header is missing", HttpStatusCode.BadRequest);
            Log.Information("Signature is found");

            if (String.IsNullOrEmpty(authRequest.KeyId))
                throw new EwpSecWebApplicationException("keyId in Authorization header is missing", HttpStatusCode.BadRequest);
            if (!VerifyDigest(body, authRequest.Digest))
                throw new EwpSecWebApplicationException("Digest does not match", HttpStatusCode.BadRequest);
            Log.Information("Digest matches");

            RegistryService _service = new RegistryService();

            String publicKey = _service.GetCertificateByRSAKey(authRequest.KeyId);
            if (String.IsNullOrEmpty(publicKey))
                throw new EwpSecWebApplicationException("Key not found for fingerprint: " + authRequest.KeyId, HttpStatusCode.Forbidden);
            Log.Information("Public cert of KeyId is found");


            if (_service.CheckIsServerKey(authRequest.KeyId))
                throw new EwpSecWebApplicationException("Request must be sign with client key not server key: " + authRequest.KeyId, HttpStatusCode.Forbidden);
            Log.Information("Request signed with client key");


            if (!VerifySignature(authRequest, publicKey))
                throw new EwpSecWebApplicationException("Signature does not match", HttpStatusCode.Unauthorized);
            Log.Information("Signature is verified successfully");

            return true;
        }

                #region date validation methods
        public Boolean isDateWithinTimeThreshold(String dateString)
        {
            try
            {
                DateTime requestDate = GetDatetimeOfHeader(dateString);
                return ((DateTime.UtcNow - requestDate).Minutes < 5);
            }
            catch (Exception e)
            {
                Log.Error("Error occured when parsing date: " + dateString, e);
            }
            return false;
        }

        public Boolean isOriginalDateWithinTimeThreshold(String dateString, String originalDateString)
        {
            try
            {
                DateTime requestDate = GetDatetimeOfHeader(dateString);
                DateTime requestOriginalDate = GetDatetimeOfHeader(originalDateString);
                return ((requestDate - requestOriginalDate).Minutes < 20);
            }
            catch (Exception e)
            {
                Log.Error("Error occured when parsing date: " + dateString, e);
            }
            return false;
        }

        private DateTime GetDatetimeOfHeader(String headerDateString)
        {
            string acceptableDate = headerDateString.Substring(0, headerDateString.IndexOf(",") + 1);
            headerDateString = headerDateString.Substring(headerDateString.IndexOf(",") + 1);
            if (headerDateString.StartsWith(" "))
                headerDateString = headerDateString.Substring(1);

            if (headerDateString.IndexOf(" ") == 1)
                headerDateString = "0" + headerDateString;
            acceptableDate = acceptableDate + " " + headerDateString;

            DateTime requestDate = (DateTime.ParseExact(acceptableDate, "ddd, dd MMM yyyy HH:mm:ss 'GMT'", CultureInfo.InvariantCulture));
            return requestDate;
        }

        #endregion

        public Boolean CheckRequiredSignedHeaders(AuthRequest authRequest, string[] authHeaders)
        {

            if (String.IsNullOrEmpty(authRequest.Headers))
                throw new EwpSecWebApplicationException("Missing headers filed in Authorization header", HttpStatusCode.BadRequest);

            string[] headers = authRequest.Headers.Split(" ".ToCharArray());
            foreach (string current in authHeaders)
            {
                string[] str = null;
                if (current.Contains("|"))
                {
                    str = Array.FindAll(headers, s => (s.StartsWith(current.Substring(0, current.IndexOf("|"))) || s.StartsWith(current.Substring(current.IndexOf("|") + 1))));
                }
                else
                {
                    str = Array.FindAll(headers, s => s.StartsWith(current));
                }

                if (str == null || str.Count() == 0)
                {
                    throw new EwpSecWebApplicationException("Missing required signed header '" + current + "'", HttpStatusCode.BadRequest);
                }
            }

            return true;
        }

        #region digest validation methods
        public bool VerifyDigest(string body, string requestDigest)
        {
            string acceptedDigest = GetSHA256Digest(requestDigest);

            if (String.IsNullOrEmpty(acceptedDigest))
                return false;

            String digestCalculated = "SHA-256=" + RsaHelper.ComputeSha256Hash(body);
            return acceptedDigest.Equals(digestCalculated);
        }

        private String GetSHA256Digest(string digestHeader)
        {
            string[] fields = digestHeader.Replace(" ", "").Split(",");
            foreach (string innerField in fields)
            {
                if (innerField.ToUpper().StartsWith("SHA-256"))
                {
                    string innerFieldName = innerField.Substring(0, innerField.IndexOf("="));
                    string acceptedInnerField = innerField.Replace(innerFieldName, innerFieldName.ToUpper());
                    return acceptedInnerField;
                }
            }
            return null;
        }

        #endregion

        #region signature validation methods
        public bool VerifySignature(AuthRequest authRequest, String publicKeyString)
        {
            return RsaHelper.VerifySign(GetStringForSign(authRequest), publicKeyString, authRequest.Signature);
        }

        public string GetStringForSign(AuthRequest authRequest)
        {
            string[] headers = authRequest.Headers.Split(" ".ToCharArray());
            string rawString = "";
            foreach (string current in headers)
            {
                if (rawString.Length > 0)
                    rawString += "\n";
                if (current.Contains("date"))
                {
                    rawString += current + ": " + authRequest.Date;
                }
                else
                {
                    rawString += current + ": " + authRequest.GetHeaderValue(current);
                }
            }
            Log.Information("Signing String = '" + rawString + "'");
            return rawString;
        }

        #endregion

    }
}
