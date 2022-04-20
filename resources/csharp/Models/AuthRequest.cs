using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EwpApi.Dto
{
    public class AuthRequest
    {
        Dictionary<string, string> _headerFields = new Dictionary<string, string>();


        public List<string> HeiIds { get; set; }
        public string XRequestId
        {
            set
            {
                SetHeaderField("X-Request-Id".ToLower(), value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("X-Request-Id".ToLower());
            }
        }
        public string RequestTarget
        {
            set
            {
                SetHeaderField("(request-target)", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("(request-target)");
            }
        }
        public string Host
        {
            set
            {
                SetHeaderField("host", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("host");
            }
        }
        public string Date
        {
            get
            {
                string val;
                if (_headerFields.TryGetValue("date", out val))
                    return val;
                return _headerFields.GetValueOrDefault("original-date");

            }
        }
        public string ContentType
        {
            set
            {
                SetHeaderField("content-type", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("content-type");
            }
        }
        public string Digest
        {
            set
            {
                SetHeaderField("digest", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("digest");
            }
        }
        public string ContentLength
        {
            set
            {
                SetHeaderField("content-length", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("content-length");
            }
        }
        public string AcceptSignature
        {
            set
            {
                SetHeaderField("accept-signature", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("accept-signature");
            }
        }
        public string KeyId
        {
            set
            {
                SetHeaderField("keyId", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("keyId");
            }
        }
        public string Algorithm
        {
            set
            {
                SetHeaderField("algorithm", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("algorithm");
            }
        }
        public string Headers
        {
            set
            {
                SetHeaderField("headers", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("headers");
            }
        }
        public string Signature
        {
            set
            {
                SetHeaderField("signature", value);
            }
            get
            {
                return _headerFields.GetValueOrDefault("signature");
            }
        }

        private void SetHeaderField(string key, string value)
        {
            if (_headerFields == null)
                _headerFields = new Dictionary<string, string>();
            _headerFields.Add(key, value);
        }
       
        public void LoadHeadersWithValues(Dictionary<string, string> allHeadersWithValues)
        {
            foreach (string headerName in allHeadersWithValues.Keys)
            {
                if (headerName.ToLower().Equals("signature") || headerName.ToLower().Equals("authorization"))
                {
                    string[] fields = allHeadersWithValues.GetValueOrDefault(headerName).Split(",");
                    foreach (string innerField in fields)
                    {
                        string fieldsText = innerField;
                        if (fieldsText.StartsWith("Signature"))
                        {
                            fieldsText = fieldsText.Substring("Signature".Length);
                            fieldsText = (fieldsText.StartsWith(" ")) ? fieldsText.Substring(1) : fieldsText;
                        }
                        if (fieldsText.IndexOf("=") > 0)
                        {
                            string fieldName = fieldsText.Substring(0, fieldsText.IndexOf("="));

                            fieldName = fieldName != "keyId" ? fieldName.ToLower() : fieldName;

                            string fieldsValue = fieldsText.Substring(fieldName.Length);

                            fieldsValue = fieldsValue.Substring(fieldsValue.IndexOf("\"") + 1);

                            fieldsValue = fieldsValue.Substring(0, fieldsValue.LastIndexOf("\""));

                            SetHeaderField(fieldName, fieldsValue);
                        }
                    }
                }
                else
                {
                    string headerValue;
                    if (allHeadersWithValues.TryGetValue(headerName, out headerValue))
                        SetHeaderField(headerName.ToLower(), headerValue);
                }
            }
        }

        public void LoadHeadersWithValues(HttpRequest request)
        {
            Dictionary<string, string> headers = request.Headers.ToDictionary(a => a.Key, a => string.Join(",", a.Value));
            LoadHeadersWithValues(headers);           
        }

        public string GetHeaderValue(string headerName)
        {
            if (headerName.Equals("x-request-id"))
                headerName = "X-Request-Id".ToLower();
            return _headerFields.GetValueOrDefault(headerName);
        }
        public string GetDateHeaderName()
        {
            if (_headerFields.ContainsKey("original-date"))
                return "original-date";
            return "date";
        }
    }


}
