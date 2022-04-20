using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace EwpApi.Service.Exception
{
    public  enum AuthMethod
    {
        TLSCERT, HTTPSIG
    }


    public class EwpSecWebApplicationException : System.Exception
    {

        private AuthMethod authMethod;
        private String _message;
        private HttpStatusCode _status;
        public EwpSecWebApplicationException(String message, HttpStatusCode status)
        {           
            this.authMethod = AuthMethod.HTTPSIG;
            _status = status;
            _message = message;
        }

        public EwpSecWebApplicationException(String message, HttpStatusCode status, AuthMethod authMethod)
        {
            this.authMethod = authMethod;
            _status = status;
            _message = message;
        }

        public HttpStatusCode getStatus()
        {
            return _status;
        }

        public String getMessage()
        {
            return _message;
        }


    }
}
