using EwpApi.Dto;
using Microsoft.AspNetCore.Http;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EwpApi.Helper
{
    public class HeaderParser
    {
        public AuthRequest ParseHeader(HttpRequest request)
        {
            var headerValues = "";
            foreach (var item in request.Headers)
            {
                headerValues += "\n" + item.Key + ":" + item.Value;
            }

            Log.Information("Request Header= \n" + headerValues);
            AuthRequest authRequest = new AuthRequest();
            authRequest.LoadHeadersWithValues(request);

            authRequest.RequestTarget = request.Method.ToLower() + " /TestEwpEcho" + request.Path + request.QueryString;
            Log.Information("Request Target= " + authRequest.RequestTarget);
            return authRequest;
        }


    }
}
