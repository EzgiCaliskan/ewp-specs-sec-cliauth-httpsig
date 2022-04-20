using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Web;
using Serilog;
using EwpApi.Service.Exception;

namespace EwpApi.Helper
{
    public static class BodyReader
    {
        /// <summary>
        /// The method returns the request body content          
        /// </summary>
        /// <param name="req"></param>
        /// <returns>string</returns>
        public async static Task<string> ReadRequestBody(HttpRequest req)
        {
            req.EnableBuffering();
            var requestReader = new StreamReader(req.Body);
            var requestContent = await requestReader.ReadToEndAsync(); 
            req.Body.Position = 0;
            return requestContent;
        }

        /// <summary>
        /// The method returns the response body content          
        /// </summary>
        /// <param name="response"></param>
        /// <returns>string</returns>
        public async static Task<string> ReadResponseBody(WebResponse response)
        {
            var requestReader = new StreamReader(response.GetResponseStream());
            var requestContent = await requestReader.ReadToEndAsync();
            //response.GetResponseStream().Seek(0, SeekOrigin.Begin);
            return requestContent;
        }

        /// <summary>
        /// The method parses the POST request body content that contains a list of values of only one parameter 
        /// such as echo or hei_id into a string list
        /// Example body content: echo=a&echo=b&echo=c
        /// </summary>
        /// <param name="req"></param>
        /// <param name="parameterName"></param>
        /// <returns></returns>
        public async static Task<List<string>> ReadParameterValues(HttpRequest req, string parameterName)
        {
            if (req == null) return null;

            string bodyStr = await ReadRequestBody(req);
            bodyStr = HttpUtility.UrlDecode(bodyStr);
        

            string[] paramList = bodyStr.Split("&");

            var isValidParam = (paramList.Count() >0 && paramList.Where(s => s.StartsWith(parameterName + "=")).Count() != 0);

            if (!isValidParam)
            {
                return new List<string>();
            }

            paramList = paramList.Where(s => s.StartsWith(parameterName + "=")).ToArray();

            var valueList = paramList.Select(s => s.Replace(parameterName + "=", "")).ToList();

            return valueList;
        }

        /// <summary>
        /// The method parses the body content that contains a list of values of only one parameter 
        /// such as echo or hei_id into a string list
        /// Example body content: echo=a&echo=b&echo=c
        /// </summary>
        /// <param name="body"></param>
        /// <param name="parameterName"></param>
        /// <returns></returns>
        public async static Task<List<string>> ReadParameterValues(String body, string parameterName)
        {
            return await Task.Run(() => { 
                if (String.IsNullOrEmpty(body)) return null;


                body = HttpUtility.UrlDecode(body);


                string[] paramList = body.Split("&");

                var isValidParam = (paramList.Count() > 0 && paramList.Where(s => s.StartsWith(parameterName + "=")).Count() != 0);

                if (!isValidParam)
                {
                    return new List<string>();
                }

                paramList = paramList.Where(s => s.StartsWith(parameterName + "=")).ToArray();

                var valueList = paramList.Select(s => s.Replace(parameterName + "=", "")).ToList();

                return valueList;
            });
        }

    }
}
