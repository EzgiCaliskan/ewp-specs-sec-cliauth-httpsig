using EwpApi.Dto;
using EwpApi.Service.Builders;
using EwpApi.Service.Exception;
using EwpApi.Validators;
using EwpApi.Validators.Factories;
using Microsoft.AspNetCore.Mvc.Filters;
using Serilog;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace EwpApi.Filters
{

    public class HttpContextFilter : IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {       
            try
            {
                string controllerName = ((Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor)context.ActionDescriptor).ControllerName;
                string actionName = ((Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor)context.ActionDescriptor).ActionName;

                RequestValidator validator = new RequestValidator();
                await validator.VerifyHttpSignatureRequest(context.HttpContext.Request);
                Log.Information("Filter worked successfully. Now [" + controllerName + "." + actionName + "] is executing");

                var result = await next();
            }
            catch (EwpSecWebApplicationException ex)
            {
                Log.Error(ex.getMessage(), ex);
                context.HttpContext.Response.StatusCode = (int)ex.getStatus();
                Dictionary<string, List<string>> errorParameters = new Dictionary<string, List<string>>();
                errorParameters.Add(Constants.ErrorParameters.DeveloperMessage.ToString(), new List<string>() { ex.getMessage() });                
                IResponse errorResponse = new ErrorResponseBuilder().Build(context.HttpContext.Request, context.HttpContext.Response, errorParameters);
                await errorResponse.WriteXmlBody(context.HttpContext.Response);
            }

        }
    }
}
