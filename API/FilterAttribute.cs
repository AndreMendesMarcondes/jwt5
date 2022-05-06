using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace API
{
    public class FilterAttribute : ActionFilterAttribute
    {
        public override Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var authorization = context.HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(authorization) as JwtSecurityToken;

            var ipAddressFromToken = token.Claims.First(claim => claim.Type == "ipAddress").Value;

            if (ipAddressFromToken != context.HttpContext.Connection.RemoteIpAddress.ToString())
            {
                context.Result = new StatusCodeResult(498);
            }

            return base.OnActionExecutionAsync(context, next);
        }
    }
}
