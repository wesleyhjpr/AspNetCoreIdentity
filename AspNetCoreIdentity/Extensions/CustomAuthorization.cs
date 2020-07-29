using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace AspNetCoreIdentity.Extensions
{
    public class CustomAuthorization
    {
        public static bool ValidarClaimsUsuario(HttpContext context, string claimName, string claimValue)
        {
            return context.User.Identity.IsAuthenticated &&
                context.User.Claims.Any(c => c.Type == claimName && c.Value.Contains(claimValue));
        }
    }

    public class ClaimsAuthorizeAttribute : TypeFilterAttribute
    {
        public ClaimsAuthorizeAttribute(string claimName, string claimValue) : base(typeof(RequisitoClaimFilter))
        {
            Arguments = new object[] {
                new List<Claim> { 
                    new Claim(claimName, claimValue),
                    new Claim("aaaa", "bbbb") 
                } 
            };
        }

    }
    public class RequisitoClaimFilter : IAuthorizationFilter
    {
        public readonly List<Claim> _claim;

        public RequisitoClaimFilter(List<Claim> claim)
        {
            _claim = claim;
        }

        void IAuthorizationFilter.OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.Identity.IsAuthenticated)
            {
                context.Result = new RedirectToRouteResult(new RouteValueDictionary(new { area = "Identity", page = "/Account/login", ReturnUrl = context.HttpContext.Request.Path.ToString() }));
                return;
            }

            //if (!CustomAuthorization.ValidarClaimsUsuario(context.HttpContext, _claim.Type, _claim.Value))
            //{
            //    context.Result = new StatusCodeResult(403) ;
            //}
        }
    }
}
