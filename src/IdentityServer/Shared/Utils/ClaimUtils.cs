using System.Security.Claims;
using OpenIddict.Abstractions;

namespace IdentityServer.Shared.Utils
{
    public static class ClaimUtils
    {
        public static string? GetUserId(this ClaimsPrincipal claims)
        {
           return claims.Claims.Where(c => c.Type == OpenIddictConstants.Claims.Subject)
                .Select(c => c.Value).FirstOrDefault();
        }

        public static string? GetUserEmail(this ClaimsPrincipal claims)
        {
            return claims.Claims.Where(c => c.Type == OpenIddictConstants.Claims.Email)
                .Select(c => c.Value).FirstOrDefault();
        }

        public static string? GetValue(this ClaimsPrincipal claims,string claimType)
        {
            return claims.Claims.Where(c => c.Type == claimType)
                .Select(c => c.Value).FirstOrDefault();
        }
    }
}