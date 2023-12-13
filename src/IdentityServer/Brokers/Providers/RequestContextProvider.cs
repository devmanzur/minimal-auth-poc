using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using OpenIddict.Abstractions;

namespace IdentityServer.Brokers.Providers;

public class RequestContextProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RequestContextProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }


    public OpenIdAuthorizedUser GetOpenIdSchemeAuthorizedUser()
    {
        return new OpenIdAuthorizedUser()
        {
            Id = _httpContextAccessor.HttpContext?.User.GetValue(OpenIddictConstants.Claims.Subject) ??
                 throw new InvalidOperationException("User is not signed in"),
            Username = _httpContextAccessor.HttpContext?.User.GetValue(OpenIddictConstants.Claims.Name),
            EmailAddress = _httpContextAccessor.HttpContext?.User.GetValue(OpenIddictConstants.Claims.Email),
            FirstName = _httpContextAccessor.HttpContext?.User.GetValue(OpenIddictConstants.Claims.GivenName),
            LastName = _httpContextAccessor.HttpContext?.User.GetValue(OpenIddictConstants.Claims.FamilyName),
        };
    }
}