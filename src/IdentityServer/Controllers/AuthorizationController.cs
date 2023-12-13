using IdentityServer.Domain.Models;
using MediatR;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace IdentityServer.Controllers
{
    public partial class AuthorizationController(IMediator mediator, UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IOptions<IdentityOptions> identityOptions)
        : BaseApiController
    {
        [HttpGet(Endpoints.Authorize)]
        [HttpPost(Endpoints.Authorize)]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest();

            var applicationAuthentication = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            if (applicationAuthentication.Succeeded)
            {
                return HandleAuthorization(request);
            }

            return Challenge(signInManager.ConfigureExternalAuthenticationProperties(
                    IdentityConstants.ApplicationScheme, ""),
                IdentityConstants.ApplicationScheme);
        }

        /// <summary>
        /// exchange credential/ auth token/ refresh token for access token
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        [AllowAnonymous]
        [HttpPost(Endpoints.Token), IgnoreAntiforgeryToken]
        public async Task<IActionResult> GetToken()
        {
            var openIdConnectRequest = HttpContext.GetOpenIddictServerRequest();

            if (openIdConnectRequest is not null)
            {
                if (openIdConnectRequest.IsPasswordGrantType())
                {
                    return await HandleResourceOwnerPasswordFlow(openIdConnectRequest);
                }

                if (openIdConnectRequest.IsRefreshTokenGrantType() ||
                    openIdConnectRequest.IsAuthorizationCodeFlow())
                {
                    return await HandleAuthorizationFlow(openIdConnectRequest);
                }

                if (openIdConnectRequest.IsAuthorizationCodeGrantType())
                {
                    return await HandleAuthorizationCodeGrant(openIdConnectRequest);
                }

                if (openIdConnectRequest.IsClientCredentialsGrantType())
                {
                    return HandleClientCredentialFlow(openIdConnectRequest);
                }
            }

            throw new InvalidOperationException("The specified grant type is not supported.");
        }
    }
}