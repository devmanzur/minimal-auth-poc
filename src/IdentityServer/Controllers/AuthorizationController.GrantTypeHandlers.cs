using System.Security.Claims;
using IdentityServer.Domain.Models;
using IdentityServer.Features.Account;
using IdentityServer.Shared.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace IdentityServer.Controllers
{
    public partial class AuthorizationController
    {
        /// <summary>
        /// Authenticate the user using provided username & password
        /// On successful authentication issue token
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        private async Task<IActionResult> HandleResourceOwnerPasswordFlow(OpenIddictRequest request)
        {
            var authenticate =
                await mediator.Send(new SignInCommand(request.Username, request.Password));
            var ticket = await IssueTicket(request, authenticate.User, authenticate.Principal);

            AssignScope(request, ticket.Principal);

            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        private IActionResult HandleAuthorization(OpenIddictRequest request)
        {
            var claims = User.Claims;

            var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            AssignScope(request, claimsPrincipal);

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// Returns new access token using the refresh token
        /// Here we can add extra checks such as, is the user still allowed to sign in
        /// </summary>
        /// <param name="dto"></param>
        /// <returns></returns>
        private async Task<IActionResult> HandleAuthorizationFlow(OpenIddictRequest request)
        {
            var claimsPrincipal =
                (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
                .Principal;

            AssignScope(request, claimsPrincipal);

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        //Handle authorization code flow
        private async Task<IActionResult> HandleAuthorizationCodeGrant(OpenIddictRequest request)
        {
            var claimsPrincipal =
                (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
                .Principal;
            var user = await userManager.FindByEmailAsync(claimsPrincipal.GetUserEmail());
            if (user is not null)
            {
                var ticket = await IssueTicket(request, user, claimsPrincipal);
                AssignScope(request, ticket.Principal);

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            return Forbid();
        }

        private IActionResult HandleClientCredentialFlow(OpenIddictRequest? request)
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            identity.AddClaim(OpenIddictConstants.Claims.Subject,
                request.ClientId ?? throw new InvalidOperationException());

            var claimsPrincipal = new ClaimsPrincipal(identity);

            AssignScope(request, claimsPrincipal);

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }


        #region token issuer

        private static void AssignScope(OpenIddictRequest dto, ClaimsPrincipal claimsPrincipal)
        {
            foreach (var scope in dto.GetScopes())
            {
                var resources = ApplicationResourceUtils.GetResources(scope);
                if (resources is not null && resources.Any())
                {
                    claimsPrincipal.SetResources(resources!);
                }
            }

            claimsPrincipal.SetScopes(dto.GetScopes());
        }


        private async Task<AuthenticationTicket> IssueTicket(OpenIddictRequest request, ApplicationUser user,
            ClaimsPrincipal principal)
        {
            var roles = await userManager.GetRolesAsync(user);
            var ticket = CreateTicketAsync(request, user, principal, null, roles.ToList());
            return ticket;
        }

        private AuthenticationTicket CreateTicketAsync(
            OpenIddictRequest request, ApplicationUser user, ClaimsPrincipal principal,
            AuthenticationProperties properties = null, List<string> roles = null)
        {
            principal = AddUserDataToPrincipal(principal, roles, user);

            var ticket = new AuthenticationTicket(principal, properties,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (!request.IsRefreshTokenGrantType())
            {
                // Set the list of scopes granted to the client application.
                // Note: the offline_access scope must be granted
                // to allow OpenIddict to return a refresh token.
                ticket.Principal.SetScopes(new[]
                {
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Scopes.Roles
                }.Intersect(request.GetScopes()));
            }

            foreach (var claim in ticket.Principal.Claims)
            {
                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                if (claim.Type == identityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
                {
                    continue;
                }

                var destinations = new List<string>
                {
                    OpenIddictConstants.Destinations.AccessToken
                };

                // Only add the iterated claim to the id_token if the corresponding scope was granted to the client application.
                // The other claims will only be added to the access_token, which is encrypted when using the default format.
                if (claim.Type == OpenIddictConstants.Claims.Name &&
                    ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile) ||
                    claim.Type == OpenIddictConstants.Claims.Email &&
                    ticket.Principal.HasScope(OpenIddictConstants.Scopes.Email) ||
                    claim.Type == OpenIddictConstants.Claims.Role &&
                    ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile) ||
                    claim.Type == OpenIddictConstants.Claims.PhoneNumber &&
                    ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile)
                   )
                {
                    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }

        private ClaimsPrincipal AddUserDataToPrincipal(ClaimsPrincipal principal, List<string> roles,
            ApplicationUser user)
        {
            var identity = principal.Identity as ClaimsIdentity;
            if (identity is null)
            {
                throw new Exception("invalid identity");
            }

            if (roles.Any())
            {
                var roleClaim = identity.Claims.Where(c => c.Type == "role").ToList();
                if (roleClaim.Any())
                {
                    foreach (var claim in roleClaim)
                    {
                        identity.RemoveClaim(claim);
                    }
                }

                identity.AddClaims(roles.Select(r => new Claim("role", r)));
            }

            return new ClaimsPrincipal(identity);
        }

        #endregion
    }
}