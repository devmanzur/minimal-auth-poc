using System.Security.Claims;
using IdentityServer.Domain.Models;
using IdentityServer.Features.Account;
using IdentityServer.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;

namespace IdentityServer.Endpoints;

public static class IdentityEndpoints
{
    public static void MapIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var routeGroup = endpoints.MapGroup("connect");
        var identityOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>();

        routeGroup.MapPost("/token",
            async (HttpContext context, [FromServices] IServiceProvider sp, [FromServices] ISender sender) =>
            {
                var userManager = sp.GetRequiredService<UserManager<ApplicationUser>>();
                var openIdConnectRequest = context.GetOpenIddictServerRequest();

                if (openIdConnectRequest is not null)
                {
                    if (openIdConnectRequest.IsPasswordGrantType())
                    {
                        return await HandleResourceOwnerPasswordFlow(userManager, sender, identityOptions,
                            openIdConnectRequest);
                    }

                    if (openIdConnectRequest.IsRefreshTokenGrantType() ||
                        openIdConnectRequest.IsAuthorizationCodeFlow())
                    {
                        return await HandleAuthorizationFlow(openIdConnectRequest, context);
                    }

                    if (openIdConnectRequest.IsAuthorizationCodeGrantType())
                    {
                        return await HandleAuthorizationCodeFlow(userManager, identityOptions, openIdConnectRequest,
                            context);
                    }

                    if (openIdConnectRequest.IsClientCredentialsGrantType())
                    {
                        return HandleClientCredentialFlow(openIdConnectRequest);
                    }
                }

                throw new InvalidOperationException("The specified grant type is not supported.");
            });

        routeGroup.MapPost("/authorize", async (HttpContext context) =>
        {
            var request = context.GetOpenIddictServerRequest();

            var applicationAuthentication = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            if (applicationAuthentication.Succeeded)
            {
                return HandleAuthorization(context.User, request);
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetEncodedUrl()
            };

            return Results.Challenge(properties, new[] { OpenIddictClientAspNetCoreDefaults.AuthenticationScheme });
        });
    }


    private static IResult HandleClientCredentialFlow(OpenIddictRequest? request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        identity.AddClaim(OpenIddictConstants.Claims.Subject,
            request.ClientId ?? throw new InvalidOperationException());

        var claimsPrincipal = new ClaimsPrincipal(identity);

        AssignScope(request, claimsPrincipal);

        return Results.SignIn(claimsPrincipal, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> HandleAuthorizationCodeFlow(UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> identityOptions,
        OpenIddictRequest request, HttpContext httpContext)
    {
        var claimsPrincipal =
            (await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
            .Principal;
        var user = await userManager.FindByEmailAsync(claimsPrincipal.GetUserEmail());
        if (user is not null)
        {
            var ticket = await IssueTicket(userManager, identityOptions, request, user, claimsPrincipal);

            AssignScope(request, ticket.Principal);

            return Results.SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        return Results.Forbid();
    }

    private static IResult HandleAuthorization(ClaimsPrincipal contextUser, OpenIddictRequest request)
    {
        var claims = contextUser.Claims;

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        AssignScope(request, claimsPrincipal);

        return Results.SignIn(claimsPrincipal, properties: null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> HandleAuthorizationFlow(OpenIddictRequest request, HttpContext httpContext)
    {
        var claimsPrincipal =
            (await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
            .Principal;

        AssignScope(request, claimsPrincipal);

        return Results.SignIn(claimsPrincipal, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> HandleResourceOwnerPasswordFlow(UserManager<ApplicationUser> userManager,
        ISender sender,
        IOptions<IdentityOptions> identityOptions,
        OpenIddictRequest request)
    {
        var authenticate =
            await sender.Send(new SignInCommand(request.Username, request.Password));
        var ticket = await IssueTicket(userManager, identityOptions, request, authenticate.User,
            authenticate.Principal);

        AssignScope(request, ticket.Principal);

        return Results.SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
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


    private static async Task<AuthenticationTicket> IssueTicket(UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> identityOptions,
        OpenIddictRequest request, ApplicationUser user,
        ClaimsPrincipal principal)
    {
        var roles = await userManager.GetRolesAsync(user);
        var ticket = CreateTicketAsync(identityOptions, request, user, principal, null, roles.ToList());
        return ticket;
    }

    private static AuthenticationTicket CreateTicketAsync(IOptions<IdentityOptions> identityOptions,
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

    private static ClaimsPrincipal AddUserDataToPrincipal(ClaimsPrincipal principal, List<string> roles,
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