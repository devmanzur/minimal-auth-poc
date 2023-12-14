using IdentityEndpoints.Domain.Models;
using MediatR;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace IdentityEndpoints.Endpoints;

public static class IdentityEndpoints
{
    public static void MapIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var routeGroup = endpoints.MapGroup("connect");
        
        routeGroup.MapPost("/token", async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>>
        ([FromBody] LoginRequest login, [FromQuery] bool? useCookies, [FromQuery] bool? useSessionCookies,
            [FromServices] ISender sender, [FromServices] SignInManager<ApplicationUser> signInManager) =>
        {
            var result = await HandleSignIn(useCookies, useSessionCookies, signInManager, login);

            if (!result.Succeeded)
            {
                return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
            }

            // The signInManager already produced the needed response in the form of a cookie or bearer token.
            return TypedResults.Empty;
        });

        routeGroup.MapPost("/refresh-token",
            async Task<Results<Ok<AccessTokenResponse>, UnauthorizedHttpResult, SignInHttpResult, ChallengeHttpResult>>
                ([FromBody] RefreshRequest refreshRequest, [FromServices] IServiceProvider sp) =>
            {
                var bearerTokenOptions = sp.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>();
                var signInManager = sp.GetRequiredService<SignInManager<ApplicationUser>>();
                var refreshTokenProtector =
                    bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
                var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

                // Reject the /refresh attempt with a 401 if the token expired or the security stamp validation fails
                if (refreshTicket?.Properties.ExpiresUtc is not { } expiresUtc ||
                    DateTimeOffset.UtcNow >= expiresUtc ||
                    await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not ApplicationUser user)

                {
                    return TypedResults.Challenge();
                }

                var newPrincipal = await signInManager.CreateUserPrincipalAsync(user);
                return TypedResults.SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
            });
    }

    private static async Task<SignInResult> HandleSignIn(bool? useCookies, bool? useSessionCookies,
        SignInManager<ApplicationUser> signInManager,
        LoginRequest login)
    {
        var useCookieScheme = useCookies == true || useSessionCookies == true;
        var isPersistent = useCookies == true && useSessionCookies != true;
        signInManager.AuthenticationScheme =
            useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

        var result =
            await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent,
                lockoutOnFailure: true);

        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent,
                    rememberClient: isPersistent);
            }
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
            {
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
            }
        }

        return result;
    }

    private static Dictionary<string, string[]> CreateErrors(IdentityResult result)
    {
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return errorDictionary;
    }
}