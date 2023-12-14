using IdentityServer.Features.Account;
using IdentityServer.Shared.Contracts;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace IdentityServer.Endpoints;

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var routeGroup = endpoints.MapGroup("accounts");

        routeGroup.MapPost("", async Task<Results<Ok<Envelope<SignUpResponse>>, ValidationProblem>>
            ([FromBody] SignUpCommand request, [FromServices] ISender sender) =>
        {
            var createAccount = await sender.Send(request);
            return Envelope.Success(createAccount);
        });


        routeGroup.MapPost("/forgot-password", async Task<Ok<Envelope<ForgotPasswordResponse>>>
            ([FromBody] ForgotPasswordCommand request, [FromServices] ISender sender) =>
        {
            var forgotPassword = await sender.Send(request);
            return Envelope.Success(forgotPassword);
        });

        routeGroup.MapPost("/reset-password", async Task<Ok<Envelope<ResetPasswordResponse>>>
            ([FromBody] ResetPasswordCommand request, [FromServices] ISender sender) =>
        {
            var resetPassword = await sender.Send(request);
            return Envelope.Success(resetPassword);
        });

        var accountGroup = routeGroup.MapGroup("/manage");

        accountGroup.MapGet("/info",
            [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
            async Task<Results<Ok<Envelope<GetProfileResponse>>, ValidationProblem, NotFound>>
                ([FromServices] ISender sender) =>
            {
                var profile = await sender.Send(new GetProfileQuery());
                return Envelope.Success(profile);
            });

        accountGroup.MapPost("/change-password",
            [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
            async Task<Ok<Envelope<ChangePasswordResponse>>> ([FromBody] ChangePasswordCommand request,
                [FromServices] ISender sender) =>
            {
                var changePassword = await sender.Send(request);
                return Envelope.Success(changePassword);
            });
    }
}