using IdentityServer.Features.Account;
using IdentityServer.Shared.Contracts;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Server.AspNetCore;

namespace IdentityServer.Controllers
{
    public class AccountsController(ISender mediator) : BaseApiController
    {
        [AllowAnonymous]
        [HttpPost]
        public async Task<Ok<Envelope<SignUpResponse>>> Register([FromBody] SignUpCommand request)
        {
            var registerUser =
                await mediator.Send(request);
            return Envelope.Success(registerUser);
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme),
         HttpGet(Endpoints.Profile)]
        public async Task<Ok<Envelope<GetProfileResponse>>> Profile()
        {
            var profile = await mediator.Send(new GetProfileQuery());
            return Envelope.Success(profile);
        }

        
        [HttpPost(Endpoints.ChangePassword), Authorize(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        public async Task<Ok<Envelope<ChangePasswordResponse>>> ChangePassword([FromBody] ChangePasswordCommand request)
        {
            var changePassword = await mediator.Send(request);
            await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return Envelope.Success(changePassword);
        }

        [AllowAnonymous]
        [HttpPost(Endpoints.ForgotPassword)]
        public async Task<Ok<Envelope<ForgotPasswordResponse>>> ForgotPassword([FromBody] ForgotPasswordCommand request)
        {
            var forgotPassword = await mediator.Send(request);
            return Envelope.Success(forgotPassword);
        }

        [AllowAnonymous]
        [HttpPost(Endpoints.ResetPassword)]
        public async Task<Ok<Envelope<ResetPasswordResponse>>> ResetPassword([FromBody] ResetPasswordCommand request)
        {
            var resetPassword = await mediator.Send(request);
            return Envelope.Success(resetPassword);
        }
    }
}