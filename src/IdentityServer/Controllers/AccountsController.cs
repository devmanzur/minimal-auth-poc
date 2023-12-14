using IdentityServer.Domain.Models;
using IdentityServer.Features.Account;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Server.AspNetCore;

namespace IdentityServer.Controllers
{
    public class AccountsController(ISender mediator) : BaseApiController
    {
        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult> Register([FromBody] SignUpCommand request)
        {
            var registerUser =
                await mediator.Send(request);
            return Ok(registerUser);
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme),
         HttpGet(Endpoints.Profile)]
        public async Task<ActionResult<GetProfileResponse>> Profile()
        {
            var profile = await mediator.Send(new GetProfileQuery());
            return Ok(profile);
        }
        
        [HttpPost(Endpoints.ChangePassword), Authorize(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        public async Task<ActionResult> ChangePassword([FromBody] ChangePasswordCommand request)
        {
            await mediator.Send(request);
            await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return Challenge(authenticationSchemes: IdentityConstants.ApplicationScheme);
        }
        
        [AllowAnonymous]
        [HttpPost(Endpoints.ForgotPassword)]
        public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordCommand request)
        {
            var forgotPassword = await mediator.Send(request);
            return Ok(forgotPassword);
        }

        [AllowAnonymous]
        [HttpPost(Endpoints.ResetPassword)]
        public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordCommand request)
        {
            var resetPassword = await mediator.Send(request);
            return Ok(resetPassword);
        }
    }
}