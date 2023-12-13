using System.Security.Claims;
using FluentValidation;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Features.Account;

public record SignInCommand(string Email, string Password) : IRequest<SignInResponse>;
public record SignInResponse(ApplicationUser User, ClaimsPrincipal Principal);

public class SignInCommandValidator : AbstractValidator<SignInCommand>
{
    public SignInCommandValidator()
    {
        RuleFor(x => x.Email).NotNull().NotEmpty().Must(ValidationUtils.IsValidEmailAddress)
            .WithMessage("Invalid email address");
        RuleFor(x => x.Password).NotNull().NotEmpty().Must(ValidationUtils.IsValidPassword)
            .WithMessage("Invalid password, password must be 8 characters long");
    }
}

public class
    SignInCommandHandler(SignInManager<ApplicationUser> authenticationManager,
        UserManager<ApplicationUser> userManager) : IRequestHandler<SignInCommand,
    SignInResponse>
{
    public async Task<SignInResponse> Handle(SignInCommand request,
        CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(request.Email!);
        if (user is not { AuthenticationProvider: AuthenticationProvider.IdentityServer })
        {
            throw new AuthenticationFailureException("Invalid username/ password combination");
        }

        var signIn = await authenticationManager.PasswordSignInAsync(user, request.Password, true, true);

        if (signIn.Succeeded)
        {
            var principal = await authenticationManager.CreateUserPrincipalAsync(user);

            return new SignInResponse(user,principal);
        }

        throw new AuthenticationFailureException("Sign in is not allowed");
    }
}