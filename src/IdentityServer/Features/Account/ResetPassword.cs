using System.Text;
using FluentValidation;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServer.Features.Account;

public record ResetPasswordCommand(string Email, string Token) : IRequest<ResetPasswordResponse>;

public record ResetPasswordResponse(string Message);

public class ResetPasswordCommandValidator : AbstractValidator<ResetPasswordCommand>
{
    public ResetPasswordCommandValidator()
    {
        RuleFor(x => x.Token).NotNull().NotEmpty();
        RuleFor(x => x.Email).NotNull().NotEmpty()
            .Must(ValidationUtils.IsValidEmailAddress);
    }
}

public class ResetPasswordCommandHandler(UserManager<ApplicationUser> userManager)
    : IRequestHandler<ResetPasswordCommand, ResetPasswordResponse>
{
    public async Task<ResetPasswordResponse> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            throw new InvalidOperationException("User not found");
        }

        var systemGeneratedPassword = PasswordUtils.CreateStrongPassword();

        var resetPassword =
            await userManager.ResetPasswordAsync(user,
                Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token)), systemGeneratedPassword);

        if (resetPassword.Succeeded)
        {
            return new ResetPasswordResponse(
                $"Your password has been reset. your new password is: {systemGeneratedPassword}");
        }

        throw new InvalidOperationException(resetPassword.Errors.FirstOrDefault()?.Description);
    }
}