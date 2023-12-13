using FluentValidation;
using IdentityServer.Brokers.Providers;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Features.Account;

public record ChangePasswordCommand(string CurrentPassword, string NewPassword) : IRequest<ChangePasswordResponse>;

public record ChangePasswordResponse(string Message);

public class ChangePasswordCommandValidator : AbstractValidator<ChangePasswordCommand>
{
    public ChangePasswordCommandValidator()
    {
        RuleFor(x => x.CurrentPassword).NotNull().NotEmpty()
            .Must(ValidationUtils.IsValidPassword);
        RuleFor(x => x.NewPassword).Must(ValidationUtils.IsValidPassword)
            .NotNull().NotEmpty();
        RuleFor(x => new { x.CurrentPassword, x.NewPassword })
            .Must(x => NotSame(x.CurrentPassword, x.NewPassword));
    }

    private bool NotSame(string currentPassword, string newPassword)
    {
        return currentPassword != newPassword;
    }
}

public class ChangePasswordCommandHandler(
    UserManager<ApplicationUser> userManager,
    RequestContextProvider requestContextProvider) : IRequestHandler<ChangePasswordCommand, ChangePasswordResponse>
{
    public async Task<ChangePasswordResponse> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var signedInUser = requestContextProvider.GetOpenIdSchemeAuthorizedUser();
        var user = await userManager.FindByIdAsync(signedInUser.Id!);
        if (user is null)
        {
            throw new InvalidOperationException("User not found!");
        }

        var changePassword =
            await userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);

        if (changePassword.Succeeded)
        {
            return new ChangePasswordResponse("Password has been changed");
        }

        throw new InvalidOperationException(changePassword.Errors.FirstOrDefault()?.Description ??
                                            "Failed to change password");
    }
}