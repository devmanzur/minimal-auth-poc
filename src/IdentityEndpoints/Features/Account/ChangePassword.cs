using System.Security.Claims;
using FluentValidation;
using IdentityEndpoints.Domain.Models;
using IdentityEndpoints.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityEndpoints.Features.Account;

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
    IHttpContextAccessor httpContext) : IRequestHandler<ChangePasswordCommand, ChangePasswordResponse>
{
    public async Task<ChangePasswordResponse> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(httpContext.HttpContext!.User);
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