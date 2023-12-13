using FluentValidation;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Features.Account;

public record ForgotPasswordCommand(string Email) : IRequest<ForgotPasswordResponse>;
public record ForgotPasswordResponse(NotificationRecipient Recipient, string ResetToken);
public record NotificationRecipient(string Name, string Email);

public class ForgotPasswordCommandValidator : AbstractValidator<ForgotPasswordCommand>
{
    public ForgotPasswordCommandValidator()
    {
        RuleFor(x => x.Email).NotNull().NotEmpty().Must(ValidationUtils.IsValidEmailAddress)
            .WithMessage("Invalid email address");
    }
}

public class ForgotPasswordCommandHandler(UserManager<ApplicationUser> userManager) : IRequestHandler<ForgotPasswordCommand, ForgotPasswordResponse>
{
    public async Task<ForgotPasswordResponse> Handle(ForgotPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is not { AuthenticationProvider: AuthenticationProvider.IdentityServer })
        {
            throw new InvalidOperationException("User not found");
        }
        
        var passwordResetToken = await userManager.GeneratePasswordResetTokenAsync(user);
        return new ForgotPasswordResponse(new NotificationRecipient(user.FullName, user.Email!), passwordResetToken);
    }
}