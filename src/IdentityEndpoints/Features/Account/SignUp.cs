using FluentValidation;
using IdentityEndpoints.Domain.Models;
using IdentityEndpoints.Shared.Utils;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityEndpoints.Features.Account;

public record SignUpCommand(string Email, string Password, string FirstName, string LastName) : IRequest<SignUpResponse>;

public record SignUpResponse(string Id);

public class SignUpCommandValidator : AbstractValidator<SignUpCommand>
{

    public SignUpCommandValidator()
    {
        RuleFor(x => x.Email).NotNull().NotEmpty().Must(ValidationUtils.IsValidEmailAddress)
            .WithMessage("Invalid email address");
        RuleFor(x => x.Password).NotNull().NotEmpty().Must(ValidationUtils.IsValidPassword)
            .WithMessage("Invalid password");
        RuleFor(x => x.FirstName).NotNull().NotEmpty().WithMessage("Invalid first name");
        RuleFor(x => x.LastName).NotNull().NotEmpty().WithMessage("Invalid last name");
    }
}

public class SignUpCommandHandler(UserManager<ApplicationUser> userManager) : IRequestHandler<SignUpCommand, SignUpResponse>
{
    public async Task<SignUpResponse> Handle(SignUpCommand request, CancellationToken cancellationToken)
    {
        var duplicateUser = await userManager.FindByEmailAsync(request.Email);
        if (duplicateUser is not null)
        {
            throw new InvalidOperationException("User with same email address already exists");
        }
        
        var user = new ApplicationUser()
        {
            Email = request.Email,
            UserName = request.Email,
            EmailConfirmed = false,
            FirstName = request.FirstName,
            LastName = request.LastName
        };
        var createUser = await userManager.CreateAsync(user, request.Password);
        if (createUser.Succeeded)
        {
            return new SignUpResponse(user.Id);
        }

        throw new SystemException("Failed to create new user account");
    }
}