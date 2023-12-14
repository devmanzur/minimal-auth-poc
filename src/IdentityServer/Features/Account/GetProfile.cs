using System.Security.Claims;
using IdentityServer.Domain.Models;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Features.Account;

public record GetProfileQuery() : IRequest<GetProfileResponse>;

public record GetProfileResponse(string Id, string? FirstName, string? LastName, string? EmailAddress, bool EmailVerified );

public class GetProfileQueryHandler(UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContext) : IRequestHandler<GetProfileQuery, GetProfileResponse>
{
    public async Task<GetProfileResponse> Handle(GetProfileQuery request, CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(httpContext.HttpContext!.User);
        if (user is not null)
        {
            return new GetProfileResponse(user.Id, user.FirstName,user.LastName, user.Email, user.EmailConfirmed);
        }

        throw new InvalidOperationException("User not found");
    }
}