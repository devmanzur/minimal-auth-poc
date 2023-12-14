using IdentityServer.Brokers.Providers;
using IdentityServer.Domain.Models;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Features.Account;

public record GetProfileQuery() : IRequest<GetProfileResponse>;

public record GetProfileResponse(string Id, string? FirstName, string? LastName, string? EmailAddress, bool EmailVerified );

public class GetProfileQueryHandler(UserManager<ApplicationUser> userManager, RequestContextProvider requestContextProvider) : IRequestHandler<GetProfileQuery, GetProfileResponse>
{
    public async Task<GetProfileResponse> Handle(GetProfileQuery request, CancellationToken cancellationToken)
    {
        var signedInUser = requestContextProvider.GetOpenIdSchemeAuthorizedUser();
        var user = await userManager.FindByIdAsync(signedInUser.Id);
        if (user is not null)
        {
            return new GetProfileResponse(user.Id, user.FirstName,user.LastName, user.Email, user.EmailConfirmed);
        }

        throw new InvalidOperationException("Profile not found");
    }
}