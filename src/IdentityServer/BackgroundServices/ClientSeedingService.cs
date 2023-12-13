using IdentityServer.Brokers;
using IdentityServer.Brokers.Database;
using IdentityServer.Shared.Utils;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdentityServer.BackgroundServices;

public class ClientSeedingService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public ClientSeedingService(IServiceProvider serviceProvider)
            => _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<IdentityContext>();
            await context.Database.MigrateAsync(cancellationToken);
            await RegisterApplications(cancellationToken, scope);
            await RegisterScopes(scope);
        }

        private async Task RegisterScopes(IServiceScope scope)
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            if (await manager.FindByNameAsync(ApplicationResourceUtils.Scopes.ResourceScope) is null)
            {
                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = ApplicationResourceUtils.Scopes.ResourceScope,
                    Resources =
                    {
                        ApplicationResourceUtils.Resources.ResourceApi
                    }
                };

                await manager.CreateAsync(descriptor);
            }
        }

        private static async Task RegisterApplications(CancellationToken cancellationToken, IServiceScope scope)
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("postman", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "postman",
                    ClientSecret = "postman-secret",
                    DisplayName = "Postman Secret",
                    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Token,

                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                        OpenIddictConstants.Permissions.ResponseTypes.Code,
                        OpenIddictConstants.Permissions.Prefixes.Scope + ApplicationResourceUtils.Scopes.ResourceScope,
                    }
                }, cancellationToken);
            }

            if (await manager.FindByClientIdAsync(ApplicationResourceUtils.Resources.ResourceApi, cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = ApplicationResourceUtils.Resources.ResourceApi,
                    ClientSecret = "846B62D0-DEF9-4215-A99D-86E6B8DAB342",
                    DisplayName = "Billiyo API",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Introspection
                    }
                }, cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }