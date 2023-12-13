using IdentityServer.BackgroundServices;
using IdentityServer.Brokers;
using IdentityServer.Brokers.Database;
using IdentityServer.Brokers.Providers;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Utils;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Quartz;

namespace IdentityServer.Configurations;

public static class ConfigureOpenIddict
{
   public static void AddAuthenticationModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<RequestContextProvider>();
        services.AddScoped<UserManager<ApplicationUser>>();
        services.AddScoped<SignInManager<ApplicationUser>>();
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(ApplicationUser).Assembly));
        services.AddHostedService<ClientSeedingService>();
        services.AddHttpContextAccessor();

        #region identity configuration

        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
                options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                options.User.RequireUniqueEmail = false;
                options.SignIn.RequireConfirmedEmail = false;
            })
            .AddEntityFrameworkStores<IdentityContext>()
            .AddDefaultTokenProviders();
        services.Configure<DataProtectionTokenProviderOptions>(opt =>
            opt.TokenLifespan = TimeSpan.FromMinutes(30));

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });
        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);
            
        #endregion

        #region external identity provider setup

        services
            .AddAuthentication(options =>
            {
                options.DefaultSignInScheme = BearerTokenDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = BearerTokenDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = BearerTokenDefaults.AuthenticationScheme;
            });
        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(120);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
        });

        #endregion

        #region openiddict setup

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<IdentityContext>();
                // Enable Quartz.NET integration.
                options.UseQuartz();
            }).AddServer(options =>
            {
                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetLogoutEndpointUris("/connect/logout")
                    .SetTokenEndpointUris("/connect/token")
                    .SetIntrospectionEndpointUris("/connect/introspect")
                    .SetUserinfoEndpointUris("/connect/userinfo")
                    .SetIntrospectionEndpointUris("/.well-known/openid-configuration");


                // Mark the "email", "profile" and "roles" scopes as supported scopes.
                options.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Roles);

                options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                options.AllowClientCredentialsFlow();
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                // Encryption and signing of tokens
                options.AddEphemeralEncryptionKey()
                    .AddEphemeralSigningKey();
                options.AddEncryptionKey(new SymmetricSecurityKey(
                    Convert.FromBase64String(configuration.GetSection("Auth").GetValue<string>("SymmetricKey") ??
                                             throw new InvalidOperationException())));
                
                // Register the signing credentials.
                options.AddDevelopmentSigningCertificate();

                options.RegisterScopes(ApplicationResourceUtils.Scopes.ResourceScope);

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
                options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(15));
                options.SetRefreshTokenLifetime(TimeSpan.FromHours(1));

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                    //todo remove the disable transport layer security
                    .DisableTransportSecurityRequirement()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableLogoutEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserinfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                options.DisableAccessTokenEncryption();
            })
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // For applications that need immediate access token or authorization
                // revocation, the database entry of the received tokens and their
                // associated authorizations can be validated for each API call.
                // Enabling these options may have a negative impact on performance.
                options.EnableAuthorizationEntryValidation();
                options.EnableTokenEntryValidation();
                    
                // Registers the OpenIddict validation services for ASP.NET Core in the DI container, so it can validate 
                // endpoints that are not directly managed by openiddict
                options.UseAspNetCore();
            });

        #endregion

        #region identity store

        services.AddDbContext<IdentityContext>(options =>
        {
            options.UseSqlite(configuration.GetConnectionString("AuthDatabase"));
            options.UseOpenIddict();
        });

        #endregion
    }
}