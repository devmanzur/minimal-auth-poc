using System.Reflection;
using FluentValidation;
using IdentityEndpoints.Brokers.Database;
using IdentityEndpoints.Domain.Models;
using IdentityEndpoints.Utils;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace IdentityEndpoints.Configurations;

public static class ConfigureIdentityDependencies
{
    public static IServiceCollection ConfigureIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthorization();
        services.AddDbContext<AppIdentityDbContext>(options =>
            options.UseSqlite(configuration.GetConnectionString("AuthDatabase")));
        services
            .AddIdentityApiEndpoints<ApplicationUser>()
            .AddEntityFrameworkStores<AppIdentityDbContext>();
        
        var asm = Assembly.GetExecutingAssembly();
        services.AddValidatorsFromAssembly(asm);
        services.AddMediatR(cfg =>
        {
            cfg.RegisterServicesFromAssembly(asm);
            cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
        });

        return services;
    }
}