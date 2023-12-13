using System.Reflection;
using IdentityServer.Domain.Models;
using IdentityServer.Shared.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Brokers.Database
{
    public class IdentityContext : IdentityDbContext<ApplicationUser, ApplicationRole, string,
        IdentityUserClaim<string>, ApplicationUserRole, IdentityUserLogin<string>,
        IdentityRoleClaim<string>, IdentityUserToken<string>>
    {

        public IdentityContext(DbContextOptions options, IConfiguration configuration)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.HasDefaultSchema("identity");
            base.OnModelCreating(builder);
            builder.ApplyConfigurationsFromAssembly(Assembly.GetAssembly(typeof(IdentityContext)));
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            base.OnConfiguring(options);
        }

        public override int SaveChanges(bool acceptAllChangesOnSuccess)
        {
            Audit();
            return base.SaveChanges(acceptAllChangesOnSuccess);;
        }

        public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess,
            CancellationToken cancellationToken = new CancellationToken())
        {
            Audit();
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        }

        #region Change tracking
        
        private void Audit()
        {
            foreach (var entry in ChangeTracker.Entries<IAuditable>().ToList())
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        entry.Entity.CreatedAt = DateTime.UtcNow;
                        break;
                    case EntityState.Modified:
                        entry.Entity.UpdatedAt = DateTime.UtcNow;
                        break;
                }
            }
        }

        #endregion
    }
}