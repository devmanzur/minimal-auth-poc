using IdentityServer.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityServer.Brokers.Database.Configurations
{
    public class ApplicationRoleConfiguration : IEntityTypeConfiguration<ApplicationRole>
    {
        public void Configure(EntityTypeBuilder<ApplicationRole> builder)
        {
            builder.HasMany(x => x.Roles)
                .WithOne(x => x.Role)
                .HasForeignKey(x => x.RoleId);
            
            builder.Metadata.FindNavigation(nameof(ApplicationRole.Roles))
                .SetPropertyAccessMode(PropertyAccessMode.Field);
        }
    }
}