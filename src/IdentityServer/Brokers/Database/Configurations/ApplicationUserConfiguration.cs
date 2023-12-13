using IdentityServer.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityServer.Brokers.Database.Configurations
{
    public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
    {
        public void Configure(EntityTypeBuilder<ApplicationUser> builder)
        {
            builder.Property(x => x.AuthenticationProvider).HasConversion<string>().IsRequired();
            
            builder.HasMany(u => u.Roles)
                .WithOne(r => r.ApplicationUser)
                .HasForeignKey(r => r.ApplicationUserId);
            
            builder.Metadata.FindNavigation(nameof(ApplicationRole.Roles))
                .SetPropertyAccessMode(PropertyAccessMode.Field);
        }
    }
}