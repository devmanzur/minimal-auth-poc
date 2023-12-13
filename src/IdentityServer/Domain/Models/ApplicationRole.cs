using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Domain.Models
{
    public class ApplicationRole : IdentityRole
    {
        private readonly List<ApplicationUserRole> _roles = new List<ApplicationUserRole>();
        public virtual IReadOnlyList<ApplicationUserRole> Roles => _roles.AsReadOnly();
    }
}
