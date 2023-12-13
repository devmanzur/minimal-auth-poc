using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Domain.Models
{
  public  class ApplicationUserRole : IdentityUserRole<string>
    {
        public virtual string ApplicationUserId { get; set; }
        public virtual ApplicationUser ApplicationUser { get; set; }
        public virtual string RoleId { get; set; }
        public virtual ApplicationRole Role { get; set; }
    }
}
