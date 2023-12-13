using FluentValidation;
using IdentityServer.Shared.Interfaces;
using IdentityServer.Shared.Utils;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Domain.Models
{
    public class ApplicationUser : IdentityUser, IAuditable
    {
        protected ApplicationUser()
        {
        }

        public ApplicationUser(string email, string firstName, string lastName,
            AuthenticationProvider authenticationProvider)
        {
            FirstName = firstName;
            LastName = lastName;
            AuthenticationProvider = authenticationProvider;
            Email = email;
            UserName = CreateUsername(email);
            DomainValidator.Validate<ApplicationUser, ApplicationUserValidator>(this);
        }

        public ApplicationUser(string username, AuthenticationProvider authenticationProvider)
        {
            FirstName = $"{authenticationProvider}";
            LastName = "User";
            AuthenticationProvider = authenticationProvider;
            Email = CreateEmail(username, authenticationProvider);
            UserName = username;
            DomainValidator.Validate<ApplicationUser, ApplicationUserValidator>(this);
        }

        private readonly List<ApplicationUserRole> _roles = new List<ApplicationUserRole>();
        public virtual IReadOnlyList<ApplicationUserRole> Roles => _roles.AsReadOnly();

        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public AuthenticationProvider AuthenticationProvider { get; private set; }
        public string FullName => $"{FirstName} {LastName}";

        private static string CreateUsername(string email)
        {
            return !string.IsNullOrEmpty(email) ? "@" + email.Split("@")[0] + Guid.NewGuid() : email;
        }

        private static string CreateEmail(string username, AuthenticationProvider authenticationProvider)
        {
            return !string.IsNullOrEmpty(username)
                ? $"{username}@{authenticationProvider.ToString().ToLower()}.com"
                : username;
        }

        public Guid Version { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public string? CreatedBy { get; set; }
        public string? UpdatedBy { get; set; }
    }

    public enum AuthenticationProvider
    {
        IdentityServer,
        // Google,
        // Microsoft,
        // MicrosoftIdentity,
        // Facebook,
        // Twitter
    }

    public class ApplicationUserValidator : AbstractValidator<ApplicationUser>
    {
        public ApplicationUserValidator()
        {
            RuleFor(x => x.FirstName).NotNull().NotEmpty();
            RuleFor(x => x.LastName).NotNull().NotEmpty();
            RuleFor(x => x.Email).NotNull().NotEmpty().Must(ValidationUtils.IsValidEmailAddress);
        }
    }
}