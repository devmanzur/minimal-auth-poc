namespace IdentityServer.Domain.Models
{
    public class OpenIdAuthorizedUser
    {
        public string? Username { get; set; }
        public string? EmailAddress { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Id { get; set; }
    }
}