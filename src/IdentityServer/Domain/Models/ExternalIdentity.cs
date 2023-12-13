using System.Security.Claims;

namespace IdentityServer.Domain.Models
{
    public class ExternalIdentity
    {
        public ExternalIdentity(string provider, string providerKey, string providerDisplayName, ClaimsPrincipal principal)
        {
            Provider = provider;
            ProviderKey = providerKey;
            ProviderDisplayName = providerDisplayName;
            Principal = principal;
        }

        public ClaimsPrincipal Principal { get; private set; }
        public string Provider { get; private set; }
        public string ProviderKey { get; private set; }
        public string ProviderDisplayName { get; private set; }
    }
}