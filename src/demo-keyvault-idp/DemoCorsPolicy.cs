using IdentityServer4.Services;
using System.Threading.Tasks;

namespace DemoKeyVaultIDP
{
    public class DemoCorsPolicy : ICorsPolicyService
    {
        public Task<bool> IsOriginAllowedAsync(string origin)
        {
            return Task.FromResult(true);
        }
    }
}
