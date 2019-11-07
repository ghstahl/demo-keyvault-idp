using IdentityServer4.Validation;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Threading.Tasks;

namespace SelfContained.AuthorizationStore
{
    class TokenRequestValidator : ITokenRequestValidator
    {
        public Task<TokenRequestValidationResult> ValidateRequestAsync(NameValueCollection parameters, ClientSecretValidationResult clientValidationResult)
        {
            throw new NotImplementedException();
        }
    }
}
