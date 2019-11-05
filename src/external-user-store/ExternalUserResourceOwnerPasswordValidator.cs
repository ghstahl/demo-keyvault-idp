using IdentityModel;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace external_user_store
{
    /// <summary>
    /// Resource owner password validator for test users
    /// </summary>
    /// <seealso cref="IdentityServer4.Validation.IResourceOwnerPasswordValidator" />
    public class ExternalUserResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private readonly ExternalUserStore _users;
        private readonly ISystemClock _clock;

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalUserResourceOwnerPasswordValidator"/> class.
        /// </summary>
        /// <param name="users">The users.</param>
        /// <param name="clock">The clock.</param>
        public ExternalUserResourceOwnerPasswordValidator(ExternalUserStore users, ISystemClock clock)
        {
            _users = users;
            _clock = clock;
        }

        /// <summary>
        /// Validates the resource owner password credential
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            if (_users.ValidateCredentials(context.UserName, context.Password))
            {
                var user = _users.FindByUsername(context.UserName);
                var subject = user.SubjectId ?? throw new ArgumentException("Subject ID not set", nameof(user.SubjectId));
                DateTime authTime = _clock.UtcNow.UtcDateTime;

                context.Result = new GrantValidationResult(
                    subject,
                    OidcConstants.AuthenticationMethods.Password, authTime,user.Claims);
            }

            return Task.CompletedTask;
        }
    }
}
