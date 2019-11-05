using external_user_store;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods for the IdentityServer builder
    /// </summary>
    public static class IdentityServerBuilderExtensions
    {
        /// <summary>
        /// Adds test users.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="users">The users.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddExternalUsers(this IIdentityServerBuilder builder, List<ExternalUser> users)
        {
            builder.Services.AddSingleton(new ExternalUserStore(users));
            builder.AddProfileService<ExternalUserProfileService>();
            builder.AddResourceOwnerValidator<ExternalUserResourceOwnerPasswordValidator>();

            return builder;
        }
    }
}
