
using IdentityServer4.Stores;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SelfContained.AuthorizationStore;
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
        public static IIdentityServerBuilder AddJWTBasedAuthorizationCodeStore(this IIdentityServerBuilder builder)
        {
            builder.Services.RemoveAll<IAuthorizationCodeStore>();
            builder.Services.TryAddTransient<IAuthorizationCodeStore, JWTBasedAuthorizationCodeStore>();
            return builder;
        }
    }
}
