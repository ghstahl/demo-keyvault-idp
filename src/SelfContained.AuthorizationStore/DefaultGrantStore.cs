using SelfContained.AuthorizationStore.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Stores.Serialization;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using ZeroFormatter;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Principal;
using System.Linq;
using Microsoft.Extensions.Caching.Memory;
using KeyVaultBackground;
using IdentityServer4.Configuration;

namespace SelfContained.AuthorizationStore
{
    /// <summary>
    /// Base class for persisting grants using the IPersistedGrantStore.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DefaultGrantStore<T>
    {
        const string Issuer = "self";
        const string Audience = "self";
  
        private IMemoryCache _cache;

        /// <summary>
        /// The grant type being stored.
        /// </summary>
        protected string GrantType { get; }

        /// <summary>
        /// The logger.
        /// </summary>
        protected ILogger Logger { get; }

        private EDCSAConfigSet _set;

        /// <summary>
        /// The PersistedGrantStore.
        /// </summary>
        protected IPersistedGrantStore Store { get; }

        /// <summary>
        /// The PersistentGrantSerializer;
        /// </summary>
        protected IPersistentGrantSerializer Serializer { get; }

        /// <summary>
        /// The HandleGenerationService.
        /// </summary>
        protected IHandleGenerationService HandleGenerationService { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultGrantStore{T}"/> class.
        /// </summary>
        /// <param name="grantType">Type of the grant.</param>
        /// <param name="store">The store.</param>
        /// <param name="serializer">The serializer.</param>
        /// <param name="handleGenerationService">The handle generation service.</param>
        /// <param name="logger">The logger.</param>
        /// <exception cref="System.ArgumentNullException">grantType</exception>
        protected DefaultGrantStore(
            string grantType,
            IPersistedGrantStore store,
            IPersistentGrantSerializer serializer,
            IHandleGenerationService handleGenerationService,
            IMemoryCache cache,
            ILogger logger)
        {
            if (grantType.IsMissing()) throw new ArgumentNullException(nameof(grantType));

            _cache = cache;
            GrantType = grantType;
            Store = store;
            Serializer = serializer;
            HandleGenerationService = handleGenerationService;
            Logger = logger;

            _set = new EDCSAConfigSet
            {
                Set = new System.Collections.Generic.List<EDCSAConfig>()
            };

            if (!_cache.TryGetValue("4be948db-3255-4fa1-a802-da66621d180c", out _set))
            {
                throw new Exception("Could not get EDCSAConfigSet from cache");
            }

        }

        private const string KeySeparator = ":";

        /// <summary>
        /// Gets the hashed key.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        protected virtual string GetHashedKey(string value)
        {
            return (value + KeySeparator + GrantType).Sha256();
        }

        /// <summary>
        /// Gets the item.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        protected virtual async Task<T> GetItemAsync(string key)
        {

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = GetValidationParameters();

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(key, validationParameters, out validatedToken);

                var code = (from claim in principal.Claims
                          where claim.Type == "code"
                          select claim).FirstOrDefault();

                var payload = Serializer.Deserialize<T>(code.Value);
                return payload;
            }
            catch(Exception ex)
            {
                Logger.LogError(ex, "Failed to deserialize JSON from grant store.");
            }
            return default(T);
        }

        /// <summary>
        /// Creates the item.
        /// </summary>
        /// <param name="item">The item.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="subjectId">The subject identifier.</param>
        /// <param name="created">The created.</param>
        /// <param name="lifetime">The lifetime.</param>
        /// <returns></returns>
        protected virtual async Task<string> CreateItemAsync(T item, string clientId, string subjectId, DateTime created, int lifetime)
        {
            var handle = await HandleGenerationService.GenerateAsync();
            handle = await StoreItemAsync(handle, item, clientId, subjectId, created, created.AddSeconds(lifetime));
            return handle;
        }

        /// <summary>
        /// Stores the item.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="item">The item.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="subjectId">The subject identifier.</param>
        /// <param name="created">The created.</param>
        /// <param name="lifetime">The lifetime.</param>
        /// <returns></returns>
        protected virtual Task StoreItemAsync(string key, T item, string clientId, string subjectId, DateTime created, int lifetime)
        {
            return StoreItemAsync(key, item, clientId, subjectId, created, created.AddSeconds(lifetime));
        }
        private TokenValidationParameters GetValidationParameters()
        {
            var issuerSigningKey = ECDsaMicrosoft.ECDSA.CreateSecurityKey(_set.Set[0].PublicKey);
            return new TokenValidationParameters()
            {
                ValidateLifetime = true, // Because there is no expiration in the generated token
                ValidateAudience = true, // Because there is no audiance in the generated token
                ValidateIssuer = true,   // Because there is no issuer in the generated token
                ValidIssuer = Issuer,
                ValidAudience = Audience,
                IssuerSigningKey = issuerSigningKey // The same key as the one that generate the token
            };
        }
        class Minimal
        {
            public string N { get; set; }
            public string S { get; set; }
        }
        /// <summary>
        /// Stores the item.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="item">The item.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="subjectId">The subject identifier.</param>
        /// <param name="created">The created.</param>
        /// <param name="expiration">The expiration.</param>
        /// <returns></returns>
        protected virtual async Task<string> StoreItemAsync(string key, T item, string clientId, string subjectId, DateTime created, DateTime? expiration)
        {
            key = GetHashedKey(key);

            var credentialsECDsa = ECDsaMicrosoft.ECDSA.CreateSigningCredentials(_set.Set[0].PrivateKey,"0");

            var json = Serializer.Serialize(item);
            var payload = JsonConvert.DeserializeObject<AuthorizationCodeHandle>(json);

            var secToken = new JwtSecurityToken(
                signingCredentials: credentialsECDsa,
                issuer: Issuer,
                audience: Audience,
                expires: (DateTime)expiration);
           
            secToken.Payload["code"] = payload;
          


            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(secToken);

            /*
                        var privateKey = Token.GetPrivateKey();
                        var token = new Token(json, (DateTime)expiration);
                        var tokenString = token.GetTokenString(privateKey);
            */
            //       var dd = JsonConvert.DeserializeObject<ZeroFormatterAuthorizationCode>(json);
            //       var bytes = ZeroFormatterSerializer.Serialize(dd);
            //       var mc2 = ZeroFormatterSerializer.Deserialize<ZeroFormatterAuthorizationCode>(bytes);

            var grant = new PersistedGrant
            {
                Key = key,
                Type = GrantType,
                ClientId = clientId,
                SubjectId = subjectId,
                CreationTime = created,
                Expiration = expiration,
                Data = json
            };

            await Store.StoreAsync(grant);
            return jwt;
        }

        /// <summary>
        /// Removes the item.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        protected virtual async Task RemoveItemAsync(string key)
        {
            //key = GetHashedKey(key);
           // await Store.RemoveAsync(key);
        }

        /// <summary>
        /// Removes all items for a subject id / cliend id combination.
        /// </summary>
        /// <param name="subjectId">The subject identifier.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <returns></returns>
        protected virtual async Task RemoveAllAsync(string subjectId, string clientId)
        {
            //await Store.RemoveAllAsync(subjectId, clientId, GrantType);
        }
    }
}
