using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;

namespace Arcus.Security.Authorization
{
    /// <summary>
    /// Represents an <see cref="ICachedSecretProvider"/> implementation that act as a filter to make the secret calls authorized by first determining if the consumer is within the expected <see cref="Role"/>.
    /// </summary>
    internal class AuthorizedCachedSecretProvider : AuthorizedSecretProvider
    {
        private readonly ICachedSecretProvider _cachedSecretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizedSecretProvider"/> class.
        /// </summary>
        /// <param name="permittedRole">The role that is required to access the <paramref name="cachedSecretProvider"/>.</param>
        /// <param name="authorization">The instance to determine if the <paramref name="permittedRole"/> is considered authorized.</param>
        /// <param name="cachedSecretProvider">The actual provider to access the secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="authorization"/> or <paramref name="cachedSecretProvider"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="permittedRole"/> is outside the bounds of the enumeration.</exception>
        public AuthorizedCachedSecretProvider(Role permittedRole, IRoleAuthorization authorization, ICachedSecretProvider cachedSecretProvider)
            : base(permittedRole, authorization, cachedSecretProvider)
        {
            Guard.NotNull(cachedSecretProvider, nameof(cachedSecretProvider), "Requires an instance to access the authorized secrets");
            _cachedSecretProvider = cachedSecretProvider;
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        public ICacheConfiguration Configuration => _cachedSecretProvider.Configuration;

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="T:System.Threading.Tasks.Task`1" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The name must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The name must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to access the secret");
            return await WhenAuthorized(() => _cachedSecretProvider.GetRawSecretAsync(secretName, ignoreCache));
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="T:System.Threading.Tasks.Task`1" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The name must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The name must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to access the secret");
            return await WhenAuthorized(() => _cachedSecretProvider.GetSecretAsync(secretName, ignoreCache));
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName" /> from the cache;
        /// so the next time <see cref="M:Arcus.Security.Core.Caching.CachedSecretProvider.GetSecretAsync(System.String)" /> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public async Task InvalidateSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to invalidate the secret");
            await WhenAuthorized(() => _cachedSecretProvider.InvalidateSecretAsync(secretName));
        }
    }
}