using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;

namespace Arcus.Security.Authorization.Tests.Unit.Fixture
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> implementation that provides secrets in-memory.
    /// </summary>
    public class InMemorySecretProvider : ISecretProvider
    {
        private readonly IDictionary<string, string> _secrets;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        public InMemorySecretProvider() : this(new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        /// <param name="secretName">The name of the secret in the in-memory collection of secrets.</param>
        /// <param name="secretValue">The value of the secret in the in-memory collection of secrets.</param>
        public InMemorySecretProvider(string secretName, string secretValue)
        {
            Guard.NotNull(secretName, nameof(secretName), "Requires a non-null secret name in the in-memory collection of secrets");
            
            _secrets = new Dictionary<string, string>
            {
                [secretName] = secretValue
            };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        /// <param name="secrets">The entire in-memory collection of secret names and their values.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secrets"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when one of the secret names in the <paramref name="secrets"/> is <c>null</c>.</exception>
        public InMemorySecretProvider(IDictionary<string, string> secrets)
        {
            Guard.NotNull(secrets, nameof(secrets), "Requires an in-memory collection of secrets");
            Guard.For<ArgumentException>(() => secrets.Any(secret => secret.Key is null), "Requires all secret names to be non-null");
            
            _secrets = secrets;
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            string secretValue = await GetRawSecretAsync(secretName);
            if (secretValue is null)
            {
                return null;
            }

            return new Secret(secretValue);
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            if (_secrets.TryGetValue(secretName, out string secretValue))
            {
                return Task.FromResult(secretValue);
            }

            return Task.FromResult<string>(null);
        }
    }
}
