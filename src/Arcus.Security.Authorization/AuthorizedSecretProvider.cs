using System;
using System.Security.Authorization;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;

namespace Arcus.Security.Authorization
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> implementation that act as a filter to make the secret calls authorized by first determining if the consumer is within the expected <see cref="Role"/>.
    /// </summary>
    internal class AuthorizedSecretProvider : ISecretProvider
    {
        private readonly Role _permittedRole;
        private readonly IRoleAuthorization _authorization;
        private readonly ISecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizedSecretProvider"/> class.
        /// </summary>
        /// <param name="permittedRole">The role that is required to access the <paramref name="secretProvider"/>.</param>
        /// <param name="authorization">The instance to determine if the <paramref name="permittedRole"/> is considered authorized.</param>
        /// <param name="secretProvider">The actual provider to access the secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="authorization"/> or <paramref name="secretProvider"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="permittedRole"/> is outside the bounds of the enumeration.</exception>
        public AuthorizedSecretProvider(Role permittedRole, IRoleAuthorization authorization, ISecretProvider secretProvider)
        {
            Guard.NotNull(authorization, nameof(authorization), "Requires an instance to determine if the current role is considered authorized");
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires an instance to access the authorized secrets");
            Guard.For<ArgumentOutOfRangeException>(() => !Enum.IsDefined(typeof(Role), permittedRole), "Requires the role to be inside the bounds of the enumeration");

            _permittedRole = permittedRole;
            _authorization = authorization;
            _secretProvider = secretProvider;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to access the secret");
            return await WhenAuthorized(() => _secretProvider.GetRawSecretAsync(secretName));
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to access the secret");
            return await WhenAuthorized(() => _secretProvider.GetSecretAsync(secretName));
        }

        /// <summary>
        /// Provides a filter to only run the asynchronous <paramref name="asyncFunc"/> when the consumer is considered authorized.
        /// </summary>
        /// <typeparam name="T">The result of the <paramref name="asyncFunc"/>.</typeparam>
        /// <param name="asyncFunc">The asynchronous function to run when the consumer is considered authorized.</param>
        /// <returns>
        ///     The result of the <paramref name="asyncFunc"/> or <c>null</c> when the consumer is not considered authorized.
        /// </returns>
        protected async Task<T> WhenAuthorized<T>(Func<Task<T>> asyncFunc) where T : class
        {
            Guard.NotNull(asyncFunc, nameof(asyncFunc), "Requires an asynchronous function to run when the consumer is considered authorized");
            
            if (await _authorization.IsAuthorizedAsync(_permittedRole))
            {
                return await asyncFunc();
            }

            throw new AuthorizationException($"Accessing secret is not permitted for role '{_permittedRole}'");
        }

        /// <summary>
        /// Provides a filter to only run the asynchronous <paramref name="asyncFunc"/> when the consumer is considered authorized.
        /// </summary>
        /// <param name="asyncFunc">The asynchronous function to run when the consumer is considered authorized.</param>
        protected async Task WhenAuthorized(Func<Task> asyncFunc)
        {
            Guard.NotNull(asyncFunc, nameof(asyncFunc), "Requires an asynchronous function to run when the consumer is considered authorized");

            if (await _authorization.IsAuthorizedAsync(_permittedRole))
            {
                await asyncFunc();
            }

            throw new AuthorizationException($"Accessing secret is not permitted for role '{_permittedRole}'");
        }
    }
}