using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authorization;
using Arcus.Security.Authorization;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> related to authorization.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Authorize the <see cref="ISecretProvider"/> instances added during the given <paramref name="addSecretProviders"/> function to be within the given <paramref name="role"/>.
        /// </summary>
        /// <param name="builder">The builder instance to add the authorized provider to.</param>
        /// <param name="role">The authorized role for all the to-be-added providers.</param>
        /// <param name="addSecretProviders">The function that will add the authorized providers.</param>
        public static SecretStoreBuilder AuthorizedWithin(
            this SecretStoreBuilder builder,
            Role role,
            Func<SecretStoreBuilder, SecretStoreBuilder> addSecretProviders)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the role-based authorization");
            Guard.NotNull(addSecretProviders, nameof(addSecretProviders), "Requires a function to make a set of secret providers only available within a specific role");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(Role), role), "Requires the role only within the boundaries of the enumeration");

            builder.AddCriticalException<AuthorizationException>();

            (IList<SecretStoreSource> before, IList<SecretStoreSource> after) = TrackSecretStoreBuilderFunc(builder, addSecretProviders);
            ReplaceSecretSourceWithAuthorized(role, after, before);

            return builder;
        }

        private static (IList<SecretStoreSource> before, IList<SecretStoreSource> after) TrackSecretStoreBuilderFunc(
            SecretStoreBuilder builder,
            Func<SecretStoreBuilder, SecretStoreBuilder> modifySecretStoreBuilder)
        {
            IList<SecretStoreSource> before = builder.SecretStoreSources.ToList();
            modifySecretStoreBuilder(builder);
            IList<SecretStoreSource> after = builder.SecretStoreSources;

            return (before, after);
        }

        private static void ReplaceSecretSourceWithAuthorized(Role role, IList<SecretStoreSource> after, IEnumerable<SecretStoreSource> before)
        {
            SecretStoreSource[] pendingAuthorization = after.Except(before).ToArray();

            foreach (SecretStoreSource pendingSource in pendingAuthorization)
            {
                var authorizedSource = new SecretStoreSource(serviceProvider =>
                {
                    var authorization = serviceProvider.GetRequiredService<IRoleAuthorization>();
                    ISecretProvider secretProvider = CreateAuthorizedSecretProvider(pendingSource, role, authorization);

                    return secretProvider;
                });

                int index = after.IndexOf(pendingSource);
                after[index] = authorizedSource;
            }
        }

        private static ISecretProvider CreateAuthorizedSecretProvider(SecretStoreSource source, Role role, IRoleAuthorization authorization)
        {
            if (source.CachedSecretProvider is null)
            {
                return new AuthorizedSecretProvider(role, authorization, source.SecretProvider);
            }

            return new AuthorizedCachedSecretProvider(role, authorization, source.CachedSecretProvider);
        }
    }
}
