using System;
using System.Runtime.InteropServices;
using System.Security.Authorization;
using System.Threading.Tasks;
using Arcus.Security.Authorization.Tests.Unit.Fixture;
using Arcus.Security.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Authorization.Tests.Unit
{
    [Trait(name: "Category", value: "Unit")]
    public class SecretStoreBuilderTests
    {
        [Theory]
        [InlineData(Role.Admin, Role.Reader)]
        [InlineData(Role.Admin, Role.Writer)]
        [InlineData(Role.Writer, Role.Reader)]
        public async Task ConfigureSecretStore_WithNotPermittedRole_CantAccess(Role permittedRole, Role currentRole)
        {
            // Arrange
            const string secretKey = "MySecret";
            var stubProvider = new InMemorySecretProvider(secretKey, $"secret-{Guid.NewGuid()}");
            IRoleAuthorization authorization = new FixedRoleAuthorization(currentRole);
            IHostBuilder builder = new HostBuilder().ConfigureServices(services => services.AddSingleton(authorization));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemorySecretProvider())
                      .AuthorizedWithin(permittedRole, x => x.AddProvider(stubProvider));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<AuthorizationException>(() => provider.GetRawSecretAsync(secretKey));
        }

        [Theory]
        [InlineData(Role.Reader, Role.Reader)]
        [InlineData(Role.Reader, Role.Admin)]
        [InlineData(Role.Writer, Role.Writer)]
        [InlineData(Role.Writer, Role.Admin)]
        [InlineData(Role.Admin, Role.Admin)]
        public async Task ConfigureSecretStore_WithPermittedRole_CantAccess(Role permittedRole, Role currentRole)
        {
            // Arrange
            const string secretKey = "MySecret";
            var expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider(secretKey, expected);
            IRoleAuthorization authorization = new FixedRoleAuthorization(currentRole);
            IHostBuilder builder = new HostBuilder().ConfigureServices(services => services.AddSingleton(authorization));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemorySecretProvider())
                      .AuthorizedWithin(permittedRole, x => x.AddProvider(stubProvider));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            string actual = await provider.GetRawSecretAsync(secretKey);

            Assert.Equal(expected, actual);
        }
    }
}
