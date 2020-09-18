# Arcus.Security.Core.Authorization
Example of how the Arcus secret store can be customized to include authorization on provider-level.

```csharp
public class Program
{
    public static void Main(string[] args) =>
        CreateHostBuilder(args).Build().Run();

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((context, config) => 
            {
                config.AddJsonFile("appsettings.json")
                      .AddJsonFile("appsettings.Development.json");
            })
            .ConfigureServices(services => services.AddSingleton(new FixedRoleAuthorization(Role.Writer))
            .ConfigureSecretStore((IConfiguration config, SecretStoreBuilder secretStoreBuilder) =>
            {
#if DEBUG
                secretStoreBuilder.AddConfiguration(config);
#endif
                var keyVaultName = config["KeyVault_Name"];
                secretStoreBuilder.AuthorizedWithin(Role.Writer, builder => 
                builder.AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net"));
                    
                secretStoreBuilder.AuthorizedWithin(Role.Admin, builder => builder.AddEnvironmentVariables();
            })
            .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
}
```
