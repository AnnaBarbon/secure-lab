using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        // У тестовому сервері RemoteIpAddress == null, тому всі клієнти одного host потрапляють
        // в одну групу лічильника login, а кожен LoginAsync — це запит login. Звичайні тести
        // отримують високий ліміт; сам ліміт (429 і відновлення) перевіряє LoginRateLimitTests
        // в окремому свіжому host із малими значеннями.
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["LoginRateLimit:PermitLimit"] = "1000",
                ["LoginRateLimit:WindowSeconds"] = "60"
            }));
    }
}