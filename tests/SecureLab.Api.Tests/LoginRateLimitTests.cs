using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

/// Добрий рівень: обмеження спроб входу. Лічильники належать host, а не HttpClient,
/// тому сценарій вичерпання ліміту створює свіжий host із малими значеннями
/// (3 спроби за 4 с) і не заважає іншим тестам.
public sealed class LoginRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const int PermitLimit = 3;
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(4);

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private WebApplicationFactory<Program> FreshHost() =>
        factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["LoginRateLimit:PermitLimit"] = "3",
                    ["LoginRateLimit:WindowSeconds"] = "4"
                })));

    private static HttpClient CreateClient(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

    [Fact]
    public async Task Login_AfterLimit_Returns429ForAnyAccount_ThenRecoversAfterWindow()
    {
        using var host = FreshHost();
        using var client = CreateClient(host);
        // Хибний пароль формується локально з навчального й не друкується.
        var wrongPassword = StudyPassword + "-wrong";

        for (var attempt = 0; attempt < PermitLimit; attempt++)
        {
            using var rejected = await client.PostAsJsonAsync("/api/auth/login",
                new { userName = "alice", password = wrongPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }

        // Після ліміту навіть правильний пароль отримує 429, а невідомий користувач —
        // той самий 429: відповідь не розкриває існування облікового запису.
        using var limitedValid = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        using var limitedUnknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nouser" + Guid.NewGuid().ToString("N")[..8], password = StudyPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedValid.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);
        Assert.False(limitedValid.Headers.Contains("Set-Cookie"), "Rate-limited login issued a cookie.");

        // Ліміт стосується лише login: інший endpoint того самого host працює.
        using var unrelated = await client.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.OK, unrelated.StatusCode);

        // Відновлення: після повного вікна з невеликим запасом вхід знову можливий.
        await Task.Delay(Window + TimeSpan.FromMilliseconds(700));
        using var recovered = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }

    [Fact]
    public async Task Quota_BelongsToHost_NotToHttpClient()
    {
        using var exhausted = FreshHost();
        using var first = CreateClient(exhausted);
        using var second = CreateClient(exhausted);
        var wrongPassword = StudyPassword + "-wrong";

        for (var attempt = 0; attempt < PermitLimit; attempt++)
        {
            using var rejected = await first.PostAsJsonAsync("/api/auth/login",
                new { userName = "bob", password = wrongPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }

        // Новий HttpClient того самого host не очищує квоту (спільний ключ RemoteIpAddress = null).
        using var sameHost = await second.PostAsJsonAsync("/api/auth/login",
            new { userName = "bob", password = StudyPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, sameHost.StatusCode);

        // Окремий host має власні лічильники.
        using var independent = FreshHost();
        using var third = CreateClient(independent);
        using var freshReply = await third.PostAsJsonAsync("/api/auth/login",
            new { userName = "bob", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, freshReply.StatusCode);
    }
}