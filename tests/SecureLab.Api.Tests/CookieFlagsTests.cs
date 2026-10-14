using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

/// Добрий рівень: фактичні атрибути cookie фіксованого профілю (за зразком CookieFlagsExampleTests).
/// Значення cookie не читається й не друкується — аналізуються лише атрибути після «назва=значення».
public sealed class CookieFlagsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string CookieName = ".AspNetCore.Identity.Application=";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // HTTPS-запит: SameAsRequest додає secure; також httponly, samesite=lax, path=/,
    // і cookie сеансова — без expires/max-age.
    [Fact]
    public async Task Login_OverHttps_SetsHttpOnlySecureLaxSessionCookie()
    {
        var attributes = await LoginAndReadAttributesAsync(new Uri("https://localhost"));

        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("path=/", attributes);
        Assert.DoesNotContain(attributes, attribute => attribute.StartsWith("expires=", StringComparison.Ordinal));
        Assert.DoesNotContain(attributes, attribute => attribute.StartsWith("max-age=", StringComparison.Ordinal));
    }

    // Локальний HTTP у Development: secure відсутній (SameAsRequest) — межа локального запуску,
    // яку чесно фіксуємо у звіті; HttpOnly і SameSite=Lax лишаються.
    [Fact]
    public async Task Login_OverPlainHttpInDevelopment_HasNoSecureButKeepsHttpOnlyAndLax()
    {
        var attributes = await LoginAndReadAttributesAsync(new Uri("http://localhost"));

        Assert.Contains("httponly", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.DoesNotContain("secure", attributes);
    }

    private async Task<string[]> LoginAndReadAttributesAsync(Uri baseAddress)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = baseAddress,
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(CookieName, StringComparison.Ordinal))
            .ToArray();
        // Assert лише за кількістю: значення cookie не потрапить у повідомлення про помилку.
        Assert.True(matching.Length == 1);

        // Перша частина — «назва=значення»; її не читаємо й не друкуємо.
        return matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant())
            .ToArray();
    }
}