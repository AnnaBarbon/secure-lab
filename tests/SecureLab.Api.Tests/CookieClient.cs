using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Presentation.Endpoints;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    // ЛР 6: тип параметра — WebApplicationFactory<Program>, щоб login працював і з похідним
    // host (WithWebHostBuilder, наприклад Production). Після login клієнт, як і справжній
    // браузерний клієнт, отримує request token і надсилає його в заголовку X-CSRF-TOKEN.
    public static async Task<HttpClient> LoginAsync(this WebApplicationFactory<Program> factory,
        string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        await client.UseAntiforgeryTokenAsync();
        return client;
    }

    // Значення токена не друкується й не логуються.
    public static async Task UseAntiforgeryTokenAsync(this HttpClient client)
    {
        client.DefaultRequestHeaders.Remove(AntiforgeryEndpoints.HeaderName);
        using var response = await client.GetAsync("/api/auth/csrf-token");
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
        {
            throw new InvalidOperationException("Missing request token.");
        }
        client.DefaultRequestHeaders.Add(AntiforgeryEndpoints.HeaderName, body.Token);
    }

    private sealed record TokenResponse(string Token);
}