using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;

namespace SecureLab.Api.Tests;

// ЛР 6: регресійні тести hardening review. Пароль береться зі змінної SeedUsers__Password
// і ніде не друкується.
public sealed class Lab06RegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // REG-HDR-01 (F-01): неочікувана 500 у Production має ті самі захисні заголовки,
    // що й звичайні відповіді, і не розкриває внутрішніх деталей.
    [Fact]
    public async Task REG_HDR_01_Unexpected500_KeepsSecurityHeaders_WithoutInternalDetails()
    {
        using var broken = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
                + "Password=unreachable-study-value;Include Error Detail=false;Timeout=3");
        });
        using var client = broken.CreateClient();

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", string.Join(",", response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", string.Join(",", response.Headers.GetValues("Referrer-Policy")));
        Assert.Contains("frame-ancestors 'none'",
            string.Join(",", response.Headers.GetValues("Content-Security-Policy")));
        Assert.Contains("traceId", body);
        Assert.DoesNotContain("Npgsql", body);
        Assert.DoesNotContain("54399", body);
        Assert.DoesNotContain("unreachable-study-value", body);
        Assert.DoesNotContain("   at ", body);
    }

    
    // REG-CORS-01: у Development лише origin http://localhost:4173 отримує CORS-заголовки;
    // недозволений origin їх не отримує; cross-origin POST через preflight не дозволено.
    [Fact]
    public async Task REG_CORS_01_OnlyAllowedDevelopmentOrigin_GetsCorsHeaders()
    {
        using var client = factory.CreateClient();

        using var allowedRequest = new HttpRequestMessage(HttpMethod.Get, "/health");
        allowedRequest.Headers.Add("Origin", "http://localhost:4173");
        using var allowed = await client.SendAsync(allowedRequest);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal("http://localhost:4173",
            allowed.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Equal("true", allowed.Headers.GetValues("Access-Control-Allow-Credentials").Single());

        using var deniedRequest = new HttpRequestMessage(HttpMethod.Get, "/health");
        deniedRequest.Headers.Add("Origin", "http://localhost:4174");
        using var denied = await client.SendAsync(deniedRequest);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        Assert.False(denied.Headers.Contains("Access-Control-Allow-Origin"));

        using var preflightRequest = new HttpRequestMessage(HttpMethod.Options, "/api/incidents");
        preflightRequest.Headers.Add("Origin", "http://localhost:4173");
        preflightRequest.Headers.Add("Access-Control-Request-Method", "POST");
        using var preflight = await client.SendAsync(preflightRequest);
        Assert.Equal("GET", string.Join(",", preflight.Headers.GetValues("Access-Control-Allow-Methods")));
        Assert.DoesNotContain("POST", string.Join(",", preflight.Headers.GetValues("Access-Control-Allow-Methods")));
    }
}