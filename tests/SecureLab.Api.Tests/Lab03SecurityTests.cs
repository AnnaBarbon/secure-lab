using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

/// Безпекові регресійні сценарії ЛР 03 (етап 5 методички):
/// A-01, A-02, A-05 — достатній рівень; A-03, A-04, A-06, A-07 — добрий рівень.
/// Пароль береться зі змінної SeedUsers__Password і ніде не друкується.
public sealed class Lab03SecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object NewIncident(string title) => new
    {
        title,
        description = "Навчальний інцидент ЛР 03 для перевірки власника запису.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    // A-01 (достатній): анонімний запит до захищеного endpoint -> 401, не 302 і не HTML.
    [Fact]
    public async Task A01_AnonymousCreate_Returns401WithoutRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var title = "A01-" + Guid.NewGuid().ToString("N")[..8];

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", NewIncident(title));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        // Код endpoint не виконувався: запис не створено.
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var created = await db.Incidents.AnyAsync(incident => incident.Title == title);
        Assert.False(created);
    }

    // A-02 (достатній): login -> /api/me повертає користувача з cookie/principal.
    [Fact]
    public async Task A02_LoginThenMe_ReturnsAliceFromPrincipal()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, document.RootElement.GetProperty("userId").GetGuid());
        Assert.Equal("alice", document.RootElement.GetProperty("userName").GetString());
        Assert.False(document.RootElement.TryGetProperty("passwordHash", out _));
        Assert.False(document.RootElement.TryGetProperty("securityStamp", out _));
    }

    // A-03 (добрий): чинна cookie Alice + X-Demo-UserId Bob -> /api/me лишається Alice.
    [Fact]
    public async Task A03_CookieWithForeignDemoHeader_KeepsCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, document.RootElement.GetProperty("userId").GetGuid());
    }

    // A-04 (добрий): Bob створює запис без owner у DTO -> owner = Bob із principal.
    [Fact]
    public async Task A04_BobCreatesWithoutOwner_OwnerIsBob()
    {
        var title = "A04-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using var bob = await factory.LoginAsync("bob", StudyPassword);

            using var response = await bob.PostAsJsonAsync("/api/incidents", NewIncident(title));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var createdId = await ReadIdAsync(response);
            Assert.Equal(DbSeeder.BobId, await ReadOwnerAsync(createdId));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-05 (достатній): Bob додає чужий ownerUserId Alice -> власник нового запису лишається Bob.
    [Fact]
    public async Task A05_BobCreatesWithForgedAliceOwner_OwnerStaysBob()
    {
        var title = "A05-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using var bob = await factory.LoginAsync("bob", StudyPassword);

            using var response = await bob.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Підроблений ownerUserId Alice не має змінити власника запису.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                ownerUserId = DbSeeder.AliceId
            });

            // 201 сам по собі не доказ: порівнюємо фактичного власника саме нового запису.
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var createdId = await ReadIdAsync(response);
            var owner = await ReadOwnerAsync(createdId);
            Assert.Equal(DbSeeder.BobId, owner);
            Assert.NotEqual(DbSeeder.AliceId, owner);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-06 (добрий): login -> захищений запит -> logout -> той самий клієнт отримує 401.
    [Fact]
    public async Task A06_LogoutThenSameClient_Gets401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var before = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await alice.PostAsync("/api/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        // Основну cookie обираємо за назвою; значення заголовків не друкуємо.
        var deletesMainCookie = logout.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(value => value.StartsWith(".AspNetCore.Identity.Application=;", StringComparison.Ordinal)
                && value.Contains("1970", StringComparison.Ordinal));
        Assert.True(deletesMainCookie, "Logout did not delete the main auth cookie.");

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07 (добрий): невідомий користувач і хибний пароль -> однаковий зовнішній результат.
    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_LookTheSame()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        // Інший пароль формується локально з навчального й не друкується.
        var wrongPassword = StudyPassword + "-wrong";
        var unknownUser = "nouser" + Guid.NewGuid().ToString("N")[..8];

        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUser, password = StudyPassword });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = wrongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);

        // Стабільні поля Problem Details однакові; traceId різний і не порівнюється.
        using var unknownBody = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync());
        using var wrongBody = JsonDocument.Parse(await wrong.Content.ReadAsStringAsync());
        foreach (var field in new[] { "type", "title", "status", "detail" })
        {
            var inUnknown = unknownBody.RootElement.TryGetProperty(field, out var unknownValue);
            var inWrong = wrongBody.RootElement.TryGetProperty(field, out var wrongValue);
            Assert.Equal(inUnknown, inWrong);
            if (inUnknown)
            {
                Assert.Equal(unknownValue.ToString(), wrongValue.ToString());
            }
        }
    }

    private static async Task<Guid> ReadIdAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<Guid> ReadOwnerAsync(Guid incidentId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == incidentId);
        return incident.OwnerUserId;
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(incident => incident.Title == title).ExecuteDeleteAsync();
    }
}