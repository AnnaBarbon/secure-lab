using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using SecureLab.Api.Presentation.Endpoints;

namespace SecureLab.Api.Tests;

// ЛР 6: регресійні тести hardening review. Пароль береться зі змінної SeedUsers__Password
// і ніде не друкується; значення токенів і cookie не друкуються.
public sealed class Lab06RegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string Header = AntiforgeryEndpoints.HeaderName;

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

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
        // Сервер повертає лише дозволений метод GET; браузер порівнює його із запитаним POST
        // і не надсилає cross-origin POST.
        Assert.Equal("GET", string.Join(",", preflight.Headers.GetValues("Access-Control-Allow-Methods")));
        Assert.DoesNotContain("POST", string.Join(",", preflight.Headers.GetValues("Access-Control-Allow-Methods")));
    }

    // REG-CSRF-01: login/cookie -> відмова без токена -> незмінний стан -> невалідний токен і
    // токен іншого користувача відхилено -> валідний токен -> успіх -> змінений стан.
    // Маршрут: PUT /api/incidents/{id} (оновлення власного інциденту Alice).
    [Fact]
    public async Task REG_CSRF_01_Update_RequiresValidAntiforgeryToken_AndKeepsStateOnRejection()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var originalTitle = $"REG-CSRF-01-{Guid.NewGuid():N}";
        var id = await CreateOwnIncidentAsync(alice, originalTitle);
        var aliceToken = alice.DefaultRequestHeaders.GetValues(Header).Single();
        var newTitle = $"REG-CSRF-01-changed-{Guid.NewGuid():N}";
        var update = new { title = newTitle, description = "Зміна після валідного токена." };

        try
        {
            // 1. Cookie сесії є, токена немає.
            alice.DefaultRequestHeaders.Remove(Header);
            using (var noToken = await alice.PutAsJsonAsync($"/api/incidents/{id}", update))
            {
                await AssertCsrfRejectedAsync(noToken);
            }
            Assert.Equal(originalTitle, await ReadTitleAsync(alice, id));

            // 2. Невалідний токен.
            alice.DefaultRequestHeaders.Add(Header, "not-a-valid-antiforgery-token");
            using (var invalid = await alice.PutAsJsonAsync($"/api/incidents/{id}", update))
            {
                await AssertCsrfRejectedAsync(invalid);
            }
            alice.DefaultRequestHeaders.Remove(Header);
            Assert.Equal(originalTitle, await ReadTitleAsync(alice, id));

            // 3. Справжній токен іншого користувача (Bob) з cookie Alice.
            using var bob = await factory.LoginAsync("bob", StudyPassword);
            var bobToken = bob.DefaultRequestHeaders.GetValues(Header).Single();
            alice.DefaultRequestHeaders.Add(Header, bobToken);
            using (var foreign = await alice.PutAsJsonAsync($"/api/incidents/{id}", update))
            {
                await AssertCsrfRejectedAsync(foreign);
            }
            alice.DefaultRequestHeaders.Remove(Header);
            Assert.Equal(originalTitle, await ReadTitleAsync(alice, id));

            // 4. Валідна пара токенів Alice: зміна проходить.
            alice.DefaultRequestHeaders.Add(Header, aliceToken);
            using (var valid = await alice.PutAsJsonAsync($"/api/incidents/{id}", update))
            {
                Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
            }
            Assert.Equal(newTitle, await ReadTitleAsync(alice, id));
        }
        finally
        {
            alice.DefaultRequestHeaders.Remove(Header);
            alice.DefaultRequestHeaders.Add(Header, aliceToken);
            using var cleanup = await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    // REG-CSRF-02: кожен cookie-автентифікований змінювальний маршрут без токена дає 400,
    // а стан не змінюється (create, update, delete, triage, logout).
    [Fact]
    public async Task REG_CSRF_02_AllCookieMutations_WithoutToken_Return400_AndKeepState()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var title = $"REG-CSRF-02-{Guid.NewGuid():N}";
        var id = await CreateOwnIncidentAsync(alice, title);
        var aliceToken = alice.DefaultRequestHeaders.GetValues(Header).Single();
        alice.DefaultRequestHeaders.Remove(Header);
        morgan.DefaultRequestHeaders.Remove(Header);

        try
        {
            // POST /api/incidents: новий інцидент не створено.
            var notCreatedTitle = $"REG-CSRF-02-create-{Guid.NewGuid():N}";
            using (var create = await alice.PostAsJsonAsync("/api/incidents", NewIncident(notCreatedTitle)))
            {
                await AssertCsrfRejectedAsync(create);
            }
            var list = await alice.GetFromJsonAsync<JsonArray>("/api/incidents");
            Assert.DoesNotContain(list!, item => item!["title"]!.GetValue<string>() == notCreatedTitle);

            // PUT /api/incidents/{id}: заголовок не змінився.
            using (var put = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                       new { title = "changed", description = "changed" }))
            {
                await AssertCsrfRejectedAsync(put);
            }
            Assert.Equal(title, await ReadTitleAsync(alice, id));

            // POST /api/incidents/{id}/triage (Analyst): статус лишився New.
            using (var triage = await morgan.PostAsJsonAsync($"/api/incidents/{id}/triage",
                       new { note = "REG-CSRF-02" }))
            {
                await AssertCsrfRejectedAsync(triage);
            }
            Assert.Equal("New", (await ReadDetailsAsync(alice, id))["status"]!.GetValue<string>());

            // DELETE /api/incidents/{id}: інцидент існує.
            using (var delete = await alice.DeleteAsync($"/api/incidents/{id}"))
            {
                await AssertCsrfRejectedAsync(delete);
            }
            Assert.Equal(title, await ReadTitleAsync(alice, id));

            // POST /api/auth/logout: сесія чинна.
            using (var logout = await alice.PostAsync("/api/auth/logout", content: null))
            {
                await AssertCsrfRejectedAsync(logout);
            }
            using var me = await alice.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        }
        finally
        {
            alice.DefaultRequestHeaders.Add(Header, aliceToken);
            using var cleanup = await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    private static object NewIncident(string title) => new
    {
        title,
        description = "Синтетичний інцидент ЛР 6.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    private static async Task<Guid> CreateOwnIncidentAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", NewIncident(title));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        return Guid.Parse(body!["id"]!.GetValue<string>());
    }

    private static async Task<JsonObject> ReadDetailsAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonObject>())!;
    }

    private static async Task<string> ReadTitleAsync(HttpClient client, Guid id) =>
        (await ReadDetailsAsync(client, id))["title"]!.GetValue<string>();

    private static async Task AssertCsrfRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("Antiforgery token is missing or invalid.", problem!["title"]!.GetValue<string>());
    }
}