using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

/// ЛР 04: authorization test matrix A-01…A-12 через HTTP boundary.
/// Один користувач — один клієнт зі своєю cookie. Пароль береться зі змінної
/// SeedUsers__Password і ніде не друкується. Для mutation негативний тест читає стан
/// до й після запиту дозволеним клієнтом. Позитивні mutation працюють лише з інцидентом,
/// який тест створив сам, і прибирають його у finally.
public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid AliceNewIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000003");
    private static readonly Guid BobSearchIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid BobCommentId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid AliceInternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private const string InternalCommentText = "Внутрішня нотатка аналітика";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private Task<HttpClient> LoginAsync(string userName) => factory.LoginAsync(userName, StudyPassword);

    // Створює власний інцидент від імені клієнта; owner/status/id визначає сервер.
    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string prefix)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"{prefix}-{Guid.NewGuid():N}",
            description = "Синтетичний інцидент для тесту авторизації ЛР 04.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        return Guid.Parse(body!["id"]!.GetValue<string>());
    }

    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }

    private static async Task<JsonObject> ReadDetailsAsync(HttpClient client, Guid id)
    {
        var details = await client.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
        Assert.NotNull(details);
        return details;
    }

    // A-01: анонімний запит до protected details — 401, без HTML redirect.
    [Fact]
    public async Task A01_Details_AsAnonymous_Returns401_WithoutRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await anonymous.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: Alice читає власний інцидент.
    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(DbSeeder.AliceIncidentId.ToString(), body!["id"]!.GetValue<string>());
    }

    // A-03: Alice підставляє id Bob — 404, дані Bob не потрапляють у відповідь.
    [Fact]
    public async Task A03_Details_AsNonOwner_ReturnsNotFound_WithoutForeignData()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Невідома спроба входу", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Боб Мельник", text, StringComparison.Ordinal);
    }

    // A-03R: Analyst читає інцидент Alice для аналізу (entry-контракт ЛР 5).
    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsIncidentOfAlice()
    {
        using var morgan = await LoginAsync("morgan");

        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("Аліса Коваль", body!["ownerDisplayName"]!.GetValue<string>());
    }

    // A-03R (межа): право читання не дає Analyst права змінювати вміст.
    [Fact]
    public async Task A03R_Update_AsAnalyst_ReturnsForbidden_AndDoesNotChangeIncident()
    {
        using var morgan = await LoginAsync("morgan");
        var before = await ReadDetailsAsync(morgan, DbSeeder.AliceIncidentId);

        using var response = await morgan.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "Змінено Analyst", description = "Analyst не має права змінювати вміст." });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await ReadDetailsAsync(morgan, DbSeeder.AliceIncidentId);
        Assert.Equal(before["title"]!.GetValue<string>(), after["title"]!.GetValue<string>());
        Assert.Equal(before["description"]!.GetValue<string>(), after["description"]!.GetValue<string>());
    }

    // A-04: Alice не може змінити інцидент Bob; стан Bob без змін.
    [Fact]
    public async Task A04_Update_AsNonOwner_ReturnsNotFound_AndDoesNotChangeIncident()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        var before = await ReadDetailsAsync(bob, DbSeeder.BobIncidentId);

        using var response = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "Змінено Alice", description = "Alice намагається змінити чужий інцидент." });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        // Стан читає власник Bob, бо Alice цього ресурсу не бачить.
        var after = await ReadDetailsAsync(bob, DbSeeder.BobIncidentId);
        Assert.Equal(before["title"]!.GetValue<string>(), after["title"]!.GetValue<string>());
        Assert.Equal(before["description"]!.GetValue<string>(), after["description"]!.GetValue<string>());
    }

    // A-04: Alice не може видалити інцидент Bob; інцидент лишається.
    [Fact]
    public async Task A04_Delete_AsNonOwner_ReturnsNotFound_AndIncidentStillExists()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");

        using var response = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var after = await bob.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
    }

    // A-04 (позитивна регресія): власник видаляє власний New-інцидент.
    [Fact]
    public async Task A04_Delete_AsOwnerOfNewIncident_ReturnsNoContent()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A04-delete");
        try
        {
            using var response = await alice.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            using var after = await alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-05: список Alice не містить чужих записів.
    [Fact]
    public async Task A05_List_AsAlice_ContainsOnlyOwnIncidents()
    {
        using var alice = await LoginAsync("alice");

        var list = await alice.GetFromJsonAsync<JsonArray>("/api/incidents");

        Assert.NotNull(list);
        var ids = list.Select(item => Guid.Parse(item!["id"]!.GetValue<string>())).ToList();
        Assert.Contains(DbSeeder.AliceIncidentId, ids);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, ids);
        Assert.DoesNotContain(BobSearchIncidentId, ids);
    }

    // A-06: Reporter не може виконати privileged transition; status не змінився.
    [Fact]
    public async Task A06_Triage_AsReporterOwner_ReturnsForbidden_AndStatusUnchanged()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A06");
        try
        {
            // Поля role/isTransitionAllowed у body не є input авторизації.
            using var response = await alice.PostAsJsonAsync($"/api/incidents/{id}/triage",
                new { note = "Спроба Reporter", role = "Analyst", isTransitionAllowed = true });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var after = await ReadDetailsAsync(alice, id);
            Assert.Equal("New", after["status"]!.GetValue<string>());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-07: Analyst виконує дозволений перехід New → Triaged; next status визначає сервер.
    [Fact]
    public async Task A07_Triage_AsAnalyst_OnNewIncident_SetsTriaged()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var id = await CreateIncidentAsync(alice, "A07");
        try
        {
            using var response = await morgan.PostAsJsonAsync($"/api/incidents/{id}/triage",
                new { note = "Первинну оцінку виконано аналітиком." });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var after = await ReadDetailsAsync(alice, id);
            Assert.Equal("Triaged", after["status"]!.GetValue<string>());

            // Повторний перехід уже не з New — 409, роль не обходить правило стану.
            using var repeat = await morgan.PostAsJsonAsync($"/api/incidents/{id}/triage",
                new { note = "Повторна спроба." });
            Assert.Equal(HttpStatusCode.Conflict, repeat.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-08a: звичайний update ігнорує forged owner/role/status/severity;
    // змінюється лише дозволений content.
    [Fact]
    public async Task A08a_Update_WithForgedFields_ChangesOnlyContent()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A08a");
        try
        {
            var newTitle = $"A08a-updated-{Guid.NewGuid():N}";
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = newTitle,
                description = "Оновлений опис після перевірки контракту.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                severity = "Critical",
                role = "Administrator"
            });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var after = await ReadDetailsAsync(alice, id);
            Assert.Equal(newTitle, after["title"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
            Assert.Equal("Low", after["severity"]!.GetValue<string>());
            Assert.Equal("Аліса Коваль", after["ownerDisplayName"]!.GetValue<string>());

            // Owner не змінився: Bob цей інцидент не бачить.
            using var bob = await LoginAsync("bob");
            using var bobRead = await bob.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, bobRead.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-09: відмова privileged action записує безпечну audit-подію з тим самим trace id.
    [Fact]
    public async Task A09_DeniedTriage_WritesSafeAuditEvent_WithResponseTraceId()
    {
        var provider = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ILoggerProvider>(provider)));
        using var alice = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        using (var login = await alice.PostAsJsonAsync("/api/auth/login",
                   new { userName = "alice", password = StudyPassword }))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        using var response = await alice.PostAsJsonAsync($"/api/incidents/{AliceNewIncidentId}/triage",
            new { note = "Спроба Reporter" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        var responseTraceId = problem!["traceId"]!.GetValue<string>();

        var audit = Assert.Single(provider.Entries,
            entry => entry.Message.StartsWith("authorization.denied", StringComparison.Ordinal));
        Assert.Equal(DbSeeder.AliceId.ToString(), audit.Properties["SubjectId"]);
        Assert.Equal("incident.triage", audit.Properties["Action"]);
        Assert.Equal(AliceNewIncidentId.ToString(), audit.Properties["ResourceId"]);
        Assert.Equal("denied", audit.Properties["Result"]);
        Assert.Equal(responseTraceId, audit.Properties["TraceId"]);
        Assert.DoesNotContain(StudyPassword, audit.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Спроба Reporter", audit.Message, StringComparison.Ordinal);
    }

    // A-10: відповідь для чужого й неіснуючого id однакова (крім traceId).
    [Fact]
    public async Task A10_ForeignAndUnknownDetails_ReturnSameProblemDetails()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignBody = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        foreignBody!.Remove("traceId");
        unknownBody!.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    // A-11: search не повертає Alice чужих записів; Analyst бачить усю множину.
    [Fact]
    public async Task A11_Search_AsAlice_DoesNotReturnForeignIncidents()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var query = "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");

        var aliceResults = await alice.GetFromJsonAsync<JsonArray>(query);
        var analystResults = await morgan.GetFromJsonAsync<JsonArray>(query);

        Assert.NotNull(aliceResults);
        Assert.Empty(aliceResults);
        Assert.NotNull(analystResults);
        var analystItem = Assert.Single(analystResults);
        Assert.Equal(BobSearchIncidentId.ToString(), analystItem!["id"]!.GetValue<string>());
    }

    // A-11: severity-summary рахує лише інциденти Alice (High є тільки в Bob).
    [Fact]
    public async Task A11_SeveritySummary_AsAlice_CountsOnlyOwnIncidents()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        var aliceSummary = await alice.GetFromJsonAsync<JsonArray>("/api/incidents/severity-summary");
        var analystSummary = await morgan.GetFromJsonAsync<JsonArray>("/api/incidents/severity-summary");

        Assert.NotNull(aliceSummary);
        Assert.NotNull(analystSummary);
        var aliceSeverities = aliceSummary.Select(item => item!["severity"]!.GetValue<string>()).ToList();
        var analystSeverities = analystSummary.Select(item => item!["severity"]!.GetValue<string>()).ToList();
        Assert.DoesNotContain("High", aliceSeverities);
        Assert.Contains("Medium", aliceSeverities);
        Assert.Contains("High", analystSeverities);
    }

    // A-11: анонім не отримує search і severity-summary.
    [Fact]
    public async Task A11_SearchAndSummary_AsAnonymous_Return401()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var search = await anonymous.GetAsync("/api/incidents/search?q=O");
        using var summary = await anonymous.GetAsync("/api/incidents/severity-summary");

        Assert.Equal(HttpStatusCode.Unauthorized, search.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, summary.StatusCode);
    }

    // A-12: коментар до інциденту Bob за прямим id — 404 для Alice.
    [Fact]
    public async Task A12_Comment_OfForeignIncident_ReturnsNotFoundForReporter()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incident-comments/{BobCommentId}");
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("журналу автентифікації", text, StringComparison.Ordinal);
    }

    // A-12: internal comment не потрапляє у відповідь Reporter-власнику ні за id, ні в details.
    [Fact]
    public async Task A12_InternalComment_IsHiddenFromReporterOwner()
    {
        using var alice = await LoginAsync("alice");

        using var direct = await alice.GetAsync($"/api/incident-comments/{AliceInternalCommentId}");
        using var details = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var detailsText = await details.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, direct.StatusCode);
        Assert.Equal(HttpStatusCode.OK, details.StatusCode);
        Assert.DoesNotContain(InternalCommentText, detailsText, StringComparison.Ordinal);
    }

    // A-12: Analyst бачить internal comment після перевірки parent incident.
    [Fact]
    public async Task A12_InternalComment_IsVisibleToAnalyst()
    {
        using var morgan = await LoginAsync("morgan");

        using var direct = await morgan.GetAsync($"/api/incident-comments/{AliceInternalCommentId}");
        using var details = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);
        var body = await direct.Content.ReadFromJsonAsync<JsonObject>();
        Assert.True(body!["isInternal"]!.GetValue<bool>());
        Assert.Contains(InternalCommentText, await details.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private sealed record CapturedLog(string Message, IReadOnlyDictionary<string, string?> Properties);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<CapturedLog> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<CapturedLog> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var properties = new Dictionary<string, string?>(StringComparer.Ordinal);
                if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
                {
                    foreach (var pair in pairs)
                    {
                        properties[pair.Key] = Convert.ToString(pair.Value, CultureInfo.InvariantCulture);
                    }
                }

                entries.Enqueue(new CapturedLog(formatter(state, exception), properties));
            }
        }
    }
}