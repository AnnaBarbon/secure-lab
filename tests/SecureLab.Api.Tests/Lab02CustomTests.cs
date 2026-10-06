using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02CustomTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    // T-01: Коректне створення інциденту (201 Created)
    [Fact]
    public async Task T01_CreateIncident_ValidData_Returns201Created()
    {
        var title = $"T01-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Коректний опис для тесту T-01 достатньої довжини.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            Assert.Equal(title, doc.RootElement.GetProperty("title").GetString());
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(i => i.Title == title).ExecuteDeleteAsync();
        }
    }

    // T-02: Відхилення некоректного DTO (400 Bad Request із валідаційними помилками)
    [Fact]
    public async Task T02_CreateIncident_EmptyTitleAndInvalidSeverity_Returns400()
    {
        var body = new
        {
            title = "",
            description = "Тестовий опис для перевірки валідації DTO.",
            severity = "SuperCriticalInvalid",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var errors = doc.RootElement.GetProperty("errors");
        
        Assert.True(errors.TryGetProperty("title", out _));
        Assert.True(errors.TryGetProperty("severity", out _));
    }

    // T-03: Предметний конфлікт при спробі створити незакритий дублікат за назвою (409 Conflict)
    [Fact]
    public async Task T03_CreateIncident_DuplicateActiveTitle_Returns409Conflict()
    {
        var title = $"T03-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Перший тестовий опис інциденту для перевірки конфлікту.",
            severity = "Medium",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
        };

        try
        {
            // Створюємо перший інцидент зі статусом New
            using var firstResponse = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

            // Спроба створити другий інцидент з тим самим title
            using var duplicateResponse = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, duplicateResponse.StatusCode);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(i => i.Title == title).ExecuteDeleteAsync();
        }
    }

    // S-02: Безпечний retest SQLi: контрольний ввід C повертає [] (Assert.Empty),
    // а позитивний контроль q=USB повертає рівно один запис (Assert.Single)
    [Fact]
    public async Task S02_RetestSqlInjection_ReturnsEmpty_AndPositiveControlPasses()
    {
        // 1. Контрольний запит C (SQLi вектор). Очікуємо 200 OK та порожню вибірку
        var sqliQuery = "zz-no-match' OR TRUE -- ";
        var sqliUrl = "/api/incidents/search?q=" + Uri.EscapeDataString(sqliQuery);

        var sqliResults = await _client.GetFromJsonAsync<List<SearchIncidentResponse>>(sqliUrl);
        Assert.NotNull(sqliResults);
        Assert.Empty(sqliResults);

        // 2. Позитивний контроль: q=USB повинен повернути рівно один запис (Id ...0005)
        var positiveUrl = "/api/incidents/search?q=USB";
        var positiveResults = await _client.GetFromJsonAsync<List<SearchIncidentResponse>>(positiveUrl);
        Assert.NotNull(positiveResults);
        var incident = Assert.Single(positiveResults);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), incident.Id);
    }

    // T-04: Пошук з легітимним апострофом повертає 200 OK і очікувані сутності
    [Fact]
    public async Task T04_Search_WithApostrophes_Returns200AndExpectedEntities()
    {
        // Перевірка O'Brien
        var obrienUrl = "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");
        var obrienResults = await _client.GetFromJsonAsync<List<SearchIncidentResponse>>(obrienUrl);
        Assert.NotNull(obrienResults);
        Assert.Single(obrienResults);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000004"), obrienResults[0].Id);

        // Перевірка українського апострофа U+0027
        var ukrUrl = "/api/incidents/search?q=" + Uri.EscapeDataString("комп'ютерного");
        var ukrResults = await _client.GetFromJsonAsync<List<SearchIncidentResponse>>(ukrUrl);
        Assert.NotNull(ukrResults);
        Assert.Single(ukrResults);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000003"), ukrResults[0].Id);
    }

    // T-05: Сортування за невідомим полем повертає 400 із ключем sortBy
    [Fact]
    public async Task T05_Search_UnknownSortBy_Returns400WithSortByKey()
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=price");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var errors = doc.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("sortBy", out _));
    }

    // T-10: Додаткове предметне правило: occurredAtUtc не раніше ніж за 365 днів -> 400
    [Fact]
    public async Task T10_CreateIncident_OccurredAtUtcTooOld_Returns400()
    {
        var body = new
        {
            title = $"T10-{Guid.NewGuid():N}",
            description = "Опис інциденту з надто давньою датою виникнення.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-366) // старше за 365 днів
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var errors = doc.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
    }

    // A-02: Захист від Overposting (Mass Assignment):
    // Передача полів id, status, ownerUserId і перевірка, що сервер призначає власні значення
    [Fact]
    public async Task A02_CreateIncident_OverpostingIgnored_ServerValuesEnforced()
    {
        var title = $"A02-{Guid.NewGuid():N}";
        var fakeId = Guid.NewGuid();
        var fakeOwner = Guid.NewGuid();

        // Спроба підмінити серверні поля id, status (на Closed), createdAtUtc, ownerUserId
        var body = new
        {
            id = fakeId,
            title,
            description = "Перевірка захисту від overposting/mass assignment для A-02.",
            severity = "Low",
            status = "Closed",
            createdAtUtc = DateTimeOffset.UtcNow.AddDays(-10),
            ownerUserId = fakeOwner,
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            
            var createdId = doc.RootElement.GetProperty("id").GetGuid();
            var createdStatus = doc.RootElement.GetProperty("status").GetString();

            // Сервер мав згенерувати свій GUID і статус New
            Assert.NotEqual(fakeId, createdId);
            Assert.Equal("New", createdStatus);

            // Перевіряємо напряму в БД призначення власника Alice
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var saved = await db.Incidents.SingleAsync(i => i.Title == title);

            Assert.Equal(DbSeeder.AliceId, saved.OwnerUserId);
            Assert.NotEqual(fakeOwner, saved.OwnerUserId);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(i => i.Title == title).ExecuteDeleteAsync();
        }
    }
}