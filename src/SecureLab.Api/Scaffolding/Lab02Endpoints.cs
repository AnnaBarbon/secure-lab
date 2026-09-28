using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var order = sortBy switch
            {
                null or "" or "createdAtUtc" => "created_at_utc DESC",
                "severity" => "severity", "status" => "status", _ => sortBy
            };
            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
                + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
            var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            if (string.IsNullOrWhiteSpace(request.Title))
            {
                errors["title"] = ["Поле title є обов'язковим."];
            }
            else if (request.Title.Length > 160)
            {
                errors["title"] = ["Довжина title не може перевищувати 160 символів."];
            }

            if (string.IsNullOrWhiteSpace(request.Description))
            {
                errors["description"] = ["Поле description є обов'язковим."];
            }
            else if (request.Description.Length > 4000)
            {
                errors["description"] = ["Довжина description не може перевищувати 4000 символів."];
            }

            IncidentSeverity parsedSeverity = default;
            if (string.IsNullOrWhiteSpace(request.Severity))
            {
                errors["severity"] = ["Поле severity є обов'язковим."];
            }
            else if (!Enum.TryParse<IncidentSeverity>(request.Severity, true, out parsedSeverity) 
                     || !Enum.IsDefined(typeof(IncidentSeverity), parsedSeverity))
            {
                errors["severity"] = ["Вказано неприпустиме значення severity."];
            }

            if (!request.OccurredAtUtc.HasValue)
            {
                errors["occurredAtUtc"] = ["Поле occurredAtUtc є обов'язковим."];
            }
            else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
            {
                errors["occurredAtUtc"] = ["Час occurredAtUtc не може випереджати поточний час сервера більш ніж на 5 хвилин."];
            }
            else if (request.OccurredAtUtc.Value < now.AddDays(-365))
            {
                errors["occurredAtUtc"] = ["Час occurredAtUtc не може бути давнішим ніж за 365 днів від поточного часу."];
            }

            var normalizedTitle = request.Title?.Trim() ?? "";
            var normalizedDescription = request.Description?.Trim() ?? "";

            if (!errors.ContainsKey("severity") && !errors.ContainsKey("description"))
            {
                if ((parsedSeverity == IncidentSeverity.High || parsedSeverity == IncidentSeverity.Critical) 
                    && normalizedDescription.Length < 40)
                {
                    errors["description"] = ["Для рівнів High та Critical опис після Trim() має містити щонайменше 40 символів."];
                }
            }

            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors, title: "Validation failed");
            }

            var activeStatuses = new[]
            {
                IncidentStatus.New,
                IncidentStatus.Triaged,
                IncidentStatus.InProgress,
                IncidentStatus.Resolved
            };

            var hasConflict = await db.Incidents
                .AnyAsync(i => i.Title == normalizedTitle && activeStatuses.Contains(i.Status), ct);

            if (hasConflict)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Conflict",
                    detail: "Активний інцидент із таким заголовком уже існує."
                );
            }

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = DbSeeder.AliceId,
                Title = normalizedTitle,
                Description = normalizedDescription,
                Severity = parsedSeverity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            var response = new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc
            );

            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);


public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc
);