using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
        .WithName("GetIncidentSeveritySummary")
        .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>(StatusCodes.Status200OK)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);
       
       group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .RequireAuthorization();
 
        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var allowedStatuses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "New",
            "Triaged",
            "Resolved"
        };

        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!allowedStatuses.Contains(status))
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["status"] = [$"Unknown status filter '{status}'. Supported values: New, Triaged, Resolved."]
                    },
                    title: "One or more validation errors occurred.",
                    statusCode: StatusCodes.Status400BadRequest);
            }
        }

        var summary = await queries.GetSeveritySummaryAsync(
            status,
            httpContext.TraceIdentifier,
            cancellationToken);

        return Results.Ok(summary);
    }
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext dbContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var title = request.Title?.Trim() ?? "";
        var description = request.Description?.Trim() ?? "";
        var errors = new Dictionary<string, string[]>();
 
        if (title.Length == 0)
        {
            errors["title"] = ["Поле title є обов'язковим."];
        }
        else if (title.Length > 160)
        {
            errors["title"] = ["Довжина title не може перевищувати 160 символів."];
        }
 
        if (description.Length == 0)
        {
            errors["description"] = ["Поле description є обов'язковим."];
        }
        else if (description.Length > 4000)
        {
            errors["description"] = ["Довжина description не може перевищувати 4000 символів."];
        }
 
        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }
 
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound);
        }
 
        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
 
        return Results.Ok(await queries.GetDetailsAsync(id, cancellationToken));
    }
 
    private static async Task<IResult> TriageAsync(
        Guid id,
        ChangeIncidentStatusRequest request,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Results.Challenge();
        }
 
        var note = request.Note?.Trim() ?? "";
        if (note.Length > 1000)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["note"] = ["Довжина note не може перевищувати 1000 символів."]
            });
        }
 
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound);
        }
 
        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Недопустимий перехід статусу",
                detail: "Triage можливий лише для інциденту зі статусом New.",
                statusCode: StatusCodes.Status409Conflict);
        }
 
        var now = DateTimeOffset.UtcNow;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = userId,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = note.Length == 0 ? "Первинну оцінку виконано." : note,
            CreatedAtUtc = now
        });
        await dbContext.SaveChangesAsync(cancellationToken);
 
        return Results.Ok(new IncidentStatusChangedResponse(incident.Id, incident.Status.ToString()));
    }
}
