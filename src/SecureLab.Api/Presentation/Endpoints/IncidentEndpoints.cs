using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
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
            .WithTags("Incidents")
            .RequireAuthorization();

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
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .AddEndpointFilter<AntiforgeryEndpointFilter>();

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .AddEndpointFilter<AntiforgeryEndpointFilter>();

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces<IncidentStatusChangedResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .AddEndpointFilter<AntiforgeryEndpointFilter>();

        // ЛР 4: child resource; доступ перевіряється через parent incident.
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        return endpoints;
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
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

        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var ownerId))
        {
            return Results.Challenge();
        }

        var canReadAll = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        return Results.Ok(await queries.GetListAsync(parsedStatus, ownerId, canReadAll, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canReadInternal = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.ReadInternalComments);

        var details = await queries.GetDetailsAsync(id, canReadInternal.Succeeded, cancellationToken);
        return details is null ? IncidentNotFound() : Results.Ok(details);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var ownerId))
        {
            return Results.Challenge();
        }

        var canReadAll = httpContext.User.IsInRole(DbSeeder.AnalystRole);

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
            ownerId,
            canReadAll,
            httpContext.TraceIdentifier,
            cancellationToken);

        return Results.Ok(summary);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canUpdate = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            return Results.Forbid();
        }

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

        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        var canReadInternal = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.ReadInternalComments);
        return Results.Ok(await queries.GetDetailsAsync(id, canReadInternal.Succeeded, cancellationToken));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            return Results.Forbid();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        ChangeIncidentStatusRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Results.Challenge();
        }

        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            LogTriageDenied(logger, httpContext, userId, incident.Id);
            return IncidentNotFound();
        }

        var canTriage = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            LogTriageDenied(logger, httpContext, userId, incident.Id);
            return Results.Forbid();
        }

        var note = request.Note?.Trim() ?? "";
        if (note.Length > 1000)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["note"] = ["Довжина note не може перевищувати 1000 символів."]
            });
        }

        // Поточний status читається з БД, наступний встановлює сервер.
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

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Include(item => item.Incident)
            .Include(item => item.Author)
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (comment is null)
        {
            return CommentNotFound();
        }

        // Спершу право читати parent incident; чужий коментар — той самий 404.
        var canReadParent = await authorizationService.AuthorizeAsync(
            httpContext.User, comment.Incident, IncidentOperations.Read);
        if (!canReadParent.Succeeded)
        {
            return CommentNotFound();
        }

        if (comment.IsInternal)
        {
            var canReadInternal = await authorizationService.AuthorizeAsync(
                httpContext.User, comment.Incident, IncidentOperations.ReadInternalComments);
            if (!canReadInternal.Succeeded)
            {
                return CommentNotFound();
            }
        }

        return Results.Ok(new IncidentCommentDetailsResponse(
            comment.Id,
            comment.IncidentId,
            comment.Author.DisplayName,
            comment.Text,
            comment.IsInternal,
            comment.CreatedAtUtc));
    }

    // ЛР 4: audit denied privileged action. Лише серверні значення:
    // subject з principal, action, resource id, result, серверний час і trace id відповіді.
    private static void LogTriageDenied(
        ILogger<Program> logger,
        HttpContext httpContext,
        Guid subjectId,
        Guid incidentId)
    {
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} "
            + "resource={ResourceId} result={Result} "
            + "occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            subjectId,
            "incident.triage",
            incidentId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }

    
}