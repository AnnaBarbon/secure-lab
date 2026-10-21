namespace SecureLab.Api.Presentation.Contracts;

public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description);

public sealed record ChangeIncidentStatusRequest(
    string? Note);

public sealed record IncidentStatusChangedResponse(
    Guid Id,
    string Status);