using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Presentation.Endpoints;

// ЛР 6: CSRF-захист для JSON-маршрутів, автентифікованих cookie. Браузер надсилає cookie
// автоматично, тому змінювальний запит приймається лише з request token у заголовку X-CSRF-TOKEN,
// який може прочитати лише same-origin JavaScript клієнта.
public static class AntiforgeryEndpoints
{
    public const string HeaderName = "X-CSRF-TOKEN";

    public static IEndpointRouteBuilder MapAntiforgeryToken(this IEndpointRouteBuilder endpoints)
    {
        // Видача пари: cookie-частина йде в Set-Cookie (HttpOnly), request token — у JSON.
        endpoints.MapGet("/api/auth/csrf-token", (IAntiforgery antiforgery, HttpContext httpContext) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            return Results.Ok(new { token = tokens.RequestToken });
        })
        .WithName("GetCsrfToken")
        .RequireAuthorization();

        return endpoints;
    }
}

// Єдине місце валідації: однаковий 400 Problem Details для відсутнього або невалідного токена.
// Фільтр виконується після authentication/authorization і до логіки маршруту, тому ресурс не змінюється.
public sealed class AntiforgeryEndpointFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                title: "Antiforgery token is missing or invalid.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}