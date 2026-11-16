using System.Threading.RateLimiting;
using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();

builder.Services.AddSingleton<IAuthorizationHandler, IncidentAuthorizationHandler>();

builder.AddLab03Identity();

// ЛР 6: antiforgery для cookie-автентифікованих змінювальних запитів.
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = AntiforgeryEndpoints.HeaderName;
    options.Cookie.Name = "securelab.antiforgery";
});

// Обмеження частоти лише для повторних спроб входу.
// Ключ групи — IP-адреса з'єднання, а не введене ім'я користувача: ключ за ім'ям дав би
// сторонньому змогу навмисно заблокувати чужий вхід; password чи email ключем не є.
// IP об'єднує користувачів за спільним NAT — це свідомий компроміс навчального in-memory limiter.
// Ліміт і вікно читаються з конфігурації (за замовчуванням 5 спроб за 60 с),
// щоб тестовий host міг задати власні значення без зміни коду.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", httpContext =>
    {
        var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = configuration.GetValue("LoginRateLimit:PermitLimit", 5),
                Window = TimeSpan.FromSeconds(configuration.GetValue("LoginRateLimit:WindowSeconds", 60)),
                QueueLimit = 0
            });
    });
});


if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                  .WithMethods("GET")
                  .WithHeaders("X-Lab-Cors-Probe")
                  .AllowCredentials();
        });
    });
}

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

var csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    + "connect-src 'self'; frame-ancestors 'none'";

// ЛР 6 (F-01): заголовки ставляться в OnStarting, а не до next(). ExceptionHandlerMiddleware
// очищає вже встановлені заголовки перед записом 500, а callback OnStarting виконується
// безпосередньо перед надсиланням будь-якої відповіді, зокрема відповіді обробника помилок.
app.Use(async (context, next) =>
{
    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");

    context.Response.OnStarting(() =>
    {
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";

        if (!isDevelopmentApiReference)
        {
            context.Response.Headers["Content-Security-Policy"] = csp;
        }

        return Task.CompletedTask;
    });

    await next(context);
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRouting();
if (app.Environment.IsDevelopment())
{
    // CORS до authentication/authorization, щоб дозволені заголовки були й на 401/403.
    app.UseCors("Lab05BrowserProbe");
}
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapAntiforgeryToken();
app.MapLab02Endpoints();
app.Map("/api/{*path}", () => Results.Problem(
    title: "API route not found",
    detail: "The requested API endpoint does not exist.",
    statusCode: StatusCodes.Status404NotFound
));
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;