using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // (UserName/Email varchar(256), DisplayName varchar(120)). Нормалізуємо лише Trim
            // для userName, email, displayName; password не змінюємо, не логуємо й не повертаємо.
            var userName = input.UserName?.Trim() ?? string.Empty;
            var email = input.Email?.Trim() ?? string.Empty;
            var displayName = input.DisplayName?.Trim() ?? string.Empty;
            var errors = new Dictionary<string, string[]>();

            if (userName.Length == 0)
                errors["userName"] = ["Поле userName є обов'язковим."];
            else if (userName.Length > 256)
                errors["userName"] = ["userName не може бути довшим за 256 символів."];

            if (email.Length == 0)
                errors["email"] = ["Поле email є обов'язковим."];
            else if (email.Length > 256)
                errors["email"] = ["email не може бути довшим за 256 символів."];

            if (displayName.Length == 0)
                errors["displayName"] = ["Поле displayName є обов'язковим."];
            else if (displayName.Length > 120)
                errors["displayName"] = ["displayName не може бути довшим за 120 символів."];

            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Поле password є обов'язковим."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // PasswordHash не обчислюємо самі: UserManager перевіряє вимоги до пароля,
            // хешує його стандартним PasswordHasher і зберігає користувача.
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = userName, Email = email, DisplayName = displayName
            };
            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();

                // Контракт duplicate: зайняте ім'я і зайнятий email дають одну й ту саму 409,
                // не уточнюючи, яке саме поле збіглося.
                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                    return Results.Problem(statusCode: StatusCodes.Status409Conflict,
                        title: "Registration conflict",
                        detail: "Обліковий запис із таким ім'ям користувача або email уже існує.");

                // Решта відмов — 400 з назвою поля; текст формує сервер, значення полів не повертаються.
                var identityErrors = new Dictionary<string, string[]>();
                if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
                    identityErrors["password"] = ["Пароль не відповідає вимогам: щонайменше 10 символів, "
                        + "велика й мала латинські літери, цифра та символ, що не є літерою чи цифрою."];
                if (codes.Contains("InvalidUserName"))
                    identityErrors["userName"] = ["userName може містити лише латинські літери, цифри та -._@+"];
                if (codes.Contains("InvalidEmail"))
                    identityErrors["email"] = ["email має бути коректною адресою."];
                if (identityErrors.Count == 0)
                    identityErrors["registration"] = ["Реєстрацію відхилено."];
                return Results.ValidationProblem(identityErrors);
            }

            // Роль призначає сервер; у request DTO поля ролі немає.
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new RegistrationResponse(user.Id, userName, displayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
        HttpContext httpContext, ILogger<Program> logger) =>
        {
            // Подія автентифікації містить лише тип, результат, id користувача після успішної 
            // перевірки та trace id. Password, введене ім'я при невдалій спробі, cookie, hash, 
            // token і тіло запиту туди не потрапляють.
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogWarning("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                    "login", "failed", "anonymous", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var user = await signIn.UserManager.FindByNameAsync(input.UserName);
            if (user is null)
            {
                // Усунутий auth defect: без цього невідоме ім'я відповідало швидше (без PBKDF2),
                // і за часом можна було визначити, чи існує акаунт. Виконуємо ту саму роботу
                // стандартного hasher над фіктивним hash і повертаємо той самий 401.
                _ = signIn.UserManager.PasswordHasher.VerifyHashedPassword(
                    TimingDummyUser, TimingDummyHash.Value, input.Password);
                logger.LogWarning("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                    "login", "failed", "anonymous", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(user, input.Password, false, false);
            if (!result.Succeeded)
            {
                // Однаковий 401 для невідомого користувача і хибного пароля; причину не розкриваємо.
                logger.LogWarning("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                    "login", "failed", "anonymous", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var userRef = user.Id.ToString();
            logger.LogInformation("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                "login", "succeeded", userRef, httpContext.TraceIdentifier);
            return Results.NoContent();
        }).RequireRateLimiting("login");
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn,
        HttpContext httpContext, ILogger<Program> logger) =>
        {
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
            await signIn.SignOutAsync();
            logger.LogInformation("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                "logout", "succeeded", userId, httpContext.TraceIdentifier);
            return Results.NoContent();
        });
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
        // Фіктивний користувач і hash стандартного формату Identity з випадковим паролем:
    // використовуються лише для однакової роботи hasher при невідомому імені, збігу бути не може.
    private static readonly ApplicationUser TimingDummyUser = new() { DisplayName = "timing-dummy" };

    private static readonly Lazy<string> TimingDummyHash = new(() =>
        new PasswordHasher<ApplicationUser>().HashPassword(
            TimingDummyUser, "Td-" + Guid.NewGuid().ToString("N") + "-9z"));
    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new CurrentUserResponse(verifiedUserId, userName, role));
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record CurrentUserResponse(Guid UserId, string UserName, string Role);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);