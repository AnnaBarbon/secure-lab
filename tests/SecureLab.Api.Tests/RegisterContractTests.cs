using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecureLab.Api.Tests;

public sealed class RegisterContractTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    // Нове ім'я для кожного запуску, щоб повторний запуск на тій самій БД не дав дублікат.
    private static string NewUserName() => "reg" + Guid.NewGuid().ToString("N")[..8];

    // Пароль формується локально, відповідає вимогам Identity і ніде не друкується.
    private static string NewPassword() => "Rg-" + Guid.NewGuid().ToString("N")[..10] + "a7!";

    private static readonly string[] ForbiddenFields =
        ["password", "confirmPassword", "passwordHash", "securityStamp", "cookie", "token"];

    // T-01: коректна реєстрація -> 201 і лише дозволені поля відповіді.
    [Fact]
    public async Task T01_ValidRegistration_Returns201WithSafeFieldsOnly()
    {
        using var client = factory.CreateClient();
        var userName = NewUserName();

        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = userName + "@example.test",
            displayName = "Студент 01",
            password = NewPassword()
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var names = document.RootElement.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(userName, document.RootElement.GetProperty("userName").GetString());
        foreach (var forbidden in ForbiddenFields)
        {
            Assert.DoesNotContain(names, name => string.Equals(name, forbidden, StringComparison.OrdinalIgnoreCase));
        }
    }

    // Добрий рівень: послідовний duplicate-контракт — ім'я чи email уже зайняті -> однакова 409.
    [Fact]
    public async Task T02_DuplicateUserNameOrEmail_ReturnsSame409()
    {
        using var client = factory.CreateClient();
        var userName = NewUserName();
        var otherName = NewUserName();
        var email = userName + "@example.test";

        using var first = await client.PostAsJsonAsync("/api/auth/register",
            new { userName, email, displayName = "Перший", password = NewPassword() });
        using var sameName = await client.PostAsJsonAsync("/api/auth/register",
            new { userName, email = otherName + "@example.test", displayName = "Другий", password = NewPassword() });
        using var sameEmail = await client.PostAsJsonAsync("/api/auth/register",
            new { userName = otherName, email, displayName = "Третій", password = NewPassword() });

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameName.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
        Assert.Equal("application/problem+json", sameName.Content.Headers.ContentType?.MediaType);

        // Відповідь однакова й не розкриває, яке саме поле збіглося.
        using var nameProblem = JsonDocument.Parse(await sameName.Content.ReadAsStringAsync());
        using var emailProblem = JsonDocument.Parse(await sameEmail.Content.ReadAsStringAsync());
        Assert.Equal(nameProblem.RootElement.GetProperty("detail").GetString(),
            emailProblem.RootElement.GetProperty("detail").GetString());
    }

    // Межа з моделі: displayName зі 121 символу -> 400 з полем displayName, а не 500 від БД.
    [Fact]
    public async Task Register_DisplayNameLongerThan120_Returns400()
    {
        using var client = factory.CreateClient();
        var userName = NewUserName();

        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = userName + "@example.test",
            displayName = new string('Д', 121),
            password = NewPassword()
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("displayName", out _));
    }

    // Зайві поля role та id ігноруються: після входу роль — Reporter, яку призначив сервер.
    [Fact]
    public async Task Register_WithExtraRoleAndId_IgnoresThem()
    {
        using var client = factory.CreateClient();
        var userName = NewUserName();
        var password = NewPassword();
        var forgedId = Guid.NewGuid();

        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = userName + "@example.test",
            displayName = "Спроба зайвих полів",
            password,
            role = "Administrator",
            id = forgedId
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var created = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.NotEqual(forgedId, created.RootElement.GetProperty("id").GetGuid());

        using var newUser = await factory.LoginAsync(userName, password);
        using var me = await newUser.GetAsync("/api/me");
        using var profile = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.Equal("Reporter", profile.RootElement.GetProperty("role").GetString());
    }
}