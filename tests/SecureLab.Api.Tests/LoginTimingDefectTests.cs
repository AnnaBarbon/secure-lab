using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

/// Поглиблення відмінного рівня: знайдений і усунений додатковий auth defect.
/// Однаковий 401 ще не означає однакову поведінку: стандартний PasswordSignInAsync(userName, ...)
/// для невідомого імені не викликає PBKDF2, тому відповідь помітно швидша, ніж для хибного пароля,
/// і за часом можна визначити, чи існує акаунт. Тест рахує виклики VerifyHashedPassword
/// детерміновано, без крихкого вимірювання часу. До виправлення: unknown = 0, wrong = 1.
public sealed class LoginTimingDefectTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task UnknownUserAndWrongPassword_RunTheSameHashVerificationWork()
    {
        var counter = new VerifyCounter();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton(counter);
                services.AddScoped<IPasswordHasher<ApplicationUser>, CountingPasswordHasher>();
            }));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        var wrongPassword = StudyPassword + "-wrong";

        var beforeUnknown = counter.Value;
        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "ghost" + Guid.NewGuid().ToString("N")[..8], password = StudyPassword });
        var unknownVerifications = counter.Value - beforeUnknown;

        var beforeWrong = counter.Value;
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = wrongPassword });
        var wrongVerifications = counter.Value - beforeWrong;

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(1, wrongVerifications);
        Assert.Equal(wrongVerifications, unknownVerifications);
    }

    public sealed class VerifyCounter
    {
        private int _value;

        public int Value => Volatile.Read(ref _value);

        public void Increment() => Interlocked.Increment(ref _value);
    }

    // Обгортка над стандартним PasswordHasher, яка лише рахує перевірки.
    public sealed class CountingPasswordHasher(VerifyCounter counter) : IPasswordHasher<ApplicationUser>
    {
        private readonly PasswordHasher<ApplicationUser> _inner = new();

        public string HashPassword(ApplicationUser user, string password) => _inner.HashPassword(user, password);

        public PasswordVerificationResult VerifyHashedPassword(
            ApplicationUser user, string hashedPassword, string providedPassword)
        {
            counter.Increment();
            return _inner.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }
}