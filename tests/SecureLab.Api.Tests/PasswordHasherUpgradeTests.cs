using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

/// Поглиблення відмінного рівня: готовність стандартного hasher до оновлення параметрів хешу.
/// Формат Identity V3: [0]=0x01, [1..4]=PRF, [5..8]=кількість ітерацій (big-endian),
/// [9..12]=довжина солі, далі сіль і результат. Тести читають лише службову кількість ітерацій;
/// hash і пароль ніде не друкуються. Власного hasher немає — лише стандартний PasswordHasher.
public sealed class PasswordHasherUpgradeTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const int CurrentIterations = 100_000;
    private const int StrongerIterations = 210_000;

    // Пароль формується локально для кожного запуску.
    private static string NewPassword() => "Hu-" + Guid.NewGuid().ToString("N")[..10] + "a7!";

    // Модульна частина: посилений hasher читає старий формат і повертає SuccessRehashNeeded.
    [Fact]
    public void StrongerHasher_ReadsOldHash_AndRequestsRehash()
    {
        var current = CreateHasher(CurrentIterations);
        var stronger = CreateHasher(StrongerIterations);
        var user = new ApplicationUser { DisplayName = "Hasher probe", UserName = "hasher-probe" };
        var password = NewPassword();

        var oldHash = current.HashPassword(user, password);
        var secondHashSamePassword = current.HashPassword(user, password);

        // Параметри записано в самому рядку.
        Assert.Equal(CurrentIterations, ReadIterationCount(oldHash));
        // Сіль окрема для кожного обчислення: той самий пароль -> різні рядки.
        var differentSalts = !string.Equals(oldHash, secondHashSamePassword, StringComparison.Ordinal);
        Assert.True(differentSalts, "Two hashes of one password are identical.");

        Assert.Equal(PasswordVerificationResult.Success, current.VerifyHashedPassword(user, oldHash, password));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded,
            stronger.VerifyHashedPassword(user, oldHash, password));
        Assert.Equal(PasswordVerificationResult.Failed,
            stronger.VerifyHashedPassword(user, oldHash, password + "x"));

        var newHash = stronger.HashPassword(user, password);
        Assert.Equal(StrongerIterations, ReadIterationCount(newHash));
        Assert.Equal(PasswordVerificationResult.Success, stronger.VerifyHashedPassword(user, newHash, password));
    }

    // Інтеграційна частина: окремий штучний акаунт із hash на 100 000 ітерацій входить у host
    // з посиленими параметрами; UserManager під час успішної перевірки зберігає оновлений hash.
    [Fact]
    public async Task SuccessfulLogin_WithStrongerParameters_UpgradesStoredHash()
    {
        var (userName, password) = await CreateTemporaryUserAsync(factory.Services);
        try
        {
            Assert.Equal(CurrentIterations, await ReadStoredIterationsAsync(factory.Services, userName));

            using var strongerHost = factory.WithWebHostBuilder(builder =>
                builder.ConfigureTestServices(services =>
                    services.Configure<PasswordHasherOptions>(options =>
                        options.IterationCount = StrongerIterations)));
            using var client = strongerHost.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false
            });

            using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });

            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
            Assert.Equal(StrongerIterations, await ReadStoredIterationsAsync(factory.Services, userName));

            // Після оновлення той самий пароль і далі приймається.
            using var again = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(factory.Services, userName);
        }
    }

    private static PasswordHasher<ApplicationUser> CreateHasher(int iterations) =>
        new(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = iterations
        }));

    private static int ReadIterationCount(string hash)
    {
        var bytes = Convert.FromBase64String(hash);
        Assert.Equal((byte)0x01, bytes[0]);
        return (int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(5, 4));
    }

    private static async Task<int> ReadStoredIterationsAsync(IServiceProvider services, string userName)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        Assert.NotNull(user);
        Assert.NotNull(user.PasswordHash);
        return ReadIterationCount(user.PasswordHash);
    }

    private static async Task<(string UserName, string Password)> CreateTemporaryUserAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userName = "hash" + Guid.NewGuid().ToString("N")[..8];
        var password = NewPassword();
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            Email = userName + "@example.test",
            DisplayName = "Тимчасовий акаунт hasher"
        };

        var created = await users.CreateAsync(user, password);
        Assert.True(created.Succeeded, "Temporary study user was not created.");
        var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
        Assert.True(role.Succeeded, "Temporary study user role was not assigned.");
        return (userName, password);
    }

    private static async Task DeleteUserAsync(IServiceProvider services, string userName)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        if (user is not null)
        {
            await users.DeleteAsync(user);
        }
    }
}