using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

/// Поглиблення відмінного рівня: втрата чинності старого сеансу після визначеної серверної події.
/// Подія — UserManager.UpdateSecurityStampAsync (так Identity реагує, наприклад, на зміну пароля
/// чи примусовий вихід з усіх пристроїв). Момент перевірки задає
/// SecurityStampValidatorOptions.ValidationInterval (за замовчуванням 30 хв).
/// «Раніше скопійована cookie» моделюється ручним заголовком Cookie з пари «назва=значення»;
/// значення ніде не друкується. Кожен сценарій має окремий тимчасовий акаунт.
public sealed class SessionRevocationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string CookieName = ".AspNetCore.Identity.Application";

    // 1. Logout видаляє cookie лише в одного клієнта: раніше скопійований квиток ще діє.
    [Fact]
    public async Task Logout_DoesNotRevokePreviouslyCopiedCookie()
    {
        var (userName, password) = await CreateTemporaryUserAsync(factory.Services);
        try
        {
            using var client = CreateClientWithoutCookieJar(factory);
            var copiedCookie = await LoginAndCopyCookieAsync(client, userName, password);

            using var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
            logoutRequest.Headers.Add("Cookie", copiedCookie);
            using var logout = await client.SendAsync(logoutRequest);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

            using var replay = await GetMeWithCookieAsync(client, copiedCookie);

            // Задокументоване обмеження: cookie-квиток без серверного відкликання діє до перевірки.
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(factory.Services, userName);
        }
    }

    // 2. Стандартний інтервал (30 хв): після зміни security stamp старий квиток діє до наступної перевірки.
    [Fact]
    public async Task SecurityStampChange_WithDefaultInterval_IsNotImmediate()
    {
        var (userName, password) = await CreateTemporaryUserAsync(factory.Services);
        try
        {
            using var client = CreateClientWithoutCookieJar(factory);
            var copiedCookie = await LoginAndCopyCookieAsync(client, userName, password);

            await UpdateSecurityStampAsync(factory.Services, userName);
            using var replay = await GetMeWithCookieAsync(client, copiedCookie);

            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(factory.Services, userName);
        }
    }

    // 3. Явно визначений момент перевірки (ValidationInterval = 0): після серверної події
    //    будь-яка раніше видана cookie цього акаунта відхиляється вже на наступному запиті.
    [Fact]
    public async Task SecurityStampChange_WithImmediateValidation_RejectsOldCookie()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Configure<SecurityStampValidatorOptions>(options =>
                    options.ValidationInterval = TimeSpan.Zero)));
        var (userName, password) = await CreateTemporaryUserAsync(host.Services);
        try
        {
            using var client = CreateClientWithoutCookieJar(host);
            var copiedCookie = await LoginAndCopyCookieAsync(client, userName, password);

            using var beforeEvent = await GetMeWithCookieAsync(client, copiedCookie);
            Assert.Equal(HttpStatusCode.OK, beforeEvent.StatusCode);

            await UpdateSecurityStampAsync(host.Services, userName);
            using var afterEvent = await GetMeWithCookieAsync(client, copiedCookie);
            Assert.Equal(HttpStatusCode.Unauthorized, afterEvent.StatusCode);

            // Новий вхід після події дає новий чинний сеанс.
            var newCookie = await LoginAndCopyCookieAsync(client, userName, password);
            using var withNewCookie = await GetMeWithCookieAsync(client, newCookie);
            Assert.Equal(HttpStatusCode.OK, withNewCookie.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(host.Services, userName);
        }
    }

    // HandleCookies = false: клієнт не зберігає cookie сам, тому ми керуємо «копією» вручну.
    private static HttpClient CreateClientWithoutCookieJar(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    private static async Task<string> LoginAndCopyCookieAsync(HttpClient client, string userName, string password)
    {
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        var header = login.Headers.GetValues("Set-Cookie")
            .First(value => value.StartsWith(CookieName + "=", StringComparison.Ordinal));
        // Лише пара «назва=значення» без атрибутів; значення не друкується.
        return header.Split(';')[0];
    }

    private static async Task<HttpResponseMessage> GetMeWithCookieAsync(HttpClient client, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("Cookie", cookie);
        return await client.SendAsync(request);
    }

    private static async Task<(string UserName, string Password)> CreateTemporaryUserAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userName = "rev" + Guid.NewGuid().ToString("N")[..8];
        // Пароль формується локально для кожного запуску й не друкується.
        var password = "Rv-" + Guid.NewGuid().ToString("N")[..10] + "a7!";
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            Email = userName + "@example.test",
            DisplayName = "Тимчасовий акаунт поглиблення"
        };

        var created = await users.CreateAsync(user, password);
        Assert.True(created.Succeeded, "Temporary study user was not created.");
        var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
        Assert.True(role.Succeeded, "Temporary study user role was not assigned.");
        return (userName, password);
    }

    private static async Task UpdateSecurityStampAsync(IServiceProvider services, string userName)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        Assert.NotNull(user);
        var updated = await users.UpdateSecurityStampAsync(user);
        Assert.True(updated.Succeeded, "Security stamp update failed.");
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