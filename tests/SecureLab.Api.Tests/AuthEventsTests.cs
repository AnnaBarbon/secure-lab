using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

/// Добрий рівень: події автентифікації записуються й не містять credentials.
/// Тестовий host отримує додатковий logger provider, який збирає повідомлення всіх категорій.
public sealed class AuthEventsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task AuthEvents_AreRecorded_WithoutPasswordsOrAttemptedUserNames()
    {
        var provider = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ILoggerProvider>(provider)));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        var wrongPassword = StudyPassword + "-wrong";
        var unknownUserName = "ghost" + Guid.NewGuid().ToString("N")[..8];

        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = wrongPassword });
        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUserName, password = StudyPassword });
        using var success = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        using var logout = await client.PostAsync("/api/auth/logout", content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, success.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var entries = provider.Entries.ToArray();
        var authEvents = entries
            .Where(entry => entry.Properties.ContainsKey("EventType") && entry.Properties.ContainsKey("Result"))
            .ToArray();

        var failedLogins = authEvents.Count(entry =>
            entry.Properties["EventType"] == "login" && entry.Properties["Result"] == "failed"
            && entry.Properties.GetValueOrDefault("UserId") == "anonymous");
        Assert.Equal(2, failedLogins);

        var aliceId = DbSeeder.AliceId.ToString();
        var successfulLogins = authEvents.Count(entry =>
            entry.Properties["EventType"] == "login" && entry.Properties["Result"] == "succeeded"
            && entry.Properties.GetValueOrDefault("UserId") == aliceId);
        Assert.Equal(1, successfulLogins);

        var logouts = authEvents.Count(entry =>
            entry.Properties["EventType"] == "logout" && entry.Properties.GetValueOrDefault("UserId") == aliceId);
        Assert.Equal(1, logouts);

        var everyEventHasTrace = authEvents.All(entry =>
            !string.IsNullOrEmpty(entry.Properties.GetValueOrDefault("TraceId")));
        Assert.True(everyEventHasTrace, "Each auth event needs a trace id.");

        // Жоден запис журналу (усіх категорій) не містить пароля; подія — введеного імені.
        // Значення в повідомленні про помилку не друкуються.
        var leaksPassword = entries.Any(entry =>
            entry.Message.Contains(StudyPassword, StringComparison.Ordinal)
            || entry.Message.Contains(wrongPassword, StringComparison.Ordinal));
        var leaksAttemptedName = authEvents.Any(entry =>
            entry.Message.Contains(unknownUserName, StringComparison.Ordinal));
        Assert.False(leaksPassword, "A log entry contains a password (value omitted).");
        Assert.False(leaksAttemptedName, "An auth event contains the attempted user name.");
    }

    private sealed record CapturedLog(string Message, IReadOnlyDictionary<string, string?> Properties);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<CapturedLog> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<CapturedLog> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var properties = new Dictionary<string, string?>(StringComparer.Ordinal);
                if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
                {
                    foreach (var pair in pairs)
                    {
                        properties[pair.Key] = Convert.ToString(pair.Value, CultureInfo.InvariantCulture);
                    }
                }

                entries.Enqueue(new CapturedLog(formatter(state, exception), properties));
            }
        }
    }
}