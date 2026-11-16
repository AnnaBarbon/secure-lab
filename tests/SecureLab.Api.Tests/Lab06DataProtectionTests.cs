using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace SecureLab.Api.Tests;

// ЛР 6, advanced variant: керування ключами Data Protection. Кожен екземпляр API — окремий
// test host із власною тимчасовою текою ключів поза репозиторієм; cookie переноситься між
// екземплярами вручну (HandleCookies = false). Значення cookie, ключів і паролів не друкуються.
public sealed class Lab06DataProtectionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>, IDisposable
{
    private const string AuthCookieName = ".AspNetCore.Identity.Application";
    private readonly List<string> directories = [];

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // REG-DP-01: спільна тека -> cookie приймає інший екземпляр і екземпляр після перезапуску;
    // окрема тека (інше кільце ключів) -> 401.
    [Fact]
    public async Task REG_DP_01_SharedKeyRing_AcceptsCookieAcrossInstances_AndAfterRestart()
    {
        var shared = NewDirectory();
        var other = NewDirectory();
        string cookie;

        using (var first = Host(shared))
        {
            cookie = await LoginCookieAsync(first);
            Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(first, cookie));
        }

        using (var restarted = Host(shared))
        {
            Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(restarted, cookie));
        }

        using (var isolated = Host(other))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, await MeStatusAsync(isolated, cookie));
        }
    }

    // REG-DP-02: із сертифікатом ключі на диску зашифровані; копія теки без сертифіката -> 401,
    // та сама тека із сертифікатом -> 200.
    [Fact]
    public async Task REG_DP_02_CertificateEncryptsKeys_CopyWithoutCertificateRejectsCookie()
    {
        var keys = NewDirectory();
        var copy = NewDirectory();
        var certificateDirectory = NewDirectory();
        var pfxPath = Path.Combine(certificateDirectory, "dp-test.pfx");
        var pfxPassword = "Pfx-" + Guid.NewGuid().ToString("N");

        using (var rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest(
                "CN=SecureLab DP test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, critical: false));
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            await File.WriteAllBytesAsync(pfxPath, certificate.Export(X509ContentType.Pfx, pfxPassword));
        }

        string cookie;
        using (var protectedHost = Host(keys, pfxPath, pfxPassword))
        {
            cookie = await LoginCookieAsync(protectedHost);
            Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(protectedHost, cookie));
        }

        var keyFiles = Directory.GetFiles(keys, "key-*.xml");
        Assert.NotEmpty(keyFiles);
        foreach (var file in keyFiles)
        {
            var xml = await File.ReadAllTextAsync(file);
            Assert.Contains("EncryptedData", xml);
            Assert.DoesNotContain("<masterKey", xml);
        }

        foreach (var file in Directory.GetFiles(keys))
        {
            File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
        }

        using (var withoutCertificate = Host(copy))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, await MeStatusAsync(withoutCertificate, cookie));
        }

        using (var withCertificate = Host(keys, pfxPath, pfxPassword))
        {
            Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(withCertificate, cookie));
        }
    }

    // REG-DP-03: як у runbook, відкликання записує окремий процес (третій host із тією самою
    // текою). Обидва робочі екземпляри з watcher перестають приймати старий cookie менш ніж
    // за 10 с без перезапуску; новий вхід приймають обидва.
    [Fact]
    public async Task REG_DP_03_RevocationReachesBothInstances_WithWatcher()
    {
        var shared = NewDirectory();
        using var first = Host(shared, watch: true);
        using var second = Host(shared, watch: true);

        var cookie = await LoginCookieAsync(first);
        Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(second, cookie));
        await Task.Delay(TimeSpan.FromSeconds(1));

        RevokeFromSeparateProcess(shared);

        var stopwatch = Stopwatch.StartNew();
        var firstStatus = HttpStatusCode.OK;
        var secondStatus = HttpStatusCode.OK;
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(15)
               && (firstStatus != HttpStatusCode.Unauthorized || secondStatus != HttpStatusCode.Unauthorized))
        {
            await Task.Delay(250);
            firstStatus = await MeStatusAsync(first, cookie);
            secondStatus = await MeStatusAsync(second, cookie);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, firstStatus);
        Assert.Equal(HttpStatusCode.Unauthorized, secondStatus);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10),
            $"Revocation reached both instances after {stopwatch.ElapsedMilliseconds} ms.");

        var fresh = await LoginCookieAsync(second);
        Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(first, fresh));
    }

    // REG-DP-04: без watcher відкликання з окремого процесу не діє на робочі екземпляри
    // (кільце ключів у кеші); після перезапуску екземпляра — діє. Тест фіксує проблему,
    // яку розв'язує watcher.
    [Fact]
    public async Task REG_DP_04_WithoutWatcher_RevocationAppliesOnlyAfterRestart()
    {
        var shared = NewDirectory();
        string cookie;

        using (var running = Host(shared))
        {
            cookie = await LoginCookieAsync(running);
            await Task.Delay(TimeSpan.FromSeconds(1));

            RevokeFromSeparateProcess(shared);
            await Task.Delay(TimeSpan.FromSeconds(5));

            Assert.Equal(HttpStatusCode.OK, await MeStatusAsync(running, cookie));
        }

        using var restarted = Host(shared);
        Assert.Equal(HttpStatusCode.Unauthorized, await MeStatusAsync(restarted, cookie));
    }

    // REG-DP-05: пошкоджений файл ключа -> старий cookie 401, а не 500; сервер працює.
    [Fact]
    public async Task REG_DP_05_CorruptedKeyFile_Returns401_Not500()
    {
        var keys = NewDirectory();
        string cookie;

        using (var healthy = Host(keys))
        {
            cookie = await LoginCookieAsync(healthy);
        }

        foreach (var file in Directory.GetFiles(keys, "key-*.xml"))
        {
            await File.WriteAllTextAsync(file, "<corrupted");
        }

        using var damaged = Host(keys);
        Assert.Equal(HttpStatusCode.Unauthorized, await MeStatusAsync(damaged, cookie));

        using var client = Client(damaged);
        using var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    public void Dispose()
    {
        foreach (var directory in directories)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (IOException)
            {
                // Тимчасова тека поза репозиторієм; залишок не впливає на інші тести.
            }
            catch (UnauthorizedAccessException)
            {
                // Те саме.
            }
        }
    }

    // Аналог команди runbook --revoke-data-protection-keys: окремий host із тією самою текою.
    private void RevokeFromSeparateProcess(string keysPath)
    {
        using var operatorHost = Host(keysPath);
        operatorHost.Services.GetRequiredService<IKeyManager>()
            .RevokeAllKeys(DateTimeOffset.UtcNow, "REG-DP runbook");
    }

    private string NewDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "securelab-dp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        directories.Add(path);
        return path;
    }

    private WebApplicationFactory<Program> Host(
        string keysPath, string? certificatePath = null, string? certificatePassword = null, bool watch = false) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("DataProtection:KeysPath", keysPath);
            builder.UseSetting("DataProtection:WatchRevocations", watch ? "true" : "false");
            if (certificatePath is not null)
            {
                builder.UseSetting("DataProtection:CertificatePath", certificatePath);
                builder.UseSetting("DataProtection:CertificatePassword", certificatePassword);
            }
        });

    private static HttpClient Client(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    private static async Task<string> LoginCookieAsync(WebApplicationFactory<Program> host)
    {
        using var client = Client(host);
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        // Лише пара "назва=значення" без атрибутів; значення не друкується.
        return response.Headers.GetValues("Set-Cookie")
            .First(value => value.StartsWith(AuthCookieName + "=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    private static async Task<HttpStatusCode> MeStatusAsync(WebApplicationFactory<Program> host, string cookie)
    {
        using var client = Client(host);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("Cookie", cookie);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }
}