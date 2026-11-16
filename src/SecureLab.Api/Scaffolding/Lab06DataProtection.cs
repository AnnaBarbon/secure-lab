using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace SecureLab.Api.Scaffolding;

// ЛР 6, advanced variant: явне керування ключами ASP.NET Core Data Protection.
// Ключами захищено authentication cookie й antiforgery-токени. Без налаштування місце ключів
// і application discriminator (content root) обирає ASP.NET Core; екземпляри з різних тек
// не приймають cookie один одного, а контейнер без volume втрачає ключі після перезапуску.
public static class Lab06DataProtection
{
    public const string RevokeCommand = "--revoke-data-protection-keys";

    public static WebApplicationBuilder AddLab06DataProtection(this WebApplicationBuilder builder)
    {
        var keysPath = builder.Configuration["DataProtection:KeysPath"];
        if (string.IsNullOrWhiteSpace(keysPath))
        {
            return builder; // Стан "до": поведінка за замовчуванням.
        }

        // Спільна тека поза Git і однакове ім'я застосунку для всіх екземплярів.
        var dataProtection = builder.Services.AddDataProtection()
            .SetApplicationName("SecureLab")
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath));

        // Ключі на диску шифруються сертифікатом (pfx поза Git, пароль зі змінної середовища).
        var certificatePath = builder.Configuration["DataProtection:CertificatePath"];
        if (!string.IsNullOrWhiteSpace(certificatePath))
        {
            if (!File.Exists(certificatePath))
            {
                // Fail closed: краще не стартувати, ніж записати в спільну теку незашифрований ключ.
                throw new InvalidOperationException(
                    "DataProtection:CertificatePath налаштовано, але файл сертифіката недоступний.");
            }

            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                certificatePath, builder.Configuration["DataProtection:CertificatePassword"]);
            dataProtection.ProtectKeysWithCertificate(certificate)
                .UnprotectKeysWithAnyCertificate(certificate);
        }

        // Кільце ключів кешується в пам'яті, тому відкликання, записане іншим процесом,
        // без цього сервісу діє не одразу.
        if (builder.Configuration.GetValue("DataProtection:WatchRevocations", true))
        {
            builder.Services.AddHostedService(services => new DataProtectionRevocationWatcher(
                keysPath,
                services.GetRequiredService<IKeyManager>(),
                services.GetRequiredService<ILogger<DataProtectionRevocationWatcher>>()));
        }

        return builder;
    }

    // Команда runbook: dotnet run --project src/SecureLab.Api -- --revoke-data-protection-keys
    // Відкликає всі ключі, створені до цього моменту, і завершує процес.
    public static bool TryRunRevokeCommand(WebApplication app, string[] args)
    {
        if (!args.Contains(RevokeCommand, StringComparer.Ordinal))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(app.Configuration["DataProtection:KeysPath"]))
        {
            throw new InvalidOperationException(
                "Відкликання дозволено лише для явно налаштованої DataProtection:KeysPath.");
        }

        var revokedAt = DateTimeOffset.UtcNow;
        app.Services.GetRequiredService<IKeyManager>()
            .RevokeAllKeys(revokedAt, "lab6 runbook: suspected key leak");
        Console.WriteLine($"Data Protection: усі ключі, створені до {revokedAt:O}, відкликано.");
        return true;
    }
}

// Кожні 2 с перевіряє спільну теку. Якщо з'явився новіший запис runbook "відкликати всі ключі"
// (key id="*"), повторює відкликання через локальний IKeyManager: це скидає кеш кільця ключів
// у цьому екземплярі. Ім'я файлу відкликання ASP.NET Core будує з його дати, тому локальний запис
// має дату, зсунуту на кілька тіків (залежно від id процесу), і позначку SyncReason. Записи з
// SyncReason інші екземпляри ігнорують, тож циклу немає. Помилки логуються й не зупиняють host.
// Вміст ключів не читається й не логуються.
public sealed class DataProtectionRevocationWatcher(
    string keysPath,
    IKeyManager keyManager,
    ILogger<DataProtectionRevocationWatcher> logger) : BackgroundService
{
    private const string SyncReason = "lab6: revocation sync";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var handled = LatestRunbookRevocationDate() ?? DateTimeOffset.MinValue;
        using var timer = new PeriodicTimer(PollInterval);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var latest = LatestRunbookRevocationDate();
                if (latest is not { } revocationDate || revocationDate <= handled)
                {
                    continue;
                }

                handled = revocationDate;
                var localDate = revocationDate.AddTicks(1 + Environment.ProcessId % 9973);
                keyManager.RevokeAllKeys(localDate, SyncReason);
                logger.LogWarning(
                    "Data Protection revocation applied: revocationDate={RevocationDate:O} delayMs={DelayMs:F0}",
                    revocationDate,
                    (DateTimeOffset.UtcNow - revocationDate).TotalMilliseconds);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError("Data Protection revocation sync failed: {ErrorType}", exception.GetType().Name);
            }
        }
    }

    private DateTimeOffset? LatestRunbookRevocationDate()
    {
        if (!Directory.Exists(keysPath))
        {
            return null;
        }

        DateTimeOffset? latest = null;
        foreach (var file in Directory.EnumerateFiles(keysPath, "revocation-*.xml"))
        {
            try
            {
                var root = XElement.Load(file);
                if ((string?)root.Element("key")?.Attribute("id") != "*"
                    || (string?)root.Element("reason") == SyncReason)
                {
                    continue;
                }

                var value = (string?)root.Element("revocationDate");
                if (value is null)
                {
                    continue;
                }

                var date = XmlConvert.ToDateTimeOffset(value);
                if (latest is null || date > latest)
                {
                    latest = date;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                                                  or XmlException or FormatException)
            {
                logger.LogWarning("Skipped unreadable revocation file {FileName}", Path.GetFileName(file));
            }
        }

        return latest;
    }
}