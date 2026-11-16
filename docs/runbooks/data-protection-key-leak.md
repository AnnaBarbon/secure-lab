# Runbook: ключ Data Protection міг витекти

Призначення: інша людина має змогу повторити реагування без автора. Ключами ASP.NET Core Data Protection захищено authentication cookie й antiforgery-токени SecureLab. Хто має незашифрований ключ (або теку ключів разом із сертифікатом і паролем pfx), може підробити cookie будь-якого користувача.

## Конфігурація, на яку спирається runbook

| Змінна середовища | Значення в навчальному стенді | Примітка |
|---|---|---|
| DataProtection__KeysPath | D:\Projects\lab-01-starter\lr06-dp\keys | спільна для всіх екземплярів, поза Git |
| DataProtection__CertificatePath | D:\Projects\lab-01-starter\lr06-dp\dp-cert.pfx | поза Git (.gitignore: *.pfx) |
| DataProtection__CertificatePassword | задається через Read-Host -AsSecureString | ніде не записується |
| DataProtection__WatchRevocations | не задано (true) | watcher кожні 2 с перевіряє теку на відкликання |

Код: src/SecureLab.Api/Scaffolding/Lab06DataProtection.cs. Ім'я застосунку SetApplicationName("SecureLab") однакове для всіх екземплярів.

## 1. Виявлення

Ознаки того, що ключ міг витекти:
- тека ключів або pfx потрапили в Git, архів, резервну копію, чат чи на інший комп'ютер;
- у теці ключів з'явились файли key-*.xml, яких не створював жоден відомий екземпляр;
- у журналі API є попередження "No XML encryptor configured" — ключі пишуться незашифрованими;
- файли ключів незашифровані. Перевірка (вміст ключів не відкривати):

```powershell
"unencrypted masterKey: " + @(Select-String -Path $env:DataProtection__KeysPath\key-*.xml -SimpleMatch '<masterKey').Count
"encrypted (EncryptedData): " + @(Select-String -Path $env:DataProtection__KeysPath\key-*.xml -SimpleMatch 'EncryptedData').Count
git ls-files | Select-String -Pattern 'DataProtection-Keys|key-.*\.xml|\.pfx$'
```

Очікувано в нормальному стані: masterKey 0, EncryptedData більше за 0, git ls-files нічого не знаходить.

Рішення: якщо виконується хоча б одна ознака, ключі вважаються скомпрометованими; переходити до стримування.

## 2. Стримування (відкликання)

У терміналі з тими самими DataProtection__* змінними, що й у робочих екземплярів, у корені репозиторію:

```powershell
dotnet run --project src/SecureLab.Api --no-build -- --revoke-data-protection-keys
```

Очікувано: "Data Protection: усі ключі, створені до <час UTC>, відкликано." і новий файл revocation-<дата>.xml у теці ключів. Команда відмовляє, якщо DataProtection:KeysPath не задано (щоб не відкликати чуже кільце ключів), і не стартує з неправильним паролем або без файлу сертифіката.

Протягом кількох секунд у журналі кожного робочого екземпляра має з'явитися:
"Data Protection revocation applied: revocationDate=<час> delayMs=<мс>"
Виміряно 16.11.2026: 399 мс і 1854 мс (два екземпляри, опитування кожні 2 с).

Якщо такого рядка немає в якомусь екземплярі за 10 с (watcher вимкнено або екземпляр недоступний), перезапустіть цей екземпляр: при старті кільце ключів читається заново й відкликання застосовується.

Наслідок для користувачів: усі сесії й antiforgery-токени, видані до відкликання, стають недійсними; потрібен повторний вхід.

## 3. Відновлення

1. Якщо міг витекти лише вміст теки ключів, а сертифікат і пароль pfx — ні: нові ключі створяться автоматично після відкликання, вони шифруються тим самим сертифікатом.
2. Якщо міг витекти сертифікат або пароль pfx:
   - зупинити всі екземпляри;
   - створити новий сертифікат (New-SelfSignedCertificate ... -Provider "Microsoft Software Key Storage Provider"), експортувати в новий pfx з новим паролем поза Git, видалити його зі сховища Windows;
   - перемістити стару теку ключів в архів поза доступом застосунку або видалити;
   - задати DataProtection__CertificatePath і DataProtection__CertificatePassword для нового pfx на всіх екземплярах;
   - запустити всі екземпляри.
3. Повідомити користувачів про потрібний повторний вхід.
4. Знайти й закрити причину витоку (наприклад, файл у Git: прибрати з поточного стану, вважати ключ скомпрометованим; історію Git не переписувати без окремого рішення).

## 4. Перевірка

| Перевірка | Як | Очікувано |
|---|---|---|
| Старий cookie на кожному екземплярі | GET /api/me зі старим cookie | 401 на всіх, без перезапуску |
| Старий antiforgery-токен | новий вхід, POST /api/incidents зі старим X-CSRF-TOKEN, потім GET /api/incidents | 400, кількість інцидентів не змінилась |
| Новий вхід | вхід через auth-lab.html, GET /api/me на іншому екземплярі | 200 |
| Ключі зашифровані | команди з розділу 1 | masterKey 0, EncryptedData більше за 0 |
| Журнал без ключів | Select-String по журналу: '<masterKey', '<value>', 'EncryptedData', 'CipherValue', 'CfDJ8', пароль pfx | 0 збігів |
| Автотести | dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Lab06DataProtectionTests" | 5 з 5 |

## Межі

Перевірено на локальному стенді Windows з двома екземплярами (5080 і 5081) і спільною локальною текою. Мережеві сховища, контейнери, кілька машин і ротація сертифіката за розкладом не перевірялись. Watcher реагує лише на відкликання всіх ключів (key id="*"), а не на відкликання окремого ключа.