# Security review SecureLab, ЛР 6

Рівень: відмінний ("Відмінно"); рівні накопичувальні, тому виконуються також усі вимоги достатнього й доброго рівнів. Commit початку огляду (review-start): 7bac4abbee19438b41e97919a02e9792aa6f0900 (гілка main, після тегу v0.5.0 = 1832f52). Хеші прийнятого commit і тегу v1.0.0 додаються наприкінці. Дата початку: 15.11.2026. .NET SDK 10.0.302 (global.json, rollForward latestPatch). Профілі: http (Development, http://localhost:5080) і production-like (ASPNETCORE_ENVIRONMENT=Production). Клієнти: Chrome, VS Code REST Client, PowerShell (curl.exe), xUnit (dotnet test).

## 1. Executive summary
Один абзац: що перевірено, скільки знахідок зафіксовано й виправлено, результат фактичного фінального прогону, головні залишкові ризики.
## 2. Scope та exclusions
Поточні відстежувані Git файли — обов’язково. Історія Git: лише фактично переглянуті файли, refs або проміжок дат; інакше напишіть «не перевірено».
## 3. System overview і trust boundaries
Компоненти, межі довіри та очікувані властивості на межах наведено в docs/threat-model.md. Кожна межа пов'язана з конкретним test або перевіркою.

| Актив | Загроза | Control | Перевірка |
|---|---|---|---|
| Сесія користувача (authentication cookie) | сторонній сайт змушує браузер виконати зміну від імені користувача (CSRF) | antiforgery-токен у заголовку для всіх змінювальних маршрутів з cookie | REG-CSRF-01 |
| Власні інциденти Reporter | читання або зміна чужого інциденту (IDOR) | IncidentAuthorizationHandler, query scoping, 404 для чужого | Lab04AuthorizationTests A-03, A-04, A-11 |
| Привілейований перехід New -> Triaged | Reporter змінює статус сам | операція Triage лише для Analyst, audit authorization.denied | A-06, A-07, A-09 |
| Облікові дані | підбір пароля | login rate limiter, PBKDF2 | LoginRateLimitTests, LoginTimingDefectTests |
| Дані в описах і коментарях | збережений XSS | textContent замість innerHTML, CSP | ClientScript_DoesNotUseDangerousInnerHtmlSink, browser-lab-dom.js |
| База даних | SQL injection через пошук | параметризовані запити EF Core, allowlist sortBy | S-02, T-05 |
| Внутрішні деталі сервера | розкриття stack trace, SQL, connection string у помилці | UseExceptionHandler, ProblemDetails у Production | перевірка контрольованої 500 (етап 1, п. 4) |
| Секрети конфігурації | витік через Git | значення поза Git, .gitignore, лише навчальні значення в tracked files | git grep і git check-ignore (етап 1, п. 3) |
| Ключі Data Protection | підробка cookie й токенів при витоку ключа | тека ключів поза Git, шифрування сертифікатом, відкликання | advanced variant |

Таблицю буде доповнено результатами перевірок.
## 4. Methodology та test environment
Початковий стан: commit 7bac4abbee19438b41e97919a02e9792aa6f0900 (main), стартова перевірка 15.11.2026: git status чистий, теги v0.1.0...v0.5.0 на місці, dotnet --version 10.0.302, dotnet restore --locked-mode і dotnet build -c Release без помилок, PostgreSQL у Docker Healthy, reset/seed виконано, dotnet test -c Release: 56 з 56, /health -> {"status":"ready"}.

БД: лише локальна навчальна PostgreSQL у контейнері secure-lab-postgres-1 (127.0.0.1:54329, база securelab). Reset виконується тільки в Development командою dotnet run --project src/SecureLab.Api -- --reset-database. Пароль навчальних акаунтів задається змінною SeedUsers__Password поза Git і в доказах не показується.

Профілі запуску:
- Development: dotnet run --project src/SecureLab.Api --launch-profile http
- Production-like: змінні ASPNETCORE_ENVIRONMENT=Production, ASPNETCORE_URLS=http://localhost:5080, ConnectionStrings__SecureLab (навчальний рядок поза Git), Logging__Console__IncludeScopes=true; запуск dotnet run --project src/SecureLab.Api --no-launch-profile -c Release, щоб launchSettings.json не перекрив environment.

Клієнти: Chrome (браузерний flow), VS Code REST Client (tests/http), PowerShell curl.exe (заголовки), xUnit TestServer (dotnet test).

### Етап 1, п. 4-5. Production-like профіль і безпечна помилка

| Перевірка | Результат |
|---|---|
| Profile активний | у консолі Hosting environment: Production і Now listening on: http://localhost:5080 |
| GET /health | 200, {"status":"ready"}; є nosniff, no-referrer, CSP |
| GET /openapi/v1.json | 404, application/problem+json: OpenAPI реєструється лише в Development |
| GET /scalar/v1 | 200, text/html, тіло починається з <!doctype html> клієнта: це fallback на index.html, а не Scalar |
| Reset у Production | процес завершується з InvalidOperationException "Reset даних дозволено лише в явно налаштованому Development environment."; дані не змінено |
| Джерело connection string | ConnectionStrings__SecureLab поза Git; appsettings.Development.json у Production не читається; Include Error Detail=false |
| Database:ApplyMigrationsOnStartup, Database:AllowReset | false в appsettings.json (Production) |
| AllowedHosts | "*": фільтрацію Host вимкнено; для локального стенда наслідок обмежений, для реального deployment потребує окремого рішення (residual risk) |
| HTTPS/HSTS | локальний запуск лише HTTP; UseHttpsRedirection і UseHsts не налаштовані; це не доказ безпеки транспорту в production |

Контрольована помилка: Production, connection string на недоступний порт 54399, запит tests/http/lab-06-unexpected-error.http (публічний login з вигаданим паролем).

| Канал | Що отримано | Чого немає |
|---|---|---|
| HTTP-відповідь | 500, application/problem+json, title "An error occurred while processing your request.", traceId 00-359d3bd2a615df3d100b045a95b2cd0e-faa0755bedae84a0-00 | stack trace, SQL, шлях до файлів, версії пакетів, connection string |
| Журнал API | fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1], TraceId:359d3bd2a615df3d100b045a95b2cd0e, RequestPath:/api/auth/login, причина Npgsql "Failed to connect to 127.0.0.1:54399" | пароль, cookie, connection string |

Середній сегмент traceId у відповіді (359d3bd2a615df3d100b045a95b2cd0e) дорівнює TraceId у журналі, тобто відповідь і внутрішню діагностику можна зіставити без розкриття деталей клієнту.

Відновлення: API зупинено, тимчасові змінні Production прибрано, запуск у Development з правильним connection string; /health -> ready, вхід alice -> 204, GET /api/incidents -> 200 зі списком її інцидентів.

Обмеження: захищені маршрути в Production через HTTP не перевіряються браузером, бо cookie має Secure (SecurePolicy.Always). Очікувані 400/404 для автентифікованого користувача в Production перевіряються в тестовому host з UseEnvironment("Production") (додається в тестах ЛР 6).
## 5. Findings summary
Таблиця: ID / актив / вплив / ймовірність / пріоритет / статус / ID повторної перевірки.
## 6. Detailed findings
Щонайменше одна власна знахідка для достатнього рівня, дві виправлені — для доброго; три виправлені — для відмінного, з них третя поза прямим checklist; кожна в окремому файлі docs/findings/*.md.
## 7. Regression results
Для всіх: мінімальний pack SQLi/authentication/authorization-IDOR/XSS/CSRF. Добрий/відмінний: ще validation/CORS/rate limiting. Відмінний: автоматизований повний REG-CSRF-01 (login/cookie → відмова → незмінний стан → token → успіх → змінений стан), команда й фактичний результат. Початкові ID сценаріїв (T/S/A/E/R/REG), команда або тест, передумова, точний результат, перевірка стану ресурсу, перевірений фінальний commit.
## 8. Hardening controls
Для всіх: наявні controls; наявний login limiter — повторна перевірка (quota, 429, відновлення), відсутній — gap або виключення з причиною. Добрий/відмінний: наявні headers, CORS, search limiter (два partitions, quota, 429, відновлення). CSP, якої не було, — N/A на достатньому/доброму; для відмінного вона обов’язкова й не має ламати client. Добрий/відмінний: змістові відмінності Development/Production. Відмінний: погодження advanced variant до реалізації й фактична перевірка; Redis — shared state, TTL, partition isolation, failure mode.

Зв’язок «control → ризик → фактична перевірка → межа»; у рядках про headers зазначте профіль, клієнт і status.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | заповнити | ЛР 2–5 / OpenAPI / client call / DISCREPANCY | заповнити | так/ні | так/ні | explicit / automatic / absent | фактичний ID |

Login і register внесіть до таблиці з позначкою Cookie authentication = ні та окремим рішенням щодо ризику й меж огляду. Logout входить до cookie-периметра; перевірка токена — до SignOutAsync.
## 9. Dependency and secret audit
### 9.1. Секрети й конфігурація (етап 1, п. 3)

Межі: поточні відстежувані файли на commit 05ae77e; історія переглянута лише для src/SecureLab.Api/appsettings.Development.json. Пошук виконано засобами Git, без сторонніх сервісів.

Команди:
- git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config' -> 4 файли: infra/.env.example, infra/compose.yaml, src/SecureLab.Api/appsettings.json, src/SecureLab.Api/appsettings.Development.json
- git check-ignore -v infra/.env appsettings.Local.json keys/key.pfx -> ігноруються правилами .gitignore:15 (.env), .gitignore:18 (appsettings.Local.json), .gitignore:19 (*.pfx)
- git grep -n -I -i -E 'password|passwd|secret|api.?key' -- . -> 199 збігів у 34 файлах
- git grep -n -I 'local-study-password' -- . -> 4 збіги
- git grep -n -I 'SeedUsers__Password' -- . -> лише читання змінної середовища
- git log --all --follow --oneline -- src/SecureLab.Api/appsettings.Development.json -> один commit 93974ce (Initial starter commit)

| Шлях:рядок | Безпечний контекст | Рішення | Причина й межа |
|---|---|---|---|
| infra/compose.yaml:9 | пароль локального контейнера PostgreSQL, порт прив'язано до 127.0.0.1 | accepted, study-only | відкрите навчальне значення, README.md:63 забороняє повторне використання; не поширюється на інші БД і середовища |
| src/SecureLab.Api/appsettings.Development.json:3 | connection string лише для Development і 127.0.0.1:54329 | accepted, study-only | те саме навчальне значення; реальний connection string передається поза Git через ConnectionStrings__SecureLab |
| src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10 | connection string для інструментів EF Core під час розробки | accepted, study-only | те саме навчальне значення, використовується лише локально для migrations |
| README.md:63 | документація про навчальні значення | не секрет | пояснення і заборона повторного використання |
| tests/SecureLab.Api.Tests/*.cs (AuthEventsTests, AuthenticationMechanicsTests, CookieFlagsTests, IncidentEndpointTests, Lab02CustomTests, Lab03SecurityTests, Lab04AuthorizationTests, LoginRateLimitTests, LoginTimingDefectTests, SearchMechanicsTests) | Environment.GetEnvironmentVariable("SeedUsers__Password") | не секрет | тест читає пароль зі змінної середовища; значення в Git немає |
| tests/http/lab-04-access.http:10, 17, 92, 102 | {{$processEnv SeedUsers__Password}} | не секрет | REST Client бере значення із середовища процесу |
| tests/http/lab-03-auth.http:23, 29 | # @prompt password | не секрет | пароль вводиться вручну під час запуску |
| src/SecureLab.Api/Data/DbSeeder.cs | ключ конфігурації SeedUsers:Password | не секрет | код читає ключ; значення задається поза Git |
| src/SecureLab.Api/Scaffolding/Lab03Identity.cs, Client/auth-lab.html, Client/auth-lab.js | назви полів password у DTO і формі входу | не секрет | назва поля, значення немає |
| src/SecureLab.Api/Data/Migrations/*.cs | стовпець PasswordHash таблиці Identity | не секрет | схема БД, хеш не є паролем і в Git не зберігається |
| tests/SecureLab.Api.Tests/PasswordHasherUpgradeTests.cs та ін. | назви тестів і змінних про password hasher | не секрет | код тестів, без значень |
| tests/SecureLab.Api.Tests/packages.lock.json:208, 291 | Microsoft.Extensions.Configuration.UserSecrets | не секрет | ідентифікатор пакета |
| .gitignore:14, docs/*.md, src/SecureLab.Api/Program.cs:32 | коментарі й документація | не секрет | згадка слова, значення немає |

Результат: реального credential у поточних відстежуваних файлах не знайдено. Навчальний пароль seed-акаунтів у Git відсутній.

| Перевірка | Очікуваний результат | Доказ | Межа висновку |
|---|---|---|---|
| .env.example | тільки безпечні значення | Get-Content infra/.env.example: лише POSTGRES_PORT=54329 і коментар | не доводить відсутність секрету в невідстежуваному файлі |
| tracked configuration | немає реального credential; навчальні значення класифіковано | команди й таблиця вище | не доводить відсутність у всій історії або зовнішньому CI |
| історія appsettings.Development.json | немає непогодженого значення | git log --all --follow: один commit 93974ce | не охоплює чужі fork, видалені refs, stash, інші клони; це не повне forensic-розслідування |

Чому видалення з поточного файла недостатньо: якщо реальний credential колись потрапив у Git, він лишається в історії комітів, у всіх клонах і fork, у кеші CI та в журналах. Видалення з поточного файла прибирає лише останню версію. Тому витеклий credential треба вважати скомпрометованим: відкликати або замінити (rotation) у самій системі (новий пароль БД, новий ключ), перевірити журнали на використання старого значення і лише після цього прибрати його з поточного стану. Переписувати історію Git без окремої інструкції не потрібно.

### 9.2. Залежності

Заповнюється на етапі 3.
## 10. Residual risks
Неперевірені й тимчасово прийняті ризики, відповідальний і наступна дія.
## 11. Conclusion
Лише фактичні результати.
## 12. Evidence appendix
Для відмінного: доказ відсутності чутливих даних у логах шести сценаріїв етапу 3, п. 4; обґрунтування пріоритетів findings; відтворювані передумови й retest для іншої людини.
Шляхи, точні команди, ID сценаріїв, безпечний зв’язок відповіді з записом журналу через traceId; без паролів, cookie, токенів і connection strings.
## Декларація й журнал ШІ
Використовував/ла / не використовував/ла. Назва сервісу, для чого, що перевірено й змінено автором, власна інтерпретація.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| заповнити або не використовував/ла | | | | |
