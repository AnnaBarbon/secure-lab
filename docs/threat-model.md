# Модель загроз SecureLab, ЛР 6

## Межі огляду

| Елемент | Що зафіксувати | Запис |
|---|---|---|
| Версія та середовище | commit, профіль, seed/reset, SDK | review-start 7bac4abbee19438b41e97919a02e9792aa6f0900 (main, після v0.5.0 = 1832f52); профіль http (Development, http://localhost:5080) і production-like запуск з ASPNETCORE_ENVIRONMENT=Production; reset командою dotnet run --project src/SecureLab.Api -- --reset-database лише в Development; .NET SDK 10.0.302; лише навчальні акаунти alice, bob (Reporter), morgan (Analyst), admin (Administrator) |
| Компоненти в межах огляду | клієнт, API, БД, конфігурація, журнали | статичний браузерний клієнт src/SecureLab.Api/Client (index.html, app.js, auth-lab.html, browser-lab.html, api-fetch.js); ASP.NET Core API src/SecureLab.Api; PostgreSQL у Docker Compose (infra/compose.yaml, порт 127.0.0.1:54329); конфігурація appsettings*.json, launchSettings.json, змінні середовища; консольні журнали API; ключі ASP.NET Core Data Protection. Redis не використовується |
| Активи | що має цінність | облікові дані та password hash (ASP.NET Identity, PBKDF2); authentication cookie сесії; власні інциденти Reporter (title, description); internal comments, доступні лише Analyst; привілейований перехід статусу New -> Triaged; audit-події authorization.denied і auth events; ключі Data Protection, якими захищено cookie й antiforgery-токени; пароль seed-акаунтів і connection string |
| Суб'єкти | ролі | анонімний відвідувач; Reporter (alice, bob); Analyst (morgan); Administrator (admin, без додаткових прав над Incident, див. docs/access-matrix.md); локальний розробник з доступом до репозиторію й конфігурації; сторонній сайт у браузері автентифікованого користувача (CSRF) |
| Entry points | маршрути та інші входи | змінювальні: POST /api/auth/register, POST /api/auth/login, POST /api/auth/logout, POST /api/incidents, PUT /api/incidents/{id}, DELETE /api/incidents/{id}, POST /api/incidents/{id}/triage; читання: GET /api/incidents, GET /api/incidents/{id}, GET /api/incidents/search?q=&sortBy=, GET /api/incidents/severity-summary, GET /api/incident-comments/{id}, GET /api/me, GET /api/auth/session-check, GET /health; браузерні форми клієнта; завантаження конфігурації під час старту; dotnet restore; журнали |
| Межі довіри | де дані переходять між рівнями довіри | browser -> API; API -> PostgreSQL; repository -> build; environment -> configuration |
| Наявні controls | з посиланням на код або тест | validation і ProblemDetails (Lab02Endpoints, T-02, T-05, T-10); параметризовані запити EF Core (S-02); cookie authentication HttpOnly, SameSite=Lax, Secure поза Development (Lab03Identity, CookieFlagsTests); login rate limiter 5 спроб за 60 с за IP (Program.cs, LoginRateLimitTests); resource-based authorization IncidentAuthorizationHandler і query scoping (Lab04AuthorizationTests A-01...A-12); безпечний DOM через textContent (browser-lab.js, ClientScript_DoesNotUseDangerousInnerHtmlSink); CSP з frame-ancestors 'none', nosniff, no-referrer (Program.cs); CORS лише в Development для http://localhost:4173, метод GET. Antiforgery відсутній, додається в ЛР 6 |
| Виключення | що не перевірялося і чому | зовнішній penetration test не виконувався; production host, реальний TLS termination і HSTS не тестувалися (локальний стенд); історія Git переглядається лише для файлів конфігурації; сторонні сервіси й інфраструктура Docker Desktop поза межами огляду; Scalar /scalar доступний лише в Development |

## Схема меж довіри

```text
браузер (недовірений ввід, cookie надсилається автоматично)
    |  HTTP localhost:5080 (Development) / HTTPS у production
    v
ASP.NET Core API (validation, authn/authz, CSP, antiforgery, rate limiting, журнали)
    |  connection string / EF Core (Npgsql)
    v
PostgreSQL у Docker (дані застосунку, Identity)

repository + NuGet  ->  dotnet restore --locked-mode / build
змінні середовища, appsettings  ->  старт API (Development / Production)
тека ключів Data Protection  ->  захист cookie й antiforgery-токенів
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Конкретний test або перевірка |
|---|---|---|
| browser -> API | змінювальний запит з cookie без дійсного antiforgery-токена відхиляється, ресурс не змінюється | REG-CSRF-01 (додається в ЛР 6) |
| browser -> API | текст користувача не виконується як код | ClientScript_DoesNotUseDangerousInnerHtmlSink, tests/browser/browser-lab-dom.js (ЛР 5) |
| browser -> API | Reporter не бачить і не змінює чужий інцидент; власника визначає сервер | Lab04AuthorizationTests A-03, A-04, A-11; Lab03SecurityTests A-05 |
| browser -> API | повторні спроби входу обмежено, відповідь 429 | LoginRateLimitTests.Login_AfterLimit_Returns429ForAnyAccount_ThenRecoversAfterWindow |
| API -> PostgreSQL | параметр пошуку не змінює структуру SQL | Lab02CustomTests.S02_RetestSqlInjection_ReturnsEmpty_AndPositiveControlPasses |
| API -> PostgreSQL | клієнт не отримує SQL, stack trace чи connection string у помилці | production-like перевірка 500 (етап 1, п. 4) |
| repository -> build | tracked files не містять реальних секретів; відкриті навчальні значення обмежені локальним стендом | git grep з етапу 1, п. 3 |
| repository -> build | restore не змінює lockfile непомітно | dotnet restore SecureLab.sln --locked-mode |
| environment -> configuration | у Production не діє Development-конфігурація, reset заборонено | Hosting environment: Production і відмова --reset-database (етап 1, п. 4) |
| environment -> configuration | ключі Data Protection не в Git і спільні для екземплярів API | advanced variant (після погодження) |

Зв'язок "актив -> загроза -> control -> перевірка" для ключових активів наведено в docs/security-review.md, розділ 3.