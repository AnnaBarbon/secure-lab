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

| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Повторна перевірка |
|---|---|---|---|---|---|---|
| F-02 | сесія користувача і всі cookie-автентифіковані зміни | цілісність: стороння сторінка того самого site завершила сесію alice; клас охоплював усі змінювальні маршрути | середня: сусідній origin того самого site, відкрита сесія, HTML-форма без JavaScript | P2 | Fixed | REG-CSRF-01, REG-CSRF-02, ручна форма з localhost:4174 |
| F-03 | antiforgery request token | стороння сторінка дозволеного Development origin читає токен; використати його не дає CORS preflight | низька: лише Development, лише localhost:4173, сесія жертви | P3 | Fixed | REG-CORS-02, ручна перевірка з localhost:4173 |
| F-01 | захисні заголовки браузера | на 500 немає nosniff, no-referrer, CSP: політика непослідовна, але тіло 500 без даних | низька: потрібна неочікувана помилка сервера | P3 | Fixed | REG-HDR-01, ручна перевірка в Production |

Порядок пріоритетів. F-02 перша: спостережено реальну зміну стану (вихід жертви) без жодних привілеїв, звичайною формою, а сам механізм відкривав усі cookie-автентифіковані зміни; SameSite=Lax і CORS цього не зупиняли. F-03 друга: дефект виник через взаємодію двох controls, токен справді читався стороннім JavaScript, але зміни стану без розширення CORS policy не дав і стосується лише Development. F-01 третя: наслідок обмежений відповіддю 500 з коротким JSON без даних користувача; заголовки є на всіх інших класах відповідей. Фактичний порядок робіт інший: F-01 виправлено першою, бо її знайдено ще на етапі 1 і виправлення ізольоване; F-02 закрито під час етапу 2 разом з усім периметром; F-03 знайдено під час огляду взаємодії CORS і antiforgery після введення маршруту токена. Тимчасово прийнятих ризиків серед findings немає.

## 6. Detailed findings

Кожна знахідка — окремий файл з передумовами, відтворенням, першопричиною, виправленням, retest і positive regression:
- docs/findings/F-01-error-path-headers.md
- docs/findings/F-02-logout-csrf.md
- docs/findings/F-03-csrf-token-cors.md

F-03 — додаткова знахідка поза прямим checklist: дефект взаємодії Development CORS (ЛР 5) з новим маршрутом видачі токена (ЛР 6), знайдений під час власного аналізу.

## 7. Regression results
### 7.1. Діагностичні журнали й аудит (етап 3, п. 4)

Діагностичний журнал (ILogger, консоль) потрібен оператору для пошуку причини збою за traceId. Журнал аудиту фіксує, хто, яку дію, над яким ресурсом, з яким результатом і коли виконав. Аудит привілейованого переходу Incident.Status має два канали: таблиця incident_status_history (дозволений перехід, з ЛР 4) і подія журналу з однаковим форматом для обох результатів: authorization.denied (ЛР 4) і audit ... result=allowed (додано в ЛР 6, IncidentEndpoints.TriageAsync, після SaveChangesAsync). Note, назва й опис інциденту в подію не потрапляють.

Збір: Development-запуск з дублюванням консолі у файл поза Git (dotnet run ... 2>&1 | Tee-Object -FilePath ..\lr06-logs\api.log), потім Production-запуск з недоступною БД, дописаний у той самий файл (-Append). Chrome: alice (звичайне вікно) і morgan (інкогніто). Після перевірки файл видалено.

| Сценарій | Що зроблено | Що є в журналі / відповіді |
|---|---|---|
| Successful login | alice, правильний пароль, Login: 204 | Auth event login: result succeeded, user <id>, trace <id> |
| Failed login | alice, вигаданий пароль NotARealPassword1!, Login: 401 | Auth event login: result failed, user anonymous, trace <id>; ім'я користувача й пароль не записано |
| Denied protected action | alice (Reporter) POST /api/incidents/7115ef08-.../triage: 403 | authorization.denied subject=10000000-...-0001 action=incident.triage resource=7115ef08-... result=denied occurredAtUtc=2026-11-16T12:43:02Z traceId=00-2a1030bb... |
| Validation error | GET /api/incidents?status=Unknown: 400 | відповідь Validation Problem Details; у журналі запису немає, введене значення Unknown не записано |
| Unexpected server error | Production, БД 54399, POST /api/auth/login: 500, traceId 00-634da2d2f424b80943ee35143030a8c2-742eb9d8fc3a2dce-00 | ExceptionHandlerMiddleware з TraceId:634da2d2f424b80943ee35143030a8c2; причина Npgsql без пароля й connection string |
| Privileged transition | morgan (Analyst) POST .../triage: 200, Triaged | audit subject=10000000-...-0003 action=incident.triage resource=7115ef08-... result=allowed from=New to=Triaged occurredAtUtc=2026-11-16T12:44:13Z traceId=00-c9837687...; у БД incident_status_history: New -> Triaged, changed_by_user_id ...0003, created_at_utc 2026-11-16 12:44:13 |

Пошук чутливих даних у ..\lr06-logs\api.log (Select-String; пароль береться зі змінної середовища, у команду не вписується):

| Що шукали | Збігів |
|---|---|
| навчальний пароль ($env:SeedUsers__Password) | 0 |
| NotARealPassword1! | 0 |
| cookie: / set-cookie | 0 |
| X-CSRF-TOKEN | 0 |
| CfDJ8 (початок значень, захищених Data Protection: cookie сесії, antiforgery-токен) | 0 |
| local-study-password / unreachable-study-value (паролі БД) | 0 |
| значення Unknown з запиту валідації | 0 |
| Позитивний контроль: Auth event login | 6 |
| Позитивний контроль: authorization.denied | 1 |
| Позитивний контроль: result=allowed | 1 |
| Позитивний контроль: ExceptionHandlerMiddleware | 2 |
| Позитивний контроль: trace 634da2d2f424b80943ee35143030a8c2 | > 0 |

Параметри SQL у журналі EF Core показано як '?' (sensitive data logging вимкнено). Повідомлення будуються structured logging з шаблонами, а не конкатенацією введення користувача, тому керівні символи в тексті не змінюють структуру запису (log injection). Межа висновку: лише ці шість сценаріїв і консольний sink одного запуску; інші sinks і маршрути не переглядалися.

### 7.2. Regression pack (етап 3, п. 5)

Known state: dotnet run --project src/SecureLab.Api -- --reset-database (Development), потім dotnet test SecureLab.sln -c Release (16.11.2026): 61 з 61. Сценарії ЛР 2-5 лишаються під своїми ID; нові REG-* надано лише сценаріям ЛР 6.

| Рівень | ID сценарію | Property | Передумови | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|---|
| добрий | T-02, T-05, T-10 (Lab02CustomTests) | server validation | reset, login alice, чинний токен | порожній title і невідома severity; невідомий sortBy; надто старий occurredAtUtc -> 400 | T-01: допустиме введення -> 201 | dotnet test, тести T02_*, T05_*, T10_*, T01_* | pass |
| достатній | S-02, T-04 (Lab02CustomTests) | query не змінює структуру SQL | seed | S-02: read-only SQLi у q -> порожній результат | T-04: пошук з апострофами -> 200 і очікувані записи | S02_RetestSqlInjection_ReturnsEmpty_AndPositiveControlPasses, T04_Search_WithApostrophes_Returns200AndExpectedEntities | pass |
| достатній | A-01, A-02, A-06, A-07 (Lab03SecurityTests) | identity lifecycle | навчальні акаунти | анонімне створення -> 401; невідомий користувач і хибний пароль однакові; після logout -> 401 | login -> /api/me повертає alice; logout 204 | A01_AnonymousCreate_*, A02_LoginThenMe_*, A06_LogoutThenSameClient_Gets401, A07_UnknownUserAndWrongPassword_LookTheSame | pass |
| достатній | A-03, A-04, A-06, A-11, A-12 (Lab04AuthorizationTests) | серверна перевірка власника й ролі | seed alice/bob/morgan | чужий інцидент -> 404 без даних; Reporter triage -> 403, статус не змінився; пошук без чужих записів | власник читає й видаляє свій New; Analyst triage -> Triaged | A03_*, A04_*, A06_*, A07_*, A11_*, A12_* | pass |
| достатній | REG-XSS-01 (ЛР 5) | текст не виконується як код | reset, local marker у seed-коментарі | marker <img onerror> не виконується, data-lab05-marker лишається null | складний текст (лапки, <, >, Unicode, <b>, 3900 символів) відображається дослівно | tests/browser/browser-lab-dom.js у Console browser-lab.html; ClientScript_DoesNotUseDangerousInnerHtmlSink | pass |
| добрий | REG-CORS-01 | точний scope browser origin | два development origins 4173/4174 | origin 4174 -> без Access-Control-*; preflight POST -> дозволено лише GET | origin 4173 -> Access-Control-Allow-Origin і Allow-Credentials | REG_CORS_01_OnlyAllowedDevelopmentOrigin_GetsCorsHeaders; ручні probes (розділ 8.2) | pass |
| достатній | REG-CSRF-01 | потрібна пара antiforgery-токенів | cookie alice, власний інцидент | без токена, з невалідним і з токеном bob -> 400, title не змінився | валідний токен alice -> 200, title змінився | REG_CSRF_01_Update_RequiresValidAntiforgeryToken_AndKeepsStateOnRejection | pass |
| відмінний | REG-CSRF-02 | токен на всьому cookie-периметрі | cookie alice і morgan | create, update, delete, triage, logout без токена -> 400, стан не змінився | ручна перевірка клієнта (розділ 8.3) | REG_CSRF_02_AllCookieMutations_WithoutToken_Return400_AndKeepState | pass |
| добрий | Login rate limit (ЛР 3) | abuse flow обмежено | quota 3/4 с у свіжому host | спроба понад quota -> 429, однаково для відомого й невідомого імені | після вікна -> 204; окремий host має власний лічильник | Login_AfterLimit_Returns429ForAnyAccount_ThenRecoversAfterWindow, Quota_BelongsToHost_NotToHttpClient | pass |
| добрий | REG-RL-01 | пошук обмежено для кожного користувача | quota 3/4 с у свіжому host | 4-й запит alice -> 429; анонім -> 401 | bob 200 (інший partition); після вікна alice 200 без чужих записів | REG_RL_01_Search_IsLimitedPerUser_AndRecoversAfterWindow; ручна перевірка (розділ 8.5) | pass |
| відмінний | REG-HDR-01 (F-01) | заголовки безпеки на шляху помилки | Production test host, БД 54399 | до виправлення 500 без заголовків | після виправлення 500 з nosniff, no-referrer, CSP без внутрішніх деталей | REG_HDR_01_Unexpected500_KeepsSecurityHeaders_WithoutInternalDetails | pass |

Повний REG-CSRF-01 автоматизовано: реальний login, cookie сесії й антифорджері-cookie в одному HttpClient (HandleCookies = true), токен отримується тим самим клієнтом з GET /api/auth/csrf-token, стан перевіряється повторним GET.

## 8. Hardening controls
### 8.1. Заголовки відповідей (етап 2, п. 1)

Заголовки ставить middleware у Program.cs через Response.OnStarting (після виправлення F-01). Значення CSP: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'.

| Клас | Profile і client | Method + route | Status | Фактичні значення | Ризик | Межа |
|---|---|---|---|---|---|---|
| Статична сторінка | Development, curl.exe, анонімно | GET / | 200 text/html | nosniff; no-referrer; CSP | MIME sniffing, витік referrer, вбудовування сторінки | не замінює правильний Content-Type і заборону секретів в URL |
| Успішний API | Development, Chrome, сеанс alice | GET /api/incidents/20000000-0000-0000-0000-000000000001 | 200 application/json | nosniff; no-referrer; CSP | те саме | не замінює authorization |
| Validation | Development, Chrome, сеанс alice | GET /api/incidents?status=Unknown | 400 application/problem+json | nosniff; no-referrer; CSP | те саме | не замінює validation |
| Unknown resource | Development, Chrome, сеанс alice | GET /api/incidents/99999999-9999-9999-9999-999999999999 | 404 application/problem+json | nosniff; no-referrer; CSP | те саме | однаковий 404 для чужого й неіснуючого задає authorization (ЛР 4) |
| Unexpected error | Production, no-launch-profile, REST Client, анонімно | POST /api/auth/login, БД 54399 | 500 application/problem+json | до виправлення: заголовків немає (F-01); після: nosniff; no-referrer; CSP | заголовки зникали на шляху помилки | REG-HDR-01 |

| Control | Що перевірено | Який ризик зменшує | Чого не замінює |
|---|---|---|---|
| Content-Security-Policy | policy відповідає клієнту: лише власні скрипти, стилі, зображення й fetch; flow /, /auth-lab.html, /browser-lab.html працює (ЛР 5) | частину наслідків injection і завантаження сторонніх ресурсів | безпечний DOM, validation, authorization |
| X-Content-Type-Options: nosniff | присутній на 200, 400, 404, 500 і статиці | MIME sniffing у браузері | правильний Content-Type на сервері |
| Referrer-Policy: no-referrer | присутній на всіх класах | витік referrer | заборону секретів в URL |
| frame-ancestors 'none' (у CSP) | присутній на всіх класах | clickjacking, вбудовування в чужі сторінки | authorization |
| CORS | лише Development, origin http://localhost:4173, метод GET, заголовок X-Lab-Cors-Probe, credentials | читання відповіді стороннім JavaScript | authentication, authorization, CSRF-захист |
| Auth cookie | HttpOnly, SameSite=Lax, Secure поза Development (CookieFlagsTests) | частину ризиків cookie в браузері | XSS, CSRF, серверну authorization |

### 8.2. CORS і профіль cookie (етап 2, п. 2, REG-CORS-01)

Profile: Development (dotnet run --launch-profile http), API http://localhost:5080; probes demonstrations/cors-probe через python -m http.server на 4173 (дозволений) і 4174 (недозволений); Chrome, сеанс alice.

| Сценарій | Origin | Результат |
|---|---|---|
| Браузер, GET /api/incidents з credentials | http://localhost:4173 | 200, JavaScript прочитав список; Access-Control-Allow-Origin: http://localhost:4173, Access-Control-Allow-Credentials: true |
| Браузер, той самий запит | http://localhost:4174 | у Network 200 OK, але без Access-Control-*; JavaScript відповідь не отримав ("Браузер не надав response JavaScript") |
| curl.exe GET /health | http://localhost:4173 | 200, Access-Control-Allow-Origin: http://localhost:4173, Allow-Credentials: true |
| curl.exe GET /health | http://localhost:4174 | 200, жодного Access-Control-* |
| curl.exe OPTIONS /api/incidents, Access-Control-Request-Method: POST | http://localhost:4173 | 204, Access-Control-Allow-Methods: GET; браузер не надішле cross-origin POST |

Автоматично: REG_CORS_01_OnlyAllowedDevelopmentOrigin_GetsCorsHeaders (Lab06RegressionTests).

Інтерпретація. Запит з 4174 у Network має 200 OK: сервер виконав його з cookie, браузер лише не віддав відповідь JavaScript. CORS обмежує читання відповіді, а не виконання запиту, тому не є захистом від CSRF. 4173 і 5080 — це той самий site (localhost), тому cookie з SameSite=Lax надсилається; різні порти localhost не є доказом поведінки SameSite між різними сайтами. Wildcard origin разом з credentials не використовується. У Production CORS policy не реєструється.

### 8.3. Периметр змінювальних маршрутів і antiforgery (етап 2, п. 3-5)

Джерела: git grep -n -E "\.Map(Post|Put|Patch|Delete)\(" -- src (7 маршрутів); git grep -n -E "method: *.(POST|PUT|PATCH|DELETE)" -- src/SecureLab.Api/Client (auth-lab.js, browser-lab.js); /openapi/v1.json у Development (ті самі 7 змінювальних маршрутів). Безпечні методи (GET) стан не змінюють; catch-all app.Map("/api/{*path}") лише повертає 404.

Контракт сервер-клієнт: request token видає GET /api/auth/csrf-token (лише автентифікованому користувачу, GetAndStoreTokens); клієнт повертає його в заголовку X-CSRF-TOKEN; cookie-частина пари: securelab.antiforgery (HttpOnly, ставить сервер). Валідація в одному місці: AntiforgeryEndpointFilter (src/SecureLab.Api/Presentation/Endpoints/Antiforgery.cs) викликає IAntiforgery.ValidateRequestAsync і перетворює AntiforgeryValidationException на 400 Problem Details "Antiforgery token is missing or invalid.". Фільтр виконується після authentication/authorization і до логіки маршруту.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | POST /api/auth/register | ЛР 3, OpenAPI, client call (auth-lab.js) | створює обліковий запис Reporter | ні | так | absent, обґрунтовано нижче | RegisterContractTests |
| SC-02 | POST /api/auth/login | ЛР 3, OpenAPI, client call (auth-lab.js) | видає cookie сесії | ні | так | absent, обґрунтовано нижче | LoginRateLimitTests, A-07 |
| SC-03 | POST /api/auth/logout | ЛР 3, OpenAPI, client call (auth-lab.js) | завершує сесію (SignOutAsync) | так | так | explicit, AntiforgeryEndpointFilter до SignOutAsync | REG-CSRF-02 |
| SC-04 | POST /api/incidents | ЛР 2-3, OpenAPI, client call (auth-lab.js, browser-lab.js) | створює інцидент; власник = principal | так | так | explicit, AntiforgeryEndpointFilter | REG-CSRF-02 |
| SC-05 | PUT /api/incidents/{id} | ЛР 4, OpenAPI; DISCREPANCY: виклику в клієнті немає | змінює title і description | так | так | explicit, AntiforgeryEndpointFilter | REG-CSRF-01 |
| SC-06 | DELETE /api/incidents/{id} | ЛР 4, OpenAPI; DISCREPANCY: виклику в клієнті немає | видаляє власний інцидент у статусі New | так | так | explicit, AntiforgeryEndpointFilter | REG-CSRF-02 |
| SC-07 | POST /api/incidents/{id}/triage | ЛР 4, OpenAPI; DISCREPANCY: виклику в клієнті немає | переводить статус New -> Triaged (Analyst) | так | так | explicit, AntiforgeryEndpointFilter | REG-CSRF-02 |

DISCREPANCY SC-05...SC-07: маршрути існують на сервері й в OpenAPI, але клієнт їх не викликає (UI для цих дій у ЛР 4 не створювався; їх використовують .http-сценарії й тести). Рішення: маршрути лишаються частиною API і захищені так само, бо CSRF атакує HTTP-маршрут, а не кнопку в інтерфейсі. Документацію узгоджено: усі три внесено до периметра.

Login і register (SC-01, SC-02) не довіряють наявній cookie сесії, тому їх не захищено токеном, що видається лише після входу. Окремий ризик: login CSRF (сторонній сайт входить у браузері жертви в акаунт нападника) і створення акаунта від імені браузера. Наслідок у SecureLab обмежений: жертва працює у чужому навчальному акаунті Reporter без доступу до її даних. Рішення: прийнято в межах огляду як residual risk; для захисту потрібен окремий анонімний bootstrap токена до входу. Login має rate limiter (5 спроб за 60 с).

Клієнтський helper: src/SecureLab.Api/Client/csrf.js (window.SecureLabCsrf.mutate), підключений перед page script на auth-lab.html і browser-lab.html; index.html змінювальних дій не має. Токен отримується lazy перед першою зміною на сторінці, зберігається лише в пам'яті сторінки, скидається після login, logout, відповіді 400/401 і на pageshow. Cookie JavaScript не читає й не копіює; автоматичного повтору запиту немає.

Ручна перевірка клієнта (Development, Chrome, 16.11.2026):

| Дія | Сторінка | Результат |
|---|---|---|
| Login alice, створення інциденту | auth-lab.html | Login: 204; Create: 201, статус New |
| Перехід, Ctrl+Shift+R і F5, "Створити й прочитати" | browser-lab.html | POST 201, GET: 200, показано створений інцидент |
| Logout | auth-lab.html | Logout: 204; повторний /api/me: 401 |
| Login bob, створення інциденту (новий principal, новий токен) | auth-lab.html | Login: 204; Create: 201 |
| DOM-тест ЛР 5 tests/browser/browser-lab-dom.js (alice) | browser-lab.html | усі PASS, опис і коментарі відображені як текст |
| POST /api/incidents без X-CSRF-TOKEN з Console (alice) | auth-lab.html | 400 "Antiforgery token is missing or invalid."; кількість інцидентів 3 -> 3; з токеном 201, 3 -> 4 |

REG-CSRF-01 (Lab06RegressionTests.REG_CSRF_01_Update_RequiresValidAntiforgeryToken_AndKeepsStateOnRejection), один HttpClient з HandleCookies = true як один браузер:

| Поле | Без токена / невалідний / токен іншого користувача | Валідна пара |
|---|---|---|
| Передумови | alice увійшла, створено власний інцидент, title записано | той самий інцидент і сесія |
| Request | PUT /api/incidents/{id}: без X-CSRF-TOKEN; з довільним рядком; з дійсним токеном bob | той самий PUT із токеном alice |
| Очікуваний результат | 400, title "Antiforgery token is missing or invalid." | 200 |
| Перевірка після request | GET /api/incidents/{id}: title не змінився | GET: title змінився на новий |
| Доказ | dotnet test --filter "FullyQualifiedName~Lab06RegressionTests": 4 з 4 | те саме |

REG-CSRF-02: для POST /api/incidents, PUT, DELETE, POST triage (morgan) і POST /api/auth/logout без токена 400; після кожного запиту перевірено стан: інцидент не створено, title не змінився, статус New, інцидент існує, /api/me 200.

Адаптація наявних тестів: CookieClient.LoginAsync після входу отримує токен тим самим клієнтом; AuthEventsTests, A-09 і SessionRevocationTests (ручний cookie) отримують токен перед logout або triage. Antiforgery не вимикався (.DisableAntiforgery() не використовується). dotnet test SecureLab.sln -c Release: 60 з 60.

### 8.4. HTTPS і HSTS (етап 2, п. 6)

Properties/launchSettings.json має лише профіль http з applicationUrl http://localhost:5080. У Program.cs немає UseHttpsRedirection() і UseHsts(). Reverse proxy або іншої межі TLS у проєкті немає. Отже, HTTPS (шифрування з'єднання), redirect (перенаправлення HTTP на HTTPS) і HSTS (браузер запам'ятовує, що хост доступний лише через HTTPS) у цьому стенді не реалізовані й не перевірялися. Відсутність заголовка Strict-Transport-Security на localhost не є дефектом: HSTS за замовчуванням не надсилається для loopback (ExcludedHosts: localhost, 127.0.0.1, [::1]), і змінювати це виключення заради демонстрації не потрібно. Локальний HTTP-профіль не доводить безпеки транспорту в production; реальний deployment, TLS termination і HSTS на production host не тестувалися (residual risk). Auth cookie поза Development має SecurePolicy.Always, тому в production працюватиме лише через HTTPS.

### 8.5. Rate limiting (етап 2, п. 7)

| Параметр | Login (ЛР 3, повторна перевірка) | Search (ЛР 6) |
|---|---|---|
| Маршрут | POST /api/auth/login | GET /api/incidents/search?q=&sortBy= |
| Partition key | IP-адреса з'єднання (RemoteIpAddress) | id автентифікованого користувача (claim NameIdentifier з cookie) |
| Quota / window | 5 за 60 с (LoginRateLimit:*) | 20 за 60 с (SearchRateLimit:*) |
| Алгоритм | fixed window, QueueLimit 0 | fixed window, QueueLimit 0 |
| Відмова | 429 | 429 |
| Місце в конвеєрі | UseRateLimiter після UseAuthentication і UseAuthorization | те саме: анонім отримує 401 до лічильника |

Чому такий ключ для search: пошук доступний лише автентифікованому користувачу, тому перевірена identity вже є. IP спільний для користувачів за NAT і дав би одному змогу вичерпати quota іншого; довільний заголовок клієнта не є перевіреною identity. Login не має автентифікованого користувача, тому там лишається IP (компроміс задокументовано в ЛР 3).

Перевірка за планом методики:

| Пункт | Login | Search |
|---|---|---|
| 1. У межах limit поведінка не ламається | LoginRateLimitTests: 3 невдалі спроби дають 401 | REG-RL-01: 3 запити 200; браузер: 20 запитів 200 |
| 2. Наступна спроба дає 429 | 429 і для правильного пароля, і для невідомого користувача | REG-RL-01: 4-й запит 429; браузер alice: 21-й і 22-й запит 429 |
| 3. Відновлення після вікна | після 4 с + 0,7 с вхід 204 | REG-RL-01: після 4 с + 0,7 с 200; браузер: alice через хвилину 200 |
| 4. Відповідь не розкриває існування акаунта | однаковий 429 для alice і невідомого імені, без Set-Cookie | 429 не залежить від q і вмісту |
| 5. Authorization окремо | обмеження не дає доступу до чужих даних | після відновлення результат alice не містить інциденту Bob; анонім 401, а не 429 |
| Два partitions | окремий test host має власні лічильники (Quota_BelongsToHost_NotToHttpClient) | REG-RL-01 і браузер: після вичерпання quota alice пошук bob дає 200 |

Ручна перевірка: Development, Chrome; alice (звичайне вікно) і bob (вікно інкогніто), Console fetch("/api/incidents/search?q=a").

Межа: limiter in-memory, його стан не спільний між кількома екземплярами API і обнуляється після перезапуску. Для одного локального екземпляра цього достатньо; для кількох екземплярів потрібне спільне сховище (residual risk).

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
Команди (16.11.2026, .NET SDK 10.0.302, global.json rollForward latestPatch): dotnet restore -> Restore complete, код 0, попереджень NU1901-NU1904 немає; dotnet package list --vulnerable --include-transitive -> код 0, джерело https://api.nuget.org/v3/index.json, "The given project SecureLab.Api has no vulnerable packages given the current sources", те саме для SecureLab.Api.Tests.

| Package | Version | Direct / transitive | Advisory / severity | Чи використовується relevant functionality | Доступне оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| (немає збігів) | версії з packages.lock.json | direct і transitive | джерело не повідомило про відомі advisories | не застосовно | не встановлювалось | дія не потрібна; NuGetAuditSuppress і WarningsNotAsErrors для NU190x не додавались |

Межа висновку: лише відомі на 16.11.2026 advisories джерела api.nuget.org для версій, зафіксованих у packages.lock.json обох проєктів. Досяжність коду, невідомі вразливості та пакети поза lock-файлами не оцінювались. Код 0 сам по собі не є доказом: висновок зроблено з тексту виводу для кожного проєкту. Нових пакетів у ЛР 6 не додавалось (antiforgery і rate limiting входять до ASP.NET Core).

Систематичний пошук у Git на commit 9dcb491: git status --short порожній; git ls-files -> 92 відстежувані файли; git grep -n -I -i -E 'password|passwd|secret|api.?key|token|connectionstring' -- . -> 351 збіг; нові відносно етапу 1 збіги (слово token) — назви заголовка X-CSRF-TOKEN, маршрут /api/auth/csrf-token, змінні й коментарі в Antiforgery.cs, csrf.js і тестах; значень токенів немає. Межа: поточні tracked files; history, stash, інші клони й зовнішні CI не перевірялися, крім історії appsettings.Development.json (розділ 9.1).

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
