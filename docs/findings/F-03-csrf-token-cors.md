# F-03. Development CORS дозволяє сторонньому origin читати antiforgery-токен

**Статус:** Fixed
**Актив:** request token antiforgery (доказ, що змінювальний запит ініціював власний клієнт)
**Компонент:** GET /api/auth/csrf-token (src/SecureLab.Api/Presentation/Endpoints/Antiforgery.cs) разом з Development CORS policy Lab05BrowserProbe (Program.cs)
**Пріоритет:** P3

## Передумови і межі огляду

Commit до виправлення: c898a82 (main). Development, профіль http, API http://localhost:5080. CORS policy Lab05BrowserProbe (ЛР 5): origin http://localhost:4173, метод GET, заголовок X-Lab-Cors-Probe, AllowCredentials; застосовується до всіх маршрутів. Chrome, alice увійшла на auth-lab.html. Сторінка demonstrations/cors-probe через python -m http.server 4173. Значення токена не друкувалось, лише його довжина. Перевірено лише локальний стенд; у Production CORS policy не реєструється.

## Відтворення

1. Увійти як alice на http://localhost:5080/auth-lab.html.
2. Відкрити http://localhost:4173, у Console: fetch("http://localhost:5080/api/auth/csrf-token", { credentials: "include" }), потім r.json().
3. Expected: JavaScript іншого origin не може прочитати request token.
4. Actual до виправлення: cross-origin read 200, token length 198 — стороння сторінка отримала токен Alice.
5. Спроба використати токен: POST /api/auth/logout із заголовком X-CSRF-TOKEN з 4173 -> заблоковано preflight ("Request header field x-csrf-token is not allowed by Access-Control-Allow-Headers"), сесія Alice лишилась активною.
6. Автоматично: REG_CORS_02_CsrfTokenRoute_IsNotReadableFromAllowedCorsOrigin до виправлення — failed (Assert.False для Access-Control-Allow-Origin: Actual True).

## Вплив і ймовірність

**Статус перевірки:** спостережено локально (читання); використання токена не вдалося.

Control з ЛР 5 (Development CORS для GET) після пізнішої зміни (новий GET-маршрут видачі токена в ЛР 6) почав охоплювати маршрут, відповідь якого не призначена для інших origins. Окремо токен не дає зміни стану: для його використання потрібен власний заголовок, а policy дозволяє лише GET і X-Lab-Cors-Probe, тому preflight блокує запит. Проте захист від CSRF тепер залежить від того, щоб CORS policy ніколи не розширили (наприклад, на AllowAnyHeader або нові методи). Ймовірність низька: лише Development, лише дозволений origin, потрібна сесія жертви. Пріоритет P3: defense-in-depth, а не прямий обхід.

## Першопричина

CORS policy застосовується глобально (app.UseCors("Lab05BrowserProbe")) до всіх маршрутів, а новий маршрут токена не виключено. Логіка CORS і логіка antiforgery розглядались окремо.

## Виправлення

На маршрут GET /api/auth/csrf-token додано metadata DisableCorsAttribute (.WithMetadata(new DisableCorsAttribute())). CORS middleware для цього маршруту не додає Access-Control-* заголовків, тож браузер не віддає відповідь іншому origin. Policy для інших маршрутів не змінено. Same-origin клієнт (csrf.js) отримує токен як і раніше.

## Retest

1. REG_CORS_02_CsrfTokenRoute_IsNotReadableFromAllowedCorsOrigin: після виправлення succeeded; токен-маршрут з Origin http://localhost:4173 -> 200 без Access-Control-Allow-Origin і Allow-Credentials.
2. Вручну з http://localhost:4173: читання /api/auth/csrf-token -> "No 'Access-Control-Allow-Origin' header is present", Failed to fetch.

## Positive regression

З 4173 GET /api/incidents з credentials -> 200 (REG-CORS-01 і та сама перевірка в REG-CORS-02); auth-lab.html створення інциденту -> Create: 201; dotnet test SecureLab.sln -c Release -> 62 з 62.

## Залишковий ризик

Інші GET-маршрути API для дозволеного Development origin лишаються читабельними за задумом ЛР 5. Нові GET-маршрути з чутливими значеннями потрібно перевіряти на CORS окремо (покриває REG-CORS-02 лише для маршруту токена).

## Доказ

Console на http://localhost:4173 до і після; dotnet test --filter "FullyQualifiedName~REG_CORS_02" failed -> succeeded. Значення токена й cookie не показано.