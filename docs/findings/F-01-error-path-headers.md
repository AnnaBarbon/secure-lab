# F-01. Захисні заголовки зникають на відповіді 500

**Статус:** Fixed
**Актив:** браузерний клієнт і відповіді API (захист від MIME sniffing, витоку referrer, clickjacking)
**Компонент:** src/SecureLab.Api/Program.cs, middleware заголовків безпеки
**Пріоритет:** P3

## Передумови і межі огляду

Commit до виправлення: d78c98e (main). Production-like профіль: ASPNETCORE_ENVIRONMENT=Production, dotnet run --project src/SecureLab.Api --no-launch-profile -c Release; connection string на навмисно недоступний локальний порт 54399. Маршрут: POST /api/auth/login (публічний), вигаданий пароль, без cookie. Тестовий акаунт і реальний пароль не потрібні. Перевірено лише локальний стенд.

## Відтворення

1. Запустити API в Production з connection string на порт 54399.
2. Надіслати tests/http/lab-06-unexpected-error.http (VS Code REST Client).
3. Expected: 500 Problem Details і ті самі заголовки X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, що й на 200, 400, 404.
4. Actual до виправлення: 500 application/problem+json без X-Content-Type-Options, Referrer-Policy і Content-Security-Policy. На GET /, GET /api/incidents/{id} (200), GET /api/incidents?status=Unknown (400) і GET /api/incidents/{неіснуючий id} (404) усі три заголовки присутні.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Відповідь помилки лишається без nosniff, no-referrer і CSP з frame-ancestors 'none'. Пряма шкода обмежена: тіло 500 є коротким JSON без даних користувача. Проте захисна політика стає непослідовною: якщо пізніше помилка відображатиме сторінку або вміст, вона не матиме CSP і захисту від вбудовування. Ймовірність експлуатації низька, тому пріоритет P3.

## Першопричина

Middleware у Program.cs встановлював заголовки до виклику next(). Коли далі в конвеєрі виникає виняток, ExceptionHandlerMiddleware (app.UseExceptionHandler) очищає відповідь разом з уже встановленими заголовками і записує 500 заново. Тому заголовки, поставлені заздалегідь, на шляху помилки губляться.

## Виправлення

Заголовки встановлюються через context.Response.OnStarting(...). Callback виконується безпосередньо перед надсиланням будь-якої відповіді, зокрема відповіді, яку записує обробник помилок після очищення. Значення CSP і виключення для /scalar у Development не змінені. Окремий catch-all middleware не додавався, порядок конвеєра не змінено.

## Retest

1. Автоматично: REG_HDR_01_Unexpected500_KeepsSecurityHeaders_WithoutInternalDetails (tests/SecureLab.Api.Tests/Lab06RegressionTests.cs). До виправлення: failed, "The given header was not found" на X-Content-Type-Options. Після: succeeded.
2. Вручну: той самий запит у Production з портом 54399. Після виправлення 500 містить X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer, Content-Security-Policy з frame-ancestors 'none'.

## Positive regression

dotnet test SecureLab.sln -c Release: 57 з 57. Звичайні 200, 400, 404 і статична сторінка мають ті самі заголовки, що й раніше. Тіло 500 і далі містить лише type, title, status, traceId без Npgsql, порту, пароля БД і stack trace (перевіряє той самий тест).

## Залишковий ризик

Заголовки перевірено на 200, 400, 404, 500 і статичній сторінці. Відповіді, які формує сам Kestrel до входу в конвеєр (наприклад, 400 через некоректний HTTP-запит), цим middleware не охоплюються.

## Доказ

dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~REG_HDR_01": до виправлення failed: 1, після succeeded: 1. Ручна перевірка: tests/http/lab-06-unexpected-error.http у Production, порт БД 54399. Без пароля, cookie і connection string.