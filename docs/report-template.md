# Звіт до лабораторної роботи № 1

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: `main`.
- Фінальний тег: `v0.1.0`.
- Commit hash: прив'язаний до тегу `v0.1.0` (HEAD).

## 2. Змінений маршрут

**Ланцюжок обробки запиту на отримання підсумку за критичністю інцидентів:**
1. **Дія у браузері / Клієнт:** `Client/app.js` ініціює виклик або надсилається HTTP-запит `GET /api/incidents/severity-summary?status={status}`.
2. **Presentation (`IncidentEndpoints.cs`):** 
   - Обробник `GetSeveritySummaryAsync` зчитує необов'язковий параметр `status`.
   - Виконує allowlist-перевірку за списком дозволених значень (`New`, `Triaged`, `Resolved`) через `HashSet<string>(StringComparer.OrdinalIgnoreCase)`.
   - У разі невідповідності повертає `Results.ValidationProblem(...)` зі статусом 400 (RFC 9457).
   - Передає `HttpContext.TraceIdentifier` далі в шар Application.
3. **Application (`IncidentQueries.cs`):**
   - Безпечно парсить фільтр через `Enum.TryParse<IncidentStatus>` без прямих текстових операцій у SQL.
   - Формує структурований лог аудиту із зазначенням `TraceId`, застосованого фільтра та кількості знайдених груп (без чутливих даних).
4. **Data (`SecureLabDbContext.cs` / PostgreSQL):**
   - Виконує параметризовану фільтрацію та агрегацію на стороні СУБД: `query.GroupBy(i => i.Severity).Select(g => new { Severity = g.Key, Count = g.Count() })`.
   - На рівні пам'яті (Client Evaluation) перетворює enum у рядок, формує DTO `IncidentSeveritySummaryResponse` та сортує за спаданням кількості й зростанням назви.
5. **Повернення відповіді:** Клієнт отримує JSON зі статусом 200 OK, а `Client/app.js` безпечно відмальовує значення в DOM через властивість `textContent`.

## 3. Виконані зміни

1. **Реалізація точки розширення (GET /api/incidents/severity-summary):**
   - Замінено початкову заглушку `501 Not Implemented` на повноцінний конвеєр агрегації за категоріями критичності.
   - Додано підтримку необов'язкового query-параметра `status`.
   - Реалізовано стійку allowlist-валідацію вхідних даних.
   - Вирішено проблему несумісності трансляції enum у Npgsql EF Core за допомогою двоетапного виконання (Server SQL GroupBy + Client DTO Projection).
   - Додано наскрізне структуроване логування з прив'язкою до `TraceIdentifier`.

2. **Усунення архітектурного дефекту стартера (SPA Fallback):**
   - У `src/SecureLab.Api/Program.cs` виявлено та усунено проблему, коли неіснуючі API-маршрути помилково перехоплювалися викликом `app.MapFallbackToFile("index.html")`, повертаючи `200 text/html`.
   - Зареєстровано обробник `app.Map("/api/{*path}", ...)` для зони `/api/`, який гарантує повернення стандартизованого RFC 9457 `404 Problem Details` замість коду сторінки.

## 4. Перевірка

| ID | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|
| T-01 | Контейнер PostgreSQL запущено | `docker compose ps` | Сервіс СУБД у стані healthy на порту 15432 | Контейнер запущено, порт 15432 відкритий | Термінал Docker |
| T-02 | API запущено локально | Запит `GET /api/incidents/severity-summary` | Статус 200 OK, повний зріз інцидентів (3 групи) | 200 OK, масив із трьох об'єктів: High: 1, Low: 1, Medium: 1 | `incidents.http` (Рис. 3.26) |
| T-03 | Запуск тестового набору | Виконання `dotnet test` | Усі модульні та інтеграційні тести пройдені | 4 passed, 0 failed, час виконання ~1.5 с | Консоль тестування |
| T-04 | Клієнтська частина | Перевірка DOM Sink у `Client/app.js` | Використання безпечних властивостей без ризику XSS | Застосовано `textContent`, тест відсутності `innerHTML` пройдено | Тест `IncidentEndpointsTests` |
| T-05 | Фільтрація з даними | Запит `.../severity-summary?status=Triaged` | 200 OK, фільтрація на стороні СУБД | 200 OK, `[{"severity": "Medium", "count": 1}]` (час 25 мс) | Відповідь клієнта (Рис. 3.27) |
| T-06 | Фільтрація без збігів | Запит `.../severity-summary?status=Resolved` | 200 OK, порожній масив без падіння | 200 OK, `[]` (час 13 мс) | Відповідь клієнта (Рис. 3.28) |
| T-07 | Невалідний статус | Запит `.../severity-summary?status=Unknown` | 400 Bad Request (Validation Problem Details) | 400 Bad Request, `application/problem+json`, наявний traceId | Відповідь клієнта (Рис. 3.29) |
| T-08 | Неіснуючий API роут | Запит `GET /api/does-not-exist` | 404 Not Found у форматі JSON (локалізація відмови) | 404 Not Found, `application/problem+json`, `detail: "The requested API endpoint does not exist."` | Відповідь клієнта (Рис. 3.33) |

## 5. Security-сценарій

- **Гіпотеза:** Конфігурація SPA fallback без розмежування масок шляхів призводить до того, що звернення до неіснуючих сервісних точок повертають успішний код 200 OK та HTML-розмітку, маскуючи факт збою або фаззингу API від систем моніторингу та ламаючи JSON-парсери клієнтів.
- **Стан «до»:** Запит `GET /api/does-not-exist` перехоплювався `app.MapFallbackToFile("index.html")` і повертав `HTTP/1.1 200 OK`, `Content-Type: text/html`, розмітку `<!doctype html>...`.
- **Мінімальний локальний PoC:**
  ```http
  GET http://localhost:5080/api/does-not-exist
  Accept: application/json