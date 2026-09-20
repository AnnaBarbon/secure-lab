# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents, GET /api/incidents/{id} або GET /api/incidents/severity-summary?status={status}
  → Presentation/Endpoints/IncidentEndpoints.cs (allowlist-перевірка status, 400 Problem Details або прокидання traceId)
  → Application/Incidents/IncidentQueries.cs (безпечний Enum.TryParse, логування події з TraceId)
  → Data/SecureLabDbContext.cs (LINQ GroupBy/Count на стороні сервера, client evaluation для enum-проєкції)
  → PostgreSQL (виконання агрегаційного SQL-запиту)
  → response DTO у Presentation/Contracts/ (IncidentSeveritySummaryResponse без надлишкових полів сутності)
  → JSON (application/json або application/problem+json)
  → textContent/createTextNode у Client/app.js (безпечний рендеринг без XSS-вразливостей)
```

## Межі довіри

Доповніть таблицю щонайменше трьома конкретними спостереженнями.

| Межа | Чому даним ще не можна довіряти | Де перевіряємо або обмежуємо |
|---|---|---|
| Користувач → Browser client | Користувач контролює введення та маніпулює станом сторінки | UI обмежує вибір лише фіксованим списком через елемент <select>, блокує надсилання некоректних типів даних до відправки запиту |
| Browser client → API | Клієнт і HTTP-запит можна змінити поза UI (curl, Burp Suite, скрипти); можлива передача невідомих статусів або звернення до неіснуючих ендпоінтів | Allowlist-валідація параметра status у IncidentEndpoints.cs через HashSet (повертає 400 ValidationProblem); перехоплення невідомих маршрутів /api/{*path} у Program.cs із поверненням 404 Problem Details замість fallback-відповіді SPA |
| PostgreSQL → API → DOM | У БД може зберігатися раніше введений недовірений текст (ризик Stored XSS при виведенні на клієнті) | Відокремлення моделі БД від вихідного контракту через IncidentSeveritySummaryResponse; безпечна вставка значень у браузері суворо через властивість textContent без використання небезпечного sink innerHTML |

## Конфігураційні входи

- `global.json` — версія .NET SDK;
- `src/SecureLab.Api/appsettings*.json` — режим міграцій і локальний connection string;
- `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.
