# Звіт ЛР04

Короткий звіт у репозиторії. Повний звіт з рисунками подано окремо у форматі Word.

## Контекст і межа виконання

- Рівень: відмінний («Відмінно»). Виконано всі кроки достатнього й доброго рівнів, A-11 і
  відокремлений resource-based handler.
- Baseline 2-A, base tag `v0.3.0` (`d6f7767`). Робота виконувалась у гілці `main`.
- Головна action: details/read `GET /api/incidents/{id}`; додатково mutation `PUT`,
  `DELETE`, triage і child resource коментарів.
- Політика відмов: 404 для чужого ресурсу (як для неіснуючого), 403 — коли ресурс видимий,
  але дія не дозволена, 401 — для аноніма.
- Виправлень стану ЛР 3 після тегу не було.

| Що | Commit |
|---|---|
| Internal comment у seed (comment-3) | `7265dc7` |
| Матриця доступу | `87ad99e` |
| Vulnerable state | `32db19f` |
| Fixed state | `1df093b` |
| Тести A-01…A-12, тег `v0.4.0` | `dff59dd` |

## Матриця і server-side рішення

Матриця — `docs/access-matrix.md`. Рішення для окремого інциденту ухвалює
`IncidentAuthorizationHandler` (`Application/Incidents/IncidentAuthorization.cs`) за
операціями `Read`, `Update`, `Delete`, `Triage`, `ReadInternalComments`. Входи handler —
principal (id і роль із server-issued claims), завантажений `Incident` і операція.
Список, пошук і severity-summary обмежено в самому запиті (`canReadAll || OwnerUserId == ownerId`).
Update DTO (`UpdateIncidentRequest`) містить лише `title` і `description`; triage DTO — лише `note`.

## Вразливий стан і PoC (`32db19f`)

| Запит | Очікувано за матрицею | Фактично до виправлення |
|---|---|---|
| Alice → `GET` власний інцидент | 200 | 200 |
| Alice → `GET` інцидент Bob | 404 | 200, дані Bob |
| Alice → `PUT` інцидент Bob | 404 | 200, title змінено |
| Alice (Reporter) → triage власного New | 403 | 200, status Triaged |
| Morgan (Analyst) → `PUT` інцидент Alice | 403 | 200, вміст змінено |
| Анонім → search `q=O'Brien`, severity-summary | 401 | 200, чужі дані |
| Alice → search `q=O'Brien` | `[]` | інцидент Bob …0004 |

Першопричина: інцидент шукався лише за id без порівняння з principal; triage не перевіряв
роль; search і severity-summary не мали обмеження видимості й автентифікації.

## Виправлення та retest (`1df093b`)

Ті самі запити після виправлення: Alice → Bob details/update/delete — 404 «Інцидент не знайдено»
(тіло збігається з відповіддю для неіснуючого id, крім `traceId`); Reporter triage — 403, status
лишився New; Analyst update/delete — 403; анонім — 401; search для Alice — `[]`;
severity-summary для Alice — Medium 1, Low 2. Позитивна регресія: власний інцидент Alice — 200,
Analyst читає інцидент Alice — 200, Analyst triage New → Triaged — 200.

## Доказова таблиця

| ID | Сценарій | Очікувано | Фактично | Доказ |
|---|---|---|---|---|
| A-01 | анонім → details | 401, без redirect | 401 | `A01_Details_AsAnonymous_Returns401_WithoutRedirect` |
| A-02 | Alice → власний | 200 | 200 | `A02_Details_AsOwner_ReturnsOwnIncident` |
| A-03 | Alice → Bob | 404 | 404, без даних Bob | `A03_Details_AsNonOwner_ReturnsNotFound_WithoutForeignData` |
| A-03R | Morgan → Alice | 200; update — 403 | 200; 403 | `A03R_*` (2 тести), `.http` блоки 18–19 |
| A-04 | Alice → Bob update/delete | 404, стан без змін | 404, стан без змін | `A04_*` (3 тести) |
| A-05 | list Alice | лише власні | лише власні | `A05_List_AsAlice_ContainsOnlyOwnIncidents` |
| A-06 | Reporter triage | 403, status New | 403, New | `A06_Triage_AsReporterOwner_ReturnsForbidden_AndStatusUnchanged` |
| A-07 | Analyst triage New | 200, Triaged | 200, Triaged; повтор — 409 | `A07_Triage_AsAnalyst_OnNewIncident_SetsTriaged` |
| A-08a | update з forged owner/status/severity/role | 200, змінено лише content | так | `A08a_Update_WithForgedFields_ChangesOnlyContent` |
| A-08b | — | не виконувалось: обрано A-08a | — | — |
| A-09 | audit denied triage | безпечна подія, той самий trace id | так | `A09_DeniedTriage_WritesSafeAuditEvent_WithResponseTraceId` |
| A-10 | чужий vs неіснуючий id | однакові status, Content-Type, тіло | так | `A10_ForeignAndUnknownDetails_ReturnSameProblemDetails` |
| A-11 | search і severity-summary | лише власні; анонім — 401 | так | `A11_*` (3 тести) |
| A-12 | коментар Bob; internal comment | 404 для Reporter; Analyst — 200 | так | `A12_*` (3 тести) |

Результат: `dotnet test` — total 56, failed 0 (20 нових тестів ЛР 4).

## Основний finding і залишковий ризик

IDOR/BOLA читання й зміни інциденту та вертикальне підвищення привілеїв через triage усунено
серверним handler і query scoping. Додатковий finding A-11: search і severity-summary були
доступні анонімно й розкривали чужі записи та агреговані дані; після виправлення обидва
маршрути вимагають login і обмежені тим самим правилом видимості.
Залишковий ризик: CSRF для cookie mutation до ЛР 6 — задокументований навчальний борг;
роль у cookie оновлюється лише після повторного login; concurrent transitions не перевірялись
(сценарію не надано); export/batch у проєкті немає.

## Browser flow

Login Alice на `auth-lab.html` → головна сторінка: у списку лише 3 інциденти Alice, деталі
власного відображено. `loadIncidentDetails` для id Bob — «Помилка: Інцидент не знайдено».
Відображення через `textContent`; UI не є механізмом контролю доступу.

## Перевірки й подання

Windows, .NET 10 SDK, PostgreSQL у Docker Compose. Reset:
`dotnet run --project src/SecureLab.Api -- --reset-database`. Тести:
`dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release`.
Сценарій ручних запитів: `tests/http/lab-04-access.http`.

## Використання ШІ

Під час роботи використовувався Claude для консультацій і прикладів коду та для оформлення звіту.
Код і тести переглянуто, адаптовано до власного проєкту, внесено поетапно й перевірено
самостійно: збіркою, тестами та ручними запитами.