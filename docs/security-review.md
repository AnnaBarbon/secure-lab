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
Відомий початковий стан, яка саме локальна БД, хеші початку й кінця, профіль запуску, конкретний клієнт і сеанс, команди та їхні коди завершення.
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
Для всіх рівнів: огляд поточної відстежуваної конфігурації й класифікація кожного збігу пошуку. Для доброго рівня додатково: таблиця рішень щодо залежностей, систематичний пошук у поточних відстежуваних файлах, повний огляд журналів і аудиту. Перевіряти всю історію не обов’язково — зазначте фактичні межі. Перевірки доброго рівня, які ви не виконували на достатньому, позначте «Не входить до обраного рівня», а не PASS.
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
