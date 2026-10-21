# Матриця доступу ЛР04

Предметне правило — канонічний baseline 2-A: Reporter створює й редагує власний запис;
Analyst читає інциденти для аналізу й може перевести лише New → Triaged; Administrator має
тільки ті права, які прямо опубліковано для предметної області. Окремих адміністративних
операцій над Incident не опубліковано, тому Administrator не отримує прав понад звичайного
власника. Усе, що матриця прямо не дозволяє, заборонено (least privilege).

Роль береться лише з server-issued role claim у `HttpContext.User`, сформованого під час login.
Власник — `Incident.OwnerUserId`, порівнюється з `ClaimTypes.NameIdentifier` principal.

Рішення для окремого інциденту ухвалює `IncidentAuthorizationHandler`
(`Application/Incidents/IncidentAuthorization.cs`, операції `IncidentOperations`).
Список, пошук і зведення обмежено в самому запиті (query scoping).

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---:|---:|---:|---:|---:|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | лише власні інциденти (фільтр за `OwnerUserId` у самому запиті) | усі інциденти (для аналізу) | лише власні інциденти, як Reporter | Так для Reporter і Administrator | Реалізовано: `IncidentQueries.GetListAsync`; A-05 |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | deny, 401 | лише власні; фільтр до сортування й `Take(50)` | усі інциденти | лише власні | Так для Reporter і Administrator | Реалізовано: `Lab02Endpoints`, фільтр у запиті; A-11 |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | deny, 401 | лише власні; фільтр до групування за severity | усі інциденти | лише власні | Так для Reporter і Administrator | Реалізовано: `IncidentQueries.GetSeveritySummaryAsync`; A-11 |
| Перегляд деталей `GET /api/incidents/{id}` | достатній, entry-контракт ЛР 5 | deny, 401 | owner — allow, 200; non-owner — deny, 404 як для неіснуючого | allow, 200 для будь-якого інциденту; internal comments включаються | owner — allow; non-owner — deny, 404 | Так | Реалізовано: handler, операція `Read`; A-01, A-02, A-03, A-03R, A-10 |
| Створення інциденту `POST /api/incidents` | успадкований baseline | deny, 401 | allow; власник = principal | allow; власник = principal | allow; власник = principal | Сервер призначає власника | Реалізовано в ЛР 3; перевірено тестами ЛР 3 |
| Update content `PUT /api/incidents/{id}` (лише title, description) | добрий | deny, 401 | owner — allow, 200; non-owner — deny, 404 | deny, 403 (ресурс видимий, але змінювати вміст Analyst не має права) | owner — allow; non-owner — deny, 404 | Так | Реалізовано: handler, операція `Update`; A-04, A-08a |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner — allow, 204, лише поки status = New; owner при іншому status — deny, 403; non-owner — deny, 404 | deny, 403 | як Reporter: власний New — 204, власний не New — 403; чужий — 404 | Так | Реалізовано: handler, операція `Delete`; A-04 |
| Зміна severity/status `POST /api/incidents/{id}/triage` | добрий | deny, 401 | owner — deny, 403; non-owner — deny, 404 | allow лише New → Triaged, 200; інший поточний status — 409, стан не змінюється | власний — deny, 403; чужий — deny, 404 | Ні для права Analyst; для Reporter визначає 403 чи 404 | Реалізовано: handler, операція `Triage`, audit `authorization.denied`; A-06, A-07, A-09 |
| Перегляд internal comment `GET /api/incident-comments/{id}` і коментарі в details | добрий | deny, 401 | deny: internal comment не включається в details, за прямим id — 404; публічний коментар власного інциденту — 200; коментар чужого інциденту — 404 | allow, 200, після перевірки доступу до parent incident | як Reporter | Ні для internal rule; доступ до parent incident перевіряється окремо | Реалізовано: handler, операції `Read` і `ReadInternalComments`; A-12 |
| Export/audit | відмінний, якщо flow існує | не застосовується | не застосовується | не застосовується | не застосовується | не застосовується | Такого flow у проєкті немає |

Severity задається лише під час створення. Звичайний update DTO не містить severity, status,
owner чи role, тому ці поля не можуть бути змінені через update.

## Політика HTTP-відмов

| Ситуація | Відповідь |
|---|---|
| Немає verified principal | 401 Unauthorized, без HTML redirect |
| Інцидент не існує або principal не має права його бачити (чужий для Reporter/Administrator) | 404, однаковий Problem Details «Інцидент не знайдено» без id у detail |
| Principal бачить інцидент (owner або Analyst), але дія йому не дозволена | 403 Forbidden |
| Дія дозволена, але поточний status не допускає переходу | 409 Conflict |

Обрано політику 404 для чужого ресурсу. Reporter не повинен дізнаватися, чи існує інцидент
іншого користувача: відповідь для чужого й для неіснуючого id однакова за status,
Content-Type і тілом (відрізняється лише `traceId`). Обидві гілки викликають один helper
`IncidentNotFound()`. Те саме правило застосовано до details, update, delete, triage і child
endpoint коментарів (для коментаря — `CommentNotFound()`, «Коментар не знайдено»).
403 повертається лише тоді, коли існування ресурсу для цього principal не є секретом,
бо він його вже може читати.

## Привілейована дія

- Дія: `POST /api/incidents/{id}/triage`, перехід New → Triaged.
- Роль: Analyst (роль із server-issued claim).
- Context: поточний status інциденту з БД має бути New; наступний status встановлює сервер.
  Ownership для Analyst не має значення.
- Owner-Reporter обмеженого переходу не виконує (403); інший Reporter отримує 404;
  Administrator — 403 для власного, 404 для чужого.
- Request містить лише `note`; role, owner чи status не є input авторизації.
- Після deny записується audit event `authorization.denied`: id суб'єкта з principal, action
  `incident.triage`, id інциденту, result `denied`, серверний час і той самий trace id, що й у
  відповіді клієнтові. Без пароля, cookie, token і тіла запиту.

## Child resource

`IncidentComment` — дочірній ресурс, через який можна непрямо отримати дані інциденту.
Доступ до коментаря за прямим id спершу перевіряє право читати parent incident; internal
comment додатково доступний лише Analyst. Те саме правило діє в details-проєкції.