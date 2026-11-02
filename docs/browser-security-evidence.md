# Докази безпеки браузера (DEL-01)

Рівень: відмінний («Відмінно»). Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюйте лише розділи свого рівня й усі попередні. Не записуйте паролі, cookie/token values чи export browser storage.

## Стенд і Git-стан (Для всіх)

ОС: Windows; браузер: Google Chrome; API origin: `http://localhost:5080`; probe origins: `http://localhost:4173` (дозволений), `http://localhost:4174` (контрольний).

Receipt `.scaffolds/lab-05.json`: release `lab-05-start-v1`, inherits `v0.4.0`, base_commit `dff59ddf8adbc2577aea02700518f60496ff70c8` (тег v0.4.0), entry_parent `9e2ba8953fe10a26b13a80f92dcc40491ba7828e` (короткий звіт ЛР 4 після тегу; тому entry_parent відрізняється від base_commit). Робота виконується в гілці `main`.

Vulnerable commit: `4e8404f` (lab5: install scaffold lab-05-start-v1). Fixed commit, v0.5.0 і спосіб передавання: …

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080), без Value:

| Name | Domain | Path | HttpOnly | SameSite | Secure |
|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | localhost | / | так | Lax | ні (локальний HTTP, у Development `SameAsRequest`) |

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: `docs/source-to-sink.md`.

Гіпотеза: значення з поля форми `description` (`browser-lab.html`, форма `#edit`) зберігається в `incidents.description`, повертається через JSON field `description` відповіді `GET /api/incidents/{id}` і передається в `#description.innerHTML` у функції `load()` (`browser-lab.js`) як HTML context; тому, якщо опис містить рядок, схожий на HTML-тег з атрибутом-обробником подій, браузер інтерпретує дані не як звичайний текст, а як розмітку й виконує обробник. Передумови, локальний користувач, Guid запису, marker із resources/lab05-marker.txt, команди reset/start і create/read: …

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | | | |
| DOM основного Description | | | |
| Дія marker | | | |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | | | |
| Довжина за власними правилами ЛР 2 | | | |
| Вікно Morgan: GET і перевірка marker; контроль Bob | | | |

Finding: актив; передумови; першопричина; safe DOM diff; retest; залишковий ризик: … Повторювана REG-XSS-01, негативний контроль і очікування: …

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповніть до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен |
| simple GET 4173 → API | так | до policy — ні; після policy — так | простий запит браузер надсилає одразу; читати відповідь дозволяє лише Access-Control-Allow-Origin для 4173 |
| simple GET 4174 → API | так | ні (і до, і після policy) | 4174 немає в allowlist, Access-Control-Allow-Origin не буде |
| curl/.http → API | так | не застосовується | це не браузерний JavaScript, same-origin policy не діє; працюють лише серверні перевірки API |
| preflighted 4173 → API | спершу OPTIONS; actual GET лише після успішного preflight | до policy — ні; після policy — так | non-safelisted header X-Lab-Cors-Probe змушує браузер спершу запитати дозвіл |

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | | | |
| Allowed 4173 | | | |
| Disallowed 4174 | | | |
| Direct HTTP / curl | | | |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … safe-url.js / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавайте. Перед поданням повторіть чекліст для свого накопичувального рівня.
