# Докази безпеки браузера (DEL-01)

Рівень: відмінний («Відмінно»). Секретів, значень cookie/token і export browser storage цей файл не містить.

## Стенд і Git-стан

ОС: Windows; браузер: Google Chrome 156; API і штатний клієнт: `http://localhost:5080` (Development, `--launch-profile http`); probes: `http://localhost:4173` (дозволений), `http://localhost:4174` (контрольний). Робота виконана в гілці `main`.

Receipt `.scaffolds/lab-05.json`: release `lab-05-start-v1`, inherits `v0.4.0`, base_commit `dff59ddf8adbc2577aea02700518f60496ff70c8` (тег v0.4.0), entry_parent `9e2ba8953fe10a26b13a80f92dcc40491ba7828e` (короткий звіт ЛР 4 після тегу, тому entry_parent ≠ base_commit).

| Commit | Зміст |
|---|---|
| `4e8404f` | **vulnerable**: встановлено scaffold (два `innerHTML`) |
| `d584466` | seed: публічний коментар `…0005` з marker |
| `2b3f3de` | **fixed**: опис і коментарі через safe helper `renderText` |
| `13a8fbf` | Development-only CORS policy `Lab05BrowserProbe` для 4173 з credentials |
| `342ef86` | CSP у режимі report-only |
| `1832f52` | CSP enforcement і DOM-тести `tests/browser/` |
| `v0.5.0` | тег на перевіреному fixed state `1832f52`; документи ЛР 5 додано наступним commit |

Передавання: `git push origin main` і `git push origin v0.5.0` у приватний remote.

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080), без Value:

| Name | Domain | Path | HttpOnly | SameSite | Secure |
|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | localhost | / | так | Lax | ні (локальний HTTP, у Development `SameAsRequest`) |

## Гіпотеза й REG-XSS-01

Карта Description і Comment.Text: `docs/source-to-sink.md`.

Гіпотеза: значення з поля форми `description` (`browser-lab.html`, форма `#edit`) зберігається в `incidents.description`, повертається через JSON field `description` відповіді `GET /api/incidents/{id}` і передається в `#description.innerHTML` у функції `load()` (`browser-lab.js`) як HTML context; тому, якщо опис містить рядок, схожий на HTML-тег з атрибутом-обробником подій, браузер інтерпретує дані не як звичайний текст, а як розмітку й виконує обробник.

**REG-XSS-01 (повторювана процедура).**
- Передумови: commit fixed (`2b3f3de` або новіший); `$env:SeedUsers__Password` задано в терміналі; `dotnet run --project src/SecureLab.Api -- --reset-database`, потім `dotnet run --project src/SecureLab.Api --launch-profile http`; вхід Alice на `/auth-lab.html`, браузер Chrome з DevTools (Disable cache).
- Вхід: єдиний рядок файла `resources/lab05-marker.txt` (канонічний harmless marker, лише змінює атрибут `#lab05-marker-target`).
- Кроки: `/browser-lab.html` → Ctrl+Shift+R → Console: `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` → `null`; назва `LR5 marker`, у порожнє поле опису вставити marker → «Створити й прочитати» (POST 201, GET 200); повторити команду перевірки. Друге вікно (інкогніто): вхід Morgan, той самий Guid → «Прочитати» → команда перевірки. Третє (окремий профіль браузера): Bob, той самий Guid.
- Очікування (fixed): marker видно як текст; у `#description` один текстовий вузол, `<img>` немає; запиту `x` немає; команда перевірки — `null` в Alice й Morgan; Bob — `GET: 404`, `null`. Автоматично: `tests/browser/description-dom.js` (Guid у полі, без «Прочитати») → `PASS`.
- Негативний контроль (vulnerable `4e8404f`): marker виконувався — `'executed'` в Alice та Morgan, `<img src="x" onerror=…>` у DOM, запит `x`; `description-dom.js` → `Error: Text changed`.

| Спостереження | До fix (`4e8404f`/`d584466`) | Після fix (`2b3f3de`) | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | `incidents.description` і JSON `description` = marker | той самий рядок без змін | psql SELECT до/після; Network Response |
| DOM основного Description | `<div id="description">` містить елемент `<img src="x" onerror="…">` | один текстовий вузол із рядком marker | Elements до/після |
| Дія marker | `data-lab05-marker="executed"`; запит `x` у Network | `null`; запиту `x` немає | Console, Network |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | лапки/`<`/Unicode — без змін; `<b>жирний</b>` → напівжирний елемент `<b>`; seed `…0003` → видно лише «Текст», решта всередині `<script>` | усе видно символ у символ; `<b>жирний</b> текст` з дужками; seed `…0003` — усе речення | скріни сторінки й Elements |
| Довжина за власними правилами ЛР 2 | 3900 символів: POST 201, GET 200 | те саме, без помилок у Console | скрін; `browser-lab-dom.js` `PASS long` |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan: GET 200, `'executed'` (stored XSS у сеансі Analyst); Bob: GET 404, `null` | Morgan: GET 200, `null`; Bob: GET 404 | скріни вікон |
| Коментар `…0005` | у `#comments` елемент `<img>`, `'executed'` | `<p>` з текстовим вузлом, `null`; повторне «Прочитати» — без дублювання | Elements, Console |

**Finding.**
- Актив: сеанс браузера користувача (Alice, Morgan/Analyst) і дані, доступні від його імені.
- Передумови: локальний обліковий запис, який може створити інцидент; інший користувач з правом читання відкриває запис.
- Першопричина: недовірене збережене значення `description` (і `comments[].text`) передавалося в HTML sink `innerHTML` у `browser-lab.js`, `load()`. Серверна авторизація й валідація довжини правильні, але не визначають, як браузер інтерпретує текст.
- Класифікація: stored XSS (значення зберігається в БД і виконується під час пізнішого перегляду іншим користувачем) з DOM-based sink (небезпечне перетворення виконує клієнтський `innerHTML`).
- Вплив на стенді: marker лише встановив атрибут на `#lab05-marker-target`.
- Fix: safe DOM — helper `renderText` (`textContent`), `createElement` для `<p>`, `replaceChildren(fragment)`; formatted HTML за контрактом не дозволено, тому sanitizer не потрібний. Diff: `git diff 4e8404f..2b3f3de -- src/SecureLab.Api/Client/browser-lab.js`.
- Retest: той самий marker і той самий запис — не виконується; значення в БД/API не змінене; позитивна регресія пройдена.
- Залишковий ризик: нові sinks, які можуть з'явитися в майбутньому коді клієнта; Development-довідник `/scalar` (сторонній UI) виключено з CSP; CSP не захищає від помилки в safe sink, якщо дані вставлять у HTML; HttpOnly обмежує лише читання cookie, а не виконання коду.

## CORS і REG-CORS-01

Прогноз (Етап 3, крок 1), заповнено до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен |
| simple GET 4173 → API | так | до policy — ні; після policy — так | простий запит браузер надсилає одразу; читати відповідь дозволяє лише Access-Control-Allow-Origin для 4173 |
| simple GET 4174 → API | так | ні (і до, і після policy) | 4174 немає в allowlist, Access-Control-Allow-Origin не буде |
| curl/.http → API | так | не застосовується | це не браузерний JavaScript, same-origin policy не діє; працюють лише серверні перевірки API |
| preflighted 4173 → API | спершу OPTIONS; actual GET лише після успішного preflight | до policy — ні; після policy — так | non-safelisted header `X-Lab-Cors-Probe` змушує браузер спершу запитати дозвіл |

Команди запуску probes (з кореня проєкту, окремі термінали): `python -m http.server 4173 --bind localhost --directory demonstrations/cors-probe` і те саме з `4174`.

Policy — навчальний Development-стенд, відокремлений від штатної same-origin топології `http://localhost:5080`: `Program.cs`, `AddCors` → `Lab05BrowserProbe` (`WithOrigins("http://localhost:4173")`, `WithMethods("GET")`, `WithHeaders("X-Lab-Cors-Probe")`, `AllowCredentials()`), реєстрація й `UseCors` лише в `IsDevelopment()`; `UseRouting()` → `UseCors` → `UseAuthentication` → `UseAuthorization` → `UseRateLimiter`. У Production policy не реєструється.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | 200, читається | 200, читається | `/browser-lab.html` GET 200 |
| Allowed 4173 | GET 200 на сервері, Console `No 'Access-Control-Allow-Origin'`; з заголовком — OPTIONS 405, GET не надіслано | GET 200, `ACAO: http://localhost:4173`; з заголовком — OPTIONS 204 (`Allow-Origin`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`), потім GET 200 | Console `{status: 200, body: '{"status":"ready"}'}` |
| Disallowed 4174 | як 4173 до policy | GET 200 на сервері, ACAO відсутній, Console `No 'Access-Control-Allow-Origin'`; з заголовком — OPTIONS 204 без жодного `Access-Control-*`, GET не надіслано | Console TypeError |
| Direct HTTP / curl | 200, читається | 200, читається; ACAO лише для Origin 4173 | `curl.exe -i` |

REG-CORS-01 (fixed state):
- browser: 4173 читає відповідь, 4174 отримує `TypeError`; у Network обох — запит на `http://localhost:5080/health` з відповідним `Origin`;
- HTTP: `curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"` → `200 OK`, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`, `nosniff`, `no-referrer`; той самий запит з `Origin: http://localhost:4174` → `200 OK`, жодного `Access-Control-*`.

Перевірка порядку: з 4173 без cross-origin cookie `fetch("http://localhost:5080/api/incidents")` → JavaScript прочитав число `401` (без `blocked by CORS policy`) — CORS стоїть до authorization.

Різниця browser/direct HTTP: same-origin policy — правило браузера для веб-вмісту; curl не застосовує її й читає будь-яку відповідь, але все одно проходить автентифікацію й авторизацію API. CORS не зупиняє сам запит.

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: `docs/source-to-sink.md`, розділ «Другий потік». Seed-коментар `30000000-0000-0000-0000-000000000005` (Morgan, публічний, до інциденту Alice `…0001`), commit `d584466`. Тести ЛР 4 точну кількість коментарів не перевіряють, тому похідних очікувань змінювати не довелося. До fix — `<img>` у `#comments` і `'executed'`; після — текстовий вузол і `null`. Єдиний safe helper `renderText` у `browser-lab.js`, виклики для опису й коментарів.

Preflight: з 4173 — OPTIONS 204 з `Access-Control-Request-Headers: x-lab-cors-probe`, `Access-Control-Request-Method: GET` і трьома `Access-Control-Allow-*`, потім GET 200; з 4174 — OPTIONS 204 без `Access-Control-*`, actual GET не надіслано.

Cookie-дослід (вхід Alice в тому самому вікні):
- 4173, кнопка «GET» (`credentials: "include"`) → `200: [...]`, response `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`;
- 4174 → сторінка: «Браузер не надав response JavaScript…», Console `No 'Access-Control-Allow-Origin'`; у Network — **200 OK**: запит із cookie виконано на сервері, браузер лише не віддав відповідь;
- без `AllowCredentials()` (тимчасово) → є `Allow-Origin`, але немає `Allow-Credentials`, браузер відмовив; повернуто;
- інкогніто без входу, 4173 → JavaScript прочитав `401` з CORS headers.
Cookie надсилається з 4173 на 5080, бо обидва — той самий site (localhost); SameSite=Lax тут не спрацьовує. Кінцевий `AllowCredentials()` — лише в Development policy для 4173. Review XSS/CORS/CSRF/authorization — `docs/report-lab-05.md`.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | fallback для неявних типів | `'self'` |
| script-src | `/app.js`, `/browser-lab.js`, `/auth-lab.js`, `/api-fetch.js` — лише власні файли, inline scripts і inline handlers немає | `'self'` |
| style-src | `/styles.css`, inline styles немає | `'self'` |
| connect-src | `fetch` лише на `/api/...` того самого origin | `'self'`; probe-origins етапу 3 не додано — клієнт із них не працює |
| img-src | власних зображень немає; marker `src=x` — той самий origin | `'self'` |
| frame-ancestors | вбудовування продуктово не потрібне | `'none'` (не має fallback до default-src, тому явно) |

Місце зміни: наявна middleware headers у `Program.cs` (після `UseStatusCodePages`, до статичних файлів), змінна `csp`. Виняток: `/scalar` лише в Development (сторонній UI-довідник з власними ресурсами) — залишковий ризик, перевіряється в ЛР 6.

Enforcement: документ `/` 200, один заголовок `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'`; три сторінки flow (`/`, `/browser-lab.html`, `/auth-lab.html`) працюють без CSP-повідомлень; кероване порушення `new Image().src = "http://localhost:4173/x.png"` на `/` → `violates … "img-src 'self'". The action has been blocked.`, у Network `x.png (blocked:csp)`.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` (baseline) | браузер не «вгадує» тип за вмістом, тож, наприклад, текст не виконається як скрипт; не замінює правильний `Content-Type` і validation |
| Referrer-Policy | `no-referrer` (baseline) | адреса сторінки (з Guid інциденту) не передається іншим сайтам у `Referer`; клієнту referrer для навігації не потрібен, тому залишено; не дозволяє класти секрети в URL |
| frame-ancestors | `'none'` у CSP | сторінку не можна вбудувати в `<iframe>` чужого сайту (clickjacking); не замінює authorization і XSS fix. `X-Frame-Options` не додано, щоб не дублювати й не створювати суперечностей |

## Додатково для Відмінно

DOM-тест (Chrome, Console на `/browser-lab.html`, вхід Alice):
- `tests/browser/description-dom.js` на vulnerable `4e8404f` (Guid `d912e83a-…`) → `Uncaught Error: Text changed` (FAIL: `<img>` замість тексту); на fixed `2b3f3de` → `PASS: persisted description rendered as plain text`;
- `tests/browser/browser-lab-dom.js` (fixed, під CSP enforcement) → `PASS marker`, `PASS quotes`, `PASS lt-gt`, `PASS unicode`, `PASS tag-b`, `PASS long`, `PASS comments render 1: 2 items, no duplicates`, `PASS comments render 2: 2 items, no duplicates`, `PASS: all descriptions and comments rendered as plain text`. Для Alice у seed-інциденті два публічні коментарі (internal `…0003` відфільтровано сервером).

CSP report-only → enforcement:
- report-only (`342ef86`): документ 200, `Content-Security-Policy-Report-Only: …`; flow без повідомлень; кероване порушення → `… The policy is report-only, so the violation has been logged but no further action has been taken.`, запит `x.png` пішов на 4173 (404 від Python-сервера);
- enforcement: див. вище — `The action has been blocked.`, `(blocked:csp)`.

`safe-url.js` (Console): `https://example.com/a`, `http://localhost:5080/incidents/1`, `null`, `null`, `null`, `http://localhost:5080/incidents/1`, `null` — `javascript:` у будь-якому регістрі й з пробілом відхилено, створене посилання має лише `href`, `onclick` немає.

Пояснення text/attribute/URL/JavaScript і ризик third-party scripts — `docs/report-lab-05.md`.