# Звіт WEB ЛР 5

Автор: Барбон Анна Олександрівна, КБ-43. Спільний сценарій 2-A, рівень «Відмінно». ОС Windows, браузер Google Chrome. Повний звіт з рисунками подано окремо у форматі Word.

## Для всіх рівнів

**DEL-01:** карта — `docs/source-to-sink.md`; докази — `docs/browser-security-evidence.md`; DOM-тести — `tests/browser/`.

До → причина → fix → retest → залишковий ризик: збережений marker в описі (і в коментарі seed) виконувався в сеансі Alice та Morgan (Analyst) → `browser-lab.js`, `load()` передавала збережений текст у `innerHTML` (stored XSS з DOM-based sink) → safe helper `renderText` (`textContent`, `createElement`, `replaceChildren`) для обох полів → той самий marker видно як текст, `null`, значення в БД/API не змінилося, звичайний текст відображається правильно → нові sinks у майбутньому коді, виняток CSP для Development `/scalar`.

**DEL-02:** release `lab-05-start-v1`, base_commit `dff59dd` (v0.4.0); vulnerable `4e8404f`, fixed `2b3f3de`; CORS `13a8fbf`; CSP report-only `342ef86`; CSP enforcement і DOM-тести `1832f52`; тег `v0.5.0` = `1832f52`. Передано в приватний remote: `main` і `v0.5.0` (`git ls-remote`).

**DEL-03 — контрольні питання.**
1. **Чому value з БД може залишатися недовіреним?** У базу його записав користувач. Збереження й повернення через API не змінюють походження: це все ще збережене значення користувача, і браузер має показувати його як текст.
2. **Source, transformation, sink.** Source — поле форми `description`; transformations — POST DTO, валідація довжини, PostgreSQL, `IncidentDetailsResponse`, `response.json()`; sink — `#description.innerHTML` (до fix) / `textContent` через `renderText` (після).
3. **Stored, reflected, DOM-based.** Stored — значення зберігається й виконується під час пізнішого перегляду (наш випадок, у сеансі Morgan). Reflected — значення з запиту одразу повертається у відповіді сервера. DOM-based — небезпечне перетворення робить клієнтський JavaScript (у нас `innerHTML`). Ознаки не взаємовиключні: наш потік stored + DOM-based sink.
4. **Чому блокування `<script>` не усуває XSS?** Код виконується й без `<script>` — через атрибути-обробники (`onerror` у marker). Крім того, `innerHTML` не виконує вставлені `<script>`, але виконує обробники подій.
5. **textContent чи sanitizer?** Для звичайного тексту (наш контракт) — `textContent`. Sanitizer — лише якщо продукт справді вимагає обмежений HTML.
6. **Чому sanitizer не пишуть regex?** HTML має складні правила розбору; regex легко обійти іншим записом того самого. Потрібна перевірена бібліотека (DOMPurify) з мінімальним allowlist.
7. **Origin.** Схема + host + порт.
8. **Preflight.** Браузер сам надсилає `OPTIONS` з `Origin`, `Access-Control-Request-Method` і `Access-Control-Request-Headers` перед «непростим» запитом (у нас — заголовок `X-Lab-Cors-Probe`).
9. **Хто оголошує й хто застосовує CORS.** API оголошує дозвіл заголовками `Access-Control-Allow-*`; застосовує браузер — вирішує, чи віддати відповідь JavaScript сторінки.
10. **Чому curl читає відповідь?** Same-origin policy — правило браузера; curl його не має. Сервер однаково виконує запит і перевіряє автентифікацію.
11. **Чому CORS — не authorization і не CSRF-захист?** CORS керує лише читанням відповіді. Запит із 4174 з cookie Alice виконався на сервері (200), браузер лише не віддав відповідь. Право доступу перевіряє API (ЛР 4), а від CSRF потрібен antiforgery (ЛР 6).
12. **Wildcard і credentials.** Тоді будь-який сайт міг би читати відповіді від імені залогіненого користувача; ASP.NET Core таку policy не запускає.
13. **Межа CSP.** CSP обмежує джерела й блокує inline-обробники, але не робить небезпечний sink безпечним: дані все одно стали б HTML-елементами, і інший вектор міг би спрацювати. Тому спершу safe DOM, CSP — додатковий шар.
14. **nosniff, Referrer-Policy, frame-ancestors.** nosniff — браузер не вгадує тип вмісту; Referrer-Policy `no-referrer` — адреса з Guid не потрапляє на інші сайти; `frame-ancestors 'none'` — сторінку не вбудувати в чужий iframe (clickjacking).

## Додатково для Добре та Відмінно

IncidentComment.Text — `docs/source-to-sink.md`, «Другий потік»; safe helper `renderText` у `browser-lab.js`; preflight, cookie-дослід, CSP enforcement і headers — `docs/browser-security-evidence.md`.

**Review XSS / CORS / CSRF / authorization на власному flow.**
- XSS — браузер виконав дані як код; усунуто в sink (`textContent`).
- Authorization (ЛР 4) — Bob інцидент Alice не бачить (404), тому marker у його сеансі не виконувався; але Morgan має право читати, і саме тому XSS у сеансі Analyst небезпечний: авторизація не захищає від того, як браузер інтерпретує дозволені дані.
- CORS — визначає, чи може JavaScript іншого origin прочитати відповідь; дозволено лише `http://localhost:4173` у Development; 4174 — контроль.
- CSRF — запит з 4174 з cookie виконався на сервері, хоча CORS його «заблокував» для сторінки. Для запитів, що змінюють стан, потрібен окремий antiforgery-контроль — ЛР 6.

**Обґрунтування policy.** CORS: один точний origin, лише `GET` і один заголовок, без `AllowAnyOrigin`/`AllowAnyHeader`; `AllowCredentials()` потрібен для cookie-досліду й допустимий лише разом із точним origin; лише Development. CSP: усі директиви `'self'`, бо клієнт завантажує лише власні файли й звертається лише до власного API; `frame-ancestors 'none'`, бо вбудовування не потрібне; без `unsafe-inline` і `*`.

## Додатково для Відмінно

DOM-тест: `description-dom.js` — FAIL на `4e8404f` (`Text changed`), PASS на `2b3f3de`; `browser-lab-dom.js` — усі рядки PASS (шість описів, коментарі, повторний render без дублювання), Chrome. CSP: report-only (`342ef86`) — порушення лише записано; enforcement — `The action has been blocked.`, `(blocked:csp)`.

**Різні правила виведення.**
- Текстовий вузол — `textContent`/`createTextNode`: усе показується як символи.
- Атрибут — `setAttribute` для безпечних атрибутів; ніколи не створювати `on*`-атрибути з даних.
- URL (`href`/`src`) — розібрати через `new URL()` і дозволити лише `http:`/`https:` (і потрібні hosts), інакше не створювати посилання (`safe-url.js`); `textContent` тут не допомагає, небезпека — у схемі `javascript:`.
- JavaScript — дані ніколи не передаються в `eval`, `new Function`, `setTimeout(string)` чи inline handler; обробники лише через `addEventListener`.

**Third-party scripts.** У досліджуваному flow сторонніх scripts немає: усі `<script src>` ведуть на власний origin, і CSP `script-src 'self'` це закріплює. Сторонній код є лише в Development-довіднику `/scalar` (виключено з CSP клієнта); будь-який підключений сторонній script отримав би повний доступ до DOM і даних сторінки, тому його потрібно перевіряти окремо (ЛР 6).

## Декларація використання ШІ

Під час виконання лабораторної роботи використовувався сервіс Claude (Anthropic) для консультацій щодо XSS, CORS і CSP, прикладів фрагментів коду (safe helper, CORS policy, CSP header, розширений DOM-тест) і допомоги з оформленням звіту. Усі пропозиції самостійно переглянуто, адаптовано під baseline 2-A і методичку та поступово внесено у власний проєкт. Відтворення marker, retest, CORS-досліди, CSP у двох режимах, DOM-тести та автоматичні тести виконано й перевірено особисто на локальному стенді.

## Межі перевірки

Фактично перевірено: Description і Comment.Text у `/browser-lab.html`, штатні сторінки `/` і `/auth-lab.html` під CSP, CORS з 4173/4174 і curl, 56 автоматичних тестів ЛР 1–4. Поза стендом: cross-site поведінка SameSite (два порти localhost — той самий site), інші браузери, крім Chrome, і сторонній Development-довідник `/scalar`.