# Власна карта source-to-sink

Поле: Incident.Description. Стан: vulnerable `4e8404f` (scaffold lab-05-start-v1) → fixed `2b3f3de`. Вхід: Alice (`/auth-lab.html`), сторінка `/browser-lab.html`; запис — інцидент `d912e83a-2d6e-4693-9b89-02d00ea22342`, створений формою «Створити й прочитати» з канонічним marker.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, форма `#edit`, `<textarea name="description">` | текст, який вводить користувач | контрольоване користувачем |
| Request | `Client/browser-lab.js`, обробник `submit` форми `#edit` → `fetch("/api/incidents", { method: "POST" })` | JSON field `description` (`event.currentTarget.elements.description.value`) | Network → POST /api/incidents → Payload; контрольоване користувачем |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`, `POST /api/incidents`, `CreateIncidentRequest.Description` | `Trim()`, обов'язкове, ≤ 4000 символів, для High/Critical ≥ 40 | validation перевіряє довжину, а не HTML; значення не стає trusted |
| Storage | `Data/Entities/Incident.cs`, `Incident.Description` → PostgreSQL `incidents.description` | те саме значення, без змін | збережене значення користувача |
| Response | `GET /api/incidents/{id}` → `IncidentEndpoints.GetDetailsAsync` → `IncidentQueries.GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON field `description` | Network → GET → Response; авторизація ЛР 4 перевіряє право читати, а не вміст; JSON escape не захищає HTML sink |
| Client transform | `Client/browser-lab.js`, функція `load()`: `current = await response.json()` | `current.description` | значення без змін передається далі |
| Sink/context (до fix) | `browser-lab.js`, `load()`: `document.querySelector("#description").innerHTML = current.description` | елемент `<div id="description">` | **HTML parser context — небезпечно**: рядок, схожий на тег, браузер розбирає як HTML |
| Sink/context (після fix) | `browser-lab.js`, `load()` → `renderText(document.querySelector("#description"), current.description)` → `element.textContent = text` | той самий `<div id="description">` | **текстовий вузол — безпечно**: значення не передається HTML parser |

## Інвентаризація DOM sinks у `Client/browser-lab.js`

| Місце (функція) | Дані | Категорія даних | Контекст | Рішення |
|---|---|---|---|---|
| `load()`: `#status.textContent = \`GET: ${response.status}\`` | HTTP status | server-generated | текстовий вузол | безпечно |
| `load()`: `#title.textContent = current.title` | назва інциденту | збережене значення користувача | текстовий вузол | безпечно |
| `load()`: `#description.innerHTML = current.description` | опис інциденту | збережене значення користувача | **HTML parser** | **небезпечно — замінити на safe DOM (`textContent`)** |
| `load()`: `paragraph.innerHTML = comment.text` | текст коментаря | збережене значення користувача | **HTML parser** | **небезпечно — замінити на safe DOM (`textContent`)** |
| `load()`: `#edit.elements.description.value = current.description` | опис у полі форми | збережене значення користувача | властивість `value` поля форми (текст) | безпечно: `value` не розбирає HTML |
| submit: `#status.textContent = \`POST: ${response.status}\`` | HTTP status | server-generated | текстовий вузол | безпечно |
| submit: `#incident-id.value = created.id` | Guid із відповіді | server-generated | властивість `value` | безпечно |

Пошук `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, inline event attributes і динамічних URL у `browser-lab.js` дав лише два `innerHTML` (опис і коментарі). У `browser-lab.html` статичної розмітки з даними користувача немає; `#lab05-marker-target` — trusted constant.

## Другий потік: IncidentComment.Text («Добре / Відмінно»)

Запис: seed-інцидент Alice `20000000-0000-0000-0000-000000000001`, публічний коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal = false`), commit `d584466`.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker` → `IncidentComment.Text` | канонічний marker | у продукті коментар написав би будь-який автор; збережене значення користувача |
| Request | `GET /api/incidents/20000000-0000-0000-0000-000000000001` | body немає; Guid лише обирає parent incident | авторизація ЛР 4: Alice — власниця, Morgan — Analyst |
| Validation/mapping | seed без HTTP-валідації | значення без змін | seed не робить текст довіреним HTML |
| Storage | `IncidentComment.Text` → PostgreSQL `incident_comments.text` | той самий рядок | збережене значення користувача |
| Response | `IncidentQueries.GetDetailsAsync` → `IncidentCommentResponse.Text` | JSON field `comments[].text` | internal comment (`…0003`) для Reporter відфільтровано ще на сервері (ЛР 4) |
| Client transform | `browser-lab.js`, `load()`, цикл `for (const comment of current.comments ?? [])` | `comment.text` | без змін |
| Sink/context (до fix) | `paragraph.innerHTML = comment.text` | `<p>` у `<div id="comments">` | **HTML parser — небезпечно**: marker виконався, у DOM був `<img>` |
| Sink/context (після fix) | `fragment.append(renderText(document.createElement("p"), comment.text))`, потім `comments.replaceChildren(fragment)` | `<p>` з текстовим вузлом | **безпечно**; повторний render не дублює коментарі |

## Єдиний safe helper

`browser-lab.js`, функція `renderText(element, text)`: структуру задає код (`createElement`), значення записується лише через `textContent`. Виклики: опис — `renderText(document.querySelector("#description"), current.description)`; коментарі — `renderText(document.createElement("p"), comment.text)`.

## Поглиблена перевірка («Відмінно»)

`tests/browser/browser-lab-dom.js` (Console на `/browser-lab.html`, Chrome, fixed state): шість описів (marker, лапки, `<`/`>`, Unicode, `<b>`, 3900 символів) — для кожного `textContent` збігається з JSON, `childElementCount === 0`; коментарі seed-інциденту — кількість `<p>` дорівнює `comments.length`, кожен текст збігається, HTML-елементів немає; повторний `load()` дає ту саму кількість (без дублювання); marker не виконався. Результат: усі рядки `PASS`.

Інших sinks у власному client code немає: `app.js` (штатний клієнт) виводить дані через `createTextElement` (`textContent`), `auth-lab.js` — через `textContent`. Сторонніх scripts у досліджуваному flow немає: усі `<script src>` ведуть на власний origin.