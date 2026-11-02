# Власна карта source-to-sink

Поле: Incident.Description. Стан/commit: vulnerable `4e8404f` (scaffold lab-05-start-v1). Вхід: Alice (`/auth-lab.html`), сторінка `/browser-lab.html`; запис — новий інцидент, створений формою «Створити й прочитати» (Guid фіксується в `docs/browser-security-evidence.md`).

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, форма `#edit`, `<textarea name="description">` | текст, який вводить користувач | контрольоване користувачем |
| Request | `Client/browser-lab.js`, обробник `submit` форми `#edit` → `fetch("/api/incidents", { method: "POST" })` | JSON field `description` (`event.currentTarget.elements.description.value`) | Network → POST /api/incidents → Payload; контрольоване користувачем |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`, `POST /api/incidents`, `CreateIncidentRequest.Description` | `Trim()`, обов'язкове, ≤ 4000 символів, для High/Critical ≥ 40 | validation перевіряє довжину, а не HTML; значення не стає trusted |
| Storage | `Data/Entities/Incident.cs`, `Incident.Description` → PostgreSQL `incidents.description` | те саме значення, без змін | збережене значення користувача |
| Response | `GET /api/incidents/{id}` → `IncidentEndpoints.GetDetailsAsync` → `IncidentQueries.GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON field `description` | Network → GET → Response; авторизація ЛР 4 перевіряє право читати, а не вміст; JSON escape не захищає HTML sink |
| Client transform | `Client/browser-lab.js`, функція `load()`: `current = await response.json()` | `current.description` | значення без змін передається далі |
| Sink/context | `browser-lab.js`, `load()`: `document.querySelector("#description").innerHTML = current.description` | елемент `<div id="description">` | **HTML parser context — небезпечно**: рядок, схожий на тег, браузер розбирає як HTML |

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
