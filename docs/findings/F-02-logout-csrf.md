# F-02. Стороння сторінка того самого site завершує сесію через logout без antiforgery

**Статус:** Fixed
**Актив:** сесія користувача (authentication cookie) і цілісність його дій
**Компонент:** POST /api/auth/logout (src/SecureLab.Api/Scaffolding/Lab03Identity.cs); той самий клас охоплює всі cookie-автентифіковані змінювальні маршрути
**Пріоритет:** P2

## Передумови і межі огляду

Commit до виправлення: 064fab7 (CORS і заголовки вже є, antiforgery ще немає); після: e6dde94 (main). Development, профіль http, API http://localhost:5080. Chrome, alice увійшла на auth-lab.html. Стороння сторінка: статичний файл поза Git (..\lr06-logs\csrf-probe\index.html), python -m http.server 4174 --bind localhost. Сторінка містить лише HTML-форму method="post" action="http://localhost:5080/api/auth/logout", без JavaScript, без токена й без даних користувача. Перевірено лише локальний стенд.

## Відтворення

1. git switch --detach 064fab7; dotnet run --project src/SecureLab.Api --launch-profile http.
2. Увійти як alice на http://localhost:5080/auth-lab.html: "Сеанс активний".
3. У тому самому браузері відкрити http://localhost:4174 і натиснути кнопку форми.
4. Expected: сервер відхиляє змінювальний запит, ініційований іншим origin без доказу наміру користувача; сесія лишається чинною.
5. Actual до виправлення: POST /api/auth/logout -> 204, у відповіді Set-Cookie з порожнім значенням .AspNetCore.Identity.Application; після F5 auth-lab.html показує "Не ввійшли".

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

localhost:4174 і localhost:5080 — різні origins, але той самий site (порти не входять до site), тому cookie з SameSite=Lax надсилається і на POST-навігацію. CORS не заважає: звичайна форма не потребує preflight, а CORS обмежує лише читання відповіді. Спостережений наслідок — примусовий вихід (порушення цілісності сесії). Той самий клас дефекту стосувався всіх cookie-автентифікованих змінювальних маршрутів; для POST/PUT/DELETE з JSON-тілом браузер без CORS-дозволу не надішле application/json або PUT/DELETE, а application/x-www-form-urlencoded minimal API відхиляє, тому найпростіше експлуатувався саме маршрут без тіла. Ймовірність середня: потрібен сусідній origin того самого site (інший порт, сусідній піддомен) і відкрита сесія жертви. Пріоритет P2: реальний обхід SameSite у межах site, наслідок обмежений виходом, але механізм поширюється на весь клас маршрутів.

## Першопричина

Змінювальні маршрути, автентифіковані cookie, приймали запит лише на підставі cookie, яку браузер додає автоматично. Окремого доказу, що запит ініціював власний клієнт застосунку (token pair), не вимагалось. SameSite=Lax не розрізняє origins одного site.

## Виправлення

Додано ASP.NET Core antiforgery (src/SecureLab.Api/Presentation/Endpoints/Antiforgery.cs): GET /api/auth/csrf-token видає пару (HttpOnly cookie securelab.antiforgery + request token у JSON), AntiforgeryEndpointFilter перевіряє заголовок X-CSRF-TOKEN через IAntiforgery.ValidateRequestAsync і повертає 400 Problem Details до логіки маршруту. Фільтр підключено до всіх п'яти cookie-автентифікованих змінювальних маршрутів: POST /api/incidents, PUT і DELETE /api/incidents/{id}, POST /api/incidents/{id}/triage, POST /api/auth/logout (до SignOutAsync). Клієнтський helper csrf.js отримує токен і додає заголовок лише для same-origin змін. Commits b65503b і a7c332e.

## Retest

На e6dde94 той самий сценарій: форма з localhost:4174 -> POST /api/auth/logout -> 400, title "Antiforgery token is missing or invalid."; після F5 auth-lab.html показує "Сеанс активний" (alice). Автоматично: REG_CSRF_02_AllCookieMutations_WithoutToken_Return400_AndKeepState (logout без токена -> 400, /api/me -> 200) і REG_CSRF_01_Update_RequiresValidAntiforgeryToken_AndKeepsStateOnRejection.

## Positive regression

Logout із власного клієнта (auth-lab.html, кнопка "Вийти") -> 204, повторний /api/me -> 401; створення інцидентів на auth-lab.html і browser-lab.html -> 201; dotnet test SecureLab.sln -c Release -> 61 з 61.

## Залишковий ризик

Login і register токеном не захищені (login CSRF, розділ 8.3 review). Сторінка з дозволеного CORS origin могла читати request token (див. F-03).

## Доказ

Скріни Network (POST /api/auth/logout 204 на 064fab7; 400 на e6dde94) і стану сесії на auth-lab.html. Значення cookie й токенів не показано.