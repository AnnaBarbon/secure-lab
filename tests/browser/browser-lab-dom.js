// ЛР 5 · розширений DOM-тест для /browser-lab.html (рівень «Відмінно»).
// Запуск: увійти як Alice, відкрити /browser-lab.html, Ctrl+Shift+R, вставити весь файл у Console.
// Тест сам створює синтетичні інциденти через наявний POST /api/incidents, читає їх через load()
// і перевіряє фактичний DOM: текст збігається з JSON, HTML-елементів немає, marker не виконався.
// Потім перевіряє кожен comments[].text seed-інциденту Alice і повторний render без дублювання.
// Перед dotnet test виконайте --reset-database: створені тестом записи лишаються в локальній БД.
await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const markerAttr = () => document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker");
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  const marker = "<img src=x onerror=\"document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')\">";
  const cases = [
    ["marker", marker],
    ["quotes", "Користувач Д'Артаньян написав \"терміново\""],
    ["lt-gt", "5 < 7 і 9 > 3"],
    ["unicode", "Київ — Ω"],
    ["tag-b", "<b>жирний</b> текст"],
    ["long", "А".repeat(3900)]
  ];
  check(markerAttr() === null, "Reload page before test");
  const run = Date.now();

  for (const [name, description] of cases) {
      const created = await window.SecureLabCsrf.mutate("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: `DOM-test ${name} ${run}`, description, severity: "Low",
        occurredAtUtc: new Date().toISOString() })
    });
    check(created.status === 201, `${name}: POST ${created.status} (login as Alice?)`);
    const { id } = await created.json();
    document.querySelector("#incident-id").value = id;
    const data = await (await fetch(`/api/incidents/${encodeURIComponent(id)}`)).json();
    check(data.description === description, `${name}: stored value changed`);
    await load();
    const box = document.querySelector("#description");
    check(box.textContent === description, `${name}: DOM text differs from JSON`);
    check(box.childElementCount === 0, `${name}: data became HTML elements`);
    console.log(`PASS ${name}`);
  }

  document.querySelector("#incident-id").value = "20000000-0000-0000-0000-000000000001";
  const seed = await (await fetch("/api/incidents/20000000-0000-0000-0000-000000000001")).json();
  check(seed.comments.some(c => c.text.includes("data-lab05-marker")), "Seed comment with marker missing (reset?)");
  for (let pass = 1; pass <= 2; pass++) {
    await load();
    const paragraphs = document.querySelectorAll("#comments > p");
    check(paragraphs.length === seed.comments.length, `comments render ${pass}: count ${paragraphs.length}`);
    seed.comments.forEach((comment, i) => {
      check(paragraphs[i].textContent === comment.text, `comment ${i}: text differs`);
      check(paragraphs[i].childElementCount === 0, `comment ${i}: became HTML`);
    });
    console.log(`PASS comments render ${pass}: ${paragraphs.length} items, no duplicates`);
  }

  await wait(500);
  check(markerAttr() === null, "Marker executed");
  console.log("PASS: all descriptions and comments rendered as plain text");
})();
