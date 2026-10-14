import { apiFetch } from "./api-fetch.js";

// Власний сценарій register -> login -> profile -> create -> logout.
// Cookie сеансу ставить сервер (HttpOnly), JavaScript її не читає. Credentials і principal
// не записуються у localStorage/sessionStorage, dataset чи Console; вивід — лише через textContent.

const result = document.querySelector("#result");
const incidentResult = document.querySelector("#incident-result");
const profileFields = ["userId", "userName", "role"];

function showState(state) {
  for (const id of ["anonymous", "signed-in", "unknown"]) {
    document.querySelector(`#${id}`).hidden = id !== state;
  }
}

function clearProfile() {
  for (const field of profileFields) {
    document.querySelector(`#profile-${field}`).textContent = "—";
  }
}

function postJson(path, payload) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}

async function loadProfile() {
  let response;
  try {
    response = await apiFetch("/api/me");
  } catch {
    clearProfile();
    showState("unknown");
    result.textContent = "Профіль: помилка мережі.";
    return;
  }

  const isJson = (response.headers.get("Content-Type") ?? "").includes("application/json");
  if (response.ok && isJson) {
    const profile = await response.json();
    for (const field of profileFields) {
      document.querySelector(`#profile-${field}`).textContent = String(profile[field] ?? "");
    }
    showState("signed-in");
  } else if (response.status === 401) {
    clearProfile();
    showState("anonymous");
  } else {
    clearProfile();
    showState("unknown");
    result.textContent = `Профіль: ${response.status}`;
  }
}

document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const payload = {
    userName: String(data.get("userName") ?? ""),
    email: String(data.get("email") ?? ""),
    displayName: String(data.get("displayName") ?? ""),
    password: String(data.get("password") ?? "")
  };
  form.elements.password.value = "";
  try {
    const response = await postJson("/api/auth/register", payload);
    result.textContent = response.status === 201
      ? "Register: 201 — обліковий запис створено. Тепер увійдіть."
      : `Register: ${response.status}`;
    if (response.status === 201) {
      document.querySelector("#login").elements.userName.value = payload.userName;
    }
  } catch {
    result.textContent = "Помилка мережі під час реєстрації.";
  }
});

document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const payload = {
    userName: String(data.get("userName") ?? ""),
    password: String(data.get("password") ?? "")
  };
  form.elements.password.value = "";
  try {
    const response = await postJson("/api/auth/login", payload);
    result.textContent = `Login: ${response.status}`;
  } catch {
    result.textContent = "Помилка мережі під час входу.";
  }
  await loadProfile();
});

document.querySelector("#me").addEventListener("click", loadProfile);

document.querySelector("#incident").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const occurredAt = new Date(String(data.get("occurredAt") ?? ""));
  const payload = {
    title: String(data.get("title") ?? ""),
    description: String(data.get("description") ?? ""),
    severity: String(data.get("severity") ?? ""),
    occurredAtUtc: occurredAt.toISOString()
  };
  try {
    const response = await postJson("/api/incidents", payload);
    if (response.status === 201) {
      const created = await response.json();
      incidentResult.textContent = `Create: 201, id ${created.id}, статус ${created.status}`;
      form.reset();
    } else {
      incidentResult.textContent = `Create: ${response.status}`;
      if (response.status === 401) {
        await loadProfile();
      }
    }
  } catch {
    incidentResult.textContent = "Помилка мережі під час створення.";
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });
    clearProfile();
    incidentResult.textContent = "";
    const check = await apiFetch("/api/me");
    showState(check.status === 401 ? "anonymous" : "unknown");
    result.textContent = `Logout: ${response.status}; повторний /api/me: ${check.status}`;
  } catch {
    result.textContent = "Помилка мережі під час виходу.";
  }
});

await loadProfile();