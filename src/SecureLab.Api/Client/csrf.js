// ЛР 6: один helper для змінювальних запитів на всіх сторінках клієнта.
// Request token отримується lazy перед першою зміною на поточній сторінці й зберігається лише
// в пам'яті сторінки (не в localStorage/sessionStorage). Cookie JavaScript не читає й не копіює.
(() => {
  const headerName = "X-CSRF-TOKEN";
  let token = null;
  let pending = null;
  let generation = 0;

  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch("/api/auth/csrf-token", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error(`Token request failed: ${response.status}`);
      const data = await response.json();
      if (current !== generation) throw new Error("Session changed; request a fresh token.");
      if (typeof data.token !== "string" || !data.token) throw new Error("Invalid token response.");
      token = data.token;
      return token;
    })();
    pending = operation;
    try { return await operation; }
    finally { if (pending === operation) pending = null; }
  }

  async function mutate(url, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      throw new Error("Use normal fetch for read requests.");
    }
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) {
      throw new Error("Token must stay on the same origin.");
    }
    const headers = new Headers(options.headers);
    headers.set(headerName, await ensureToken());
    const response = await fetch(target, { ...options, method, headers, credentials: "same-origin" });
    // Після відмови токен скидається; запит автоматично не повторюється.
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = Object.freeze({ reset, mutate });
  window.addEventListener("pageshow", reset);
})();