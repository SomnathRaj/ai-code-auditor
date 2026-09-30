// REST API client and shared UI helpers (PRD §43).
//
// - The access token lives in memory only (never localStorage). Each page load
//   gets a fresh one from POST /auth/refresh using the HttpOnly refresh cookie.
// - A 401 on any call triggers one refresh + retry; if that fails, go to login.
// - All rendering goes through el()/textContent — never innerHTML with server
//   data — because this app displays untrusted code, file paths and names.
(function () {
  const BASE = "/api/v1";
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  let accessToken = null;
  let session = null;
  let refreshing = null;

  class ApiError extends Error {
    constructor(message, status, error) {
      super(message);
      this.status = status;
      this.code = error && error.code;
      this.details = (error && error.details) || {};
    }
  }

  async function parse(res) {
    if (res.status === 204) return null;
    try { return await res.json(); } catch (_) { return null; }
  }

  function toError(res, json) {
    const err = json && json.error;
    return new ApiError((err && err.message) || `Request failed (${res.status})`, res.status, err);
  }

  function setSession(data) {
    accessToken = data.access_token;
    session = { user: data.user, organization: data.organization, role: data.role };
    return session;
  }

  // Endpoints that read the refresh cookie need the CSRF header (PRD §43.3).
  function cookieRequest(path) {
    return fetch(BASE + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", "X-Requested-With": "fetch" },
    });
  }

  function refresh() {
    if (!refreshing) {
      refreshing = cookieRequest("/auth/refresh")
        .then(async (res) => {
          const json = await parse(res);
          if (!res.ok) throw toError(res, json);
          return setSession(json.data);
        })
        .finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  function toLogin() {
    window.location.replace("/login.html");
  }

  // Returns the parsed envelope ({data, meta}) or null for 204.
  async function api(method, path, body, retry = true) {
    const headers = { Accept: "application/json" };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const opts = { method, headers, credentials: "same-origin" };
    if (body instanceof FormData) {
      opts.body = body; // browser sets the multipart boundary
    } else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(BASE + path, opts);
    const json = await parse(res);
    if (res.status === 401 && retry && !path.startsWith("/auth/")) {
      try {
        await refresh();
      } catch (_) {
        toLogin();
        throw toError(res, json);
      }
      return api(method, path, body, false);
    }
    if (!res.ok) throw toError(res, json);
    return json;
  }

  // Authenticated file download (reports): fetch with the bearer token, save with the server's filename.
  async function download(path, fallbackName) {
    const get = () => fetch(BASE + path, { headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
                                           credentials: "same-origin" });
    let res = await get();
    if (res.status === 401) {
      await refresh();
      res = await get();
    }
    if (!res.ok) throw toError(res, await parse(res));
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = /filename="([^"]+)"/.exec(disposition);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = match ? match[1] : fallbackName;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Log in / register: store the returned token and session.
  async function authenticate(path, body) {
    const json = await api("POST", path, body, false);
    return setSession(json.data);
  }

  async function logout() {
    try { await cookieRequest("/auth/logout"); } finally {
      accessToken = null;
      session = null;
      toLogin();
    }
  }

  // ---- DOM helpers ----

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "style") node.style.cssText = v; // CSSOM, allowed by the CSP
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function formatDate(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function statusBadge(status) {
    return el("span", { class: `badge status-${status}`, text: status.replace(/_/g, " ") });
  }

  // linkFor(severity) → URL makes each card a link (e.g. to the filtered findings list).
  function renderSeverityCards(container, counts, linkFor = null) {
    container.replaceChildren(
      ...SEVERITIES.slice(0, 4).map((s) => {
        const children = [el("div", { class: "sev-label", text: s }),
          el("div", { class: "sev-count", text: (counts && counts[s]) || 0 })];
        return linkFor
          ? el("a", { class: `card sev-card sev-${s} card-link`, href: linkFor(s), "aria-label": `${s} findings` }, ...children)
          : el("div", { class: `card sev-card sev-${s}` }, ...children);
      })
    );
  }

  function table(headers, rows) {
    return el("div", { class: "table-wrap" },
      el("table", { class: "table" },
        el("thead", {}, el("tr", {}, headers.map((h) => el("th", { text: h })))),
        el("tbody", {}, rows)));
  }

  function emptyState(text) {
    return el("p", { class: "empty muted", text });
  }

  function showError(node, message) {
    node.textContent = message || "";
    node.hidden = !message;
  }

  function canManageRepos() {
    return !!session && ["owner", "admin"].includes(session.role);
  }

  function canRunAudits() {
    return !!session && ["owner", "admin", "developer"].includes(session.role);
  }

  function formatBytes(n) {
    if (n === null || n === undefined) return "—";
    const units = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
  }

  // Workspace switcher (shown when the user belongs to more than one organization).
  async function setupOrgSwitch(s) {
    const select = document.getElementById("org-switch");
    if (!select) return;
    try {
      const { data: orgs } = await api("GET", "/me/organizations");
      select.replaceChildren(...orgs.map((o) => el("option", { value: o.id, text: o.name, selected: o.current })));
      select.hidden = false;
      select.disabled = orgs.length < 2;
      select.title = orgs.length < 2 ? "Your only workspace" : "Switch workspace";
      select.addEventListener("change", async () => {
        const json = await api("POST", "/auth/switch-organization", { organization_id: select.value });
        setSession(json.data);
        window.location.href = "/";  // pages show organization-scoped data: start from the dashboard
      });
    } catch (_) {
      select.replaceChildren(el("option", { text: s.organization.name }));
      select.hidden = false;
      select.disabled = true;
    }
  }

  // ---- Page boot ----
  // App pages require a session; auth pages redirect away if already logged in.
  const page = document.body.dataset.page;
  const ready = refresh().then(
    (s) => {
      if (page === "auth") {
        window.location.replace("/");
        return new Promise(() => {}); // never resolves; we're navigating away
      }
      const name = document.getElementById("user-name");
      if (name) name.textContent = s.user.name;
      setupOrgSwitch(s);
      const logoutBtn = document.getElementById("logout-btn");
      if (logoutBtn) logoutBtn.addEventListener("click", logout);
      document.body.classList.remove("booting");
      return s;
    },
    () => {
      if (page === "app") {
        toLogin();
        return new Promise(() => {});
      }
      document.body.classList.remove("booting");
      return null;
    }
  );

  window.App = {
    api, authenticate, logout, ready, ApiError, download,
    el, table, formatDate, statusBadge, renderSeverityCards, emptyState, showError, canManageRepos, canRunAudits, formatBytes,
    SEVERITIES,
  };
})();
