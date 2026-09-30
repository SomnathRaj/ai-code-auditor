(function () {
  const { api, ready, el, table, formatDate, emptyState, showError, canManageRepos } = window.App;
  const $ = (id) => document.getElementById(id);
  const ROLE_LABELS = { owner: "Owner", admin: "Admin", developer: "Developer", viewer: "Viewer" };
  let me = null;
  let logPage = 1;

  function flash(id, message) {
    const node = $(id);
    node.textContent = message;
    node.hidden = !message;
    if (message) setTimeout(() => { node.hidden = true; }, 4000);
  }

  // ---- workspace ----

  async function loadOrg() {
    const { data: org } = await api("GET", "/organization");
    const form = $("org-form");
    form.name.value = org.name;
    form.audit_days.value = String(org.retention.audit_days);
    form.source_days.value = String(org.retention.source_days);
    const owner = org.role === "owner";
    for (const field of form.elements) field.disabled = !owner;
    $("org-save").hidden = !owner;
    $("org-readonly").hidden = owner;
  }

  $("org-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    showError($("org-error"), "");
    try {
      await api("PATCH", "/organization", {
        name: form.name.value,
        retention: { audit_days: Number(form.audit_days.value), source_days: Number(form.source_days.value) },
      });
      flash("org-ok", "Saved. Retention is applied daily.");
      const current = document.getElementById("org-switch").selectedOptions[0];
      if (current) current.textContent = form.name.value;
    } catch (err) {
      showError($("org-error"), err.message);
    }
  });

  // ---- members ----

  function canChange(member) {
    if (member.user_id === me.user.id) return false;  // use "Leave" for yourself
    if (me.role === "owner") return true;
    return me.role === "admin" && !["owner", "admin"].includes(member.role);
  }

  async function loadMembers() {
    const { data: members } = await api("GET", "/organization/members");
    const roles = me.role === "owner" ? ["owner", "admin", "developer", "viewer"] : ["developer", "viewer"];
    $("members").replaceChildren(table(["Name", "Email", "Role", "Joined", ""], members.map((m) => {
      const editable = canChange(m);
      const select = el("select", { "aria-label": `Role of ${m.name}`, disabled: !editable },
        ...(editable ? roles : [m.role]).map((r) => el("option", { value: r, text: ROLE_LABELS[r], selected: r === m.role })));
      select.addEventListener("change", async () => {
        showError($("member-error"), "");
        try {
          await api("PATCH", `/organization/members/${encodeURIComponent(m.user_id)}`, { role: select.value });
          loadMembers();
        } catch (err) {
          showError($("member-error"), err.message);
          select.value = m.role;
        }
      });
      return el("tr", {},
        el("td", {}, m.name || "—", m.user_id === me.user.id ? el("span", { class: "muted small", text: " (you)" }) : null),
        el("td", { class: "small", text: m.email || "—" }),
        el("td", {}, select),
        el("td", { class: "small", text: formatDate(m.joined_at) }),
        el("td", {}, editable ? el("button", {
          class: "btn btn-ghost btn-sm", type: "button", text: "Remove",
          onclick: async () => {
            if (!confirm(`Remove ${m.name} from this workspace?`)) return;
            try {
              await api("DELETE", `/organization/members/${encodeURIComponent(m.user_id)}`);
              loadMembers();
            } catch (err) { showError($("member-error"), err.message); }
          },
        }) : null));
    })));
    const roleSelect = $("member-form").role;
    for (const opt of roleSelect.options) opt.hidden = !roles.includes(opt.value);
  }

  $("member-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    showError($("member-error"), "");
    try {
      await api("POST", "/organization/members", { email: form.email.value, role: form.role.value });
      form.reset();
      loadMembers();
    } catch (err) {
      showError($("member-error"), err.message);
    }
  });

  // ---- activity log ----

  function describe(details) {
    const shown = { ...(details || {}) };
    if (shown.member) delete shown.member_id;  // the name says it; the id is still in the API
    const parts = Object.entries(shown).filter(([, v]) => v !== null && v !== "")
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v}`);
    return parts.join(" · ");
  }

  async function loadLogs(page = 1) {
    const filter = $("log-filter").value;
    const q = new URLSearchParams({ page, per_page: 25 });
    if (filter) q.set("event", filter);
    const json = await api("GET", `/audit-logs?${q}`);
    logPage = json.meta.page;
    $("logs").replaceChildren(json.data.length ? table(["When", "Event", "Who", "Details"], json.data.map((e) =>
      el("tr", {},
        el("td", { class: "small", text: formatDate(e.at) }),
        el("td", {}, el("code", { class: "small", text: e.event })),
        el("td", { class: "small", text: e.user || "—" }),
        el("td", {}, el("div", { class: "log-details", text: describe(e.details) }),
          e.ip_address ? el("div", { class: "muted small", text: e.ip_address }) : null)))) : emptyState("No activity."));
    const m = json.meta;
    $("logs-pager").replaceChildren(...(m.total_pages > 1 ? [
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page <= 1, onclick: () => loadLogs(m.page - 1) }, "Newer"),
      el("span", { class: "muted small", text: `Page ${m.page} of ${m.total_pages}` }),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page >= m.total_pages, onclick: () => loadLogs(m.page + 1) }, "Older"),
    ] : []));
  }

  $("log-filter").addEventListener("change", () => loadLogs(1));

  // ---- leave ----

  $("leave-btn").addEventListener("click", async () => {
    if (!confirm("Leave this workspace? You'll need to be added again to get access back.")) return;
    try {
      await api("DELETE", `/organization/members/${encodeURIComponent(me.user.id)}`);
      // Reloading refreshes the session: it moves to another workspace, or ends on the login page.
      window.location.href = "/";
    } catch (err) {
      showError($("leave-error"), err.message);
    }
  });

  ready.then(async (session) => {
    me = session;
    await loadOrg();
    if (canManageRepos()) {
      $("members-card").hidden = false;
      $("logs-card").hidden = false;
      await Promise.all([loadMembers(), loadLogs(1)]);
    }
  });
})();
