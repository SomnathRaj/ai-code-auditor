(function () {
  const { api, ready, el, table, emptyState, statusBadge, showError } = window.App;
  const params = new URLSearchParams(window.location.search);
  const auditId = params.get("audit") || "";
  const $ = (id) => document.getElementById(id);
  const TABS = [
    ["new", "New", "Found now, not in the earlier audit."],
    ["resolved", "Resolved", "Reported earlier, gone now (fixed in code)."],
    ["reopened", "Reopened", "Marked resolved earlier, but still found."],
    ["unchanged", "Unchanged", "Found in both audits (including code that moved)."],
  ];
  let data = null;
  let tab = "new";

  function tiles(c, scoreChange) {
    const tile = (label, value, note, cls = "") =>
      el("div", { class: `card sev-card ${cls}` }, el("div", { class: "sev-label", text: label }),
        el("div", { class: "sev-count", text: value }), note ? el("div", { class: "muted small", text: note }) : null);
    $("tiles").replaceChildren(
      tile("New", c.new, null, "sev-high"),
      tile("Resolved", c.resolved, scoreChange === null ? null : `score ${scoreChange >= 0 ? "+" : ""}${scoreChange}`, "sev-low"),
      tile("Reopened", c.reopened, null, "sev-critical"),
      tile("Unchanged", c.unchanged, c.dismissed_no_longer_reported ? `${c.dismissed_no_longer_reported} dismissed and no longer reported` : null));
  }

  function renderList() {
    $("tabs").replaceChildren(...TABS.map(([key, label]) =>
      el("button", { class: `tab${key === tab ? " active" : ""}`, type: "button", role: "tab",
        "aria-selected": String(key === tab), onclick: () => { tab = key; renderList(); } }, `${label} (${data.counts[key]})`)));
    const [, , help] = TABS.find(([k]) => k === tab);
    const rows = data[tab];
    const box = $("list");
    if (!rows.length) {
      box.replaceChildren(el("p", { class: "muted small", text: help }), emptyState("Nothing here."));
      return;
    }
    box.replaceChildren(el("p", { class: "muted small", text: help }),
      table(["Severity", "Finding", "Location", tab === "resolved" ? "Last status" : "Status"], rows.map((f) =>
        el("tr", {},
          el("td", {}, el("span", { class: `sev-badge sev-${f.severity}`, text: f.severity })),
          el("td", {}, el("a", { href: `/finding.html?id=${encodeURIComponent(f.id)}`, text: f.title }),
            el("div", { class: "muted small", text: [f.category, f.cwe].filter(Boolean).join(" · ") })),
          el("td", {}, el("span", { class: "path", text: `${f.file || "—"}${f.line_start ? ":" + f.line_start : ""}` })),
          el("td", {}, statusBadge(f.status),
            f.previous_status && f.previous_status !== f.status
              ? el("div", { class: "muted small", text: `was ${f.previous_status.replace(/_/g, " ")}` }) : null)))));
    $("truncated").hidden = !data.truncated;
  }

  async function load(baseId) {
    showError($("error"), "");
    try {
      const q = baseId ? `?base=${encodeURIComponent(baseId)}` : "";
      ({ data } = await api("GET", `/audits/${encodeURIComponent(auditId)}/comparison${q}`));
      $("subtitle").textContent = `${data.base.display_id} (${data.base.open_findings} open, score ${data.base.security_score ?? "—"}) → ` +
        `${data.target.display_id} (${data.target.open_findings} open, score ${data.target.security_score ?? "—"})`;
      $("base-select").value = data.base.id;
      tiles(data.counts, data.score_change);
      renderList();
    } catch (err) {
      showError($("error"), err.message);
      $("tiles").replaceChildren();
      $("list").replaceChildren();
    }
  }

  ready.then(async () => {
    const { data: audit } = await api("GET", `/audits/${encodeURIComponent(auditId)}`);
    $("title").textContent = `Compare ${audit.display_id}`;
    $("back-link").href = `/audit.html?id=${encodeURIComponent(audit.id)}`;
    $("back-link").textContent = `← ${audit.display_id}`;
    const history = await api("GET", `/repositories/${encodeURIComponent(audit.repository.id)}/audits?per_page=100`);
    const others = history.data.filter((a) => a.status === "completed" && a.id !== audit.id);
    const select = $("base-select");
    select.replaceChildren(...others.map((a) => el("option", { value: a.id, text: `${a.display_id} · ${new Date(a.created_at).toLocaleDateString()}` })));
    select.disabled = !others.length;
    select.addEventListener("change", () => load(select.value));
    load(params.get("base"));
  });
})();
