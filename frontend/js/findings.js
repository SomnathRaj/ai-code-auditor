(function () {
  const { api, ready, el, table, emptyState, statusBadge, SEVERITIES } = window.App;
  const params = new URLSearchParams(window.location.search);
  const auditId = params.get("audit") || "";
  const form = document.getElementById("filters");
  const FIELDS = ["q", "file", "status", "category", "scanner", "ai_verdict", "sort"];
  const PER_PAGE = 50;
  const VERDICT_LABELS = { true_positive: "Likely real", false_positive: "Likely false positive", needs_more_context: "Needs context" };
  const SCANNER_LABELS = { semgrep: "Code (Semgrep)", gitleaks: "Secrets (Gitleaks)", osv: "Dependencies (OSV)" };
  let severities = new Set((params.get("severity") || "").split(",").filter(Boolean));
  let page = Number(params.get("page") || 1);
  let debounce = null;

  for (const f of FIELDS) if (params.has(f) && form[f]) form[f].value = params.get(f);
  if (!params.has("status")) form.status.value = "open";

  function query() {
    const q = new URLSearchParams();
    for (const f of FIELDS) if (form[f].value) q.set(f, form[f].value);
    if (severities.size) q.set("severity", [...severities].join(","));
    return q;
  }

  function syncUrl() {
    const q = query();
    q.set("audit", auditId);
    if (page > 1) q.set("page", page);
    history.replaceState(null, "", `/findings.html?${q}`);
  }

  function aiBadge(ai) {
    if (!ai || !ai.verdict) return el("span", { class: "muted small", text: ai && ai.status === "failed" ? "AI failed" : "—" });
    const pct = ai.verdict === "false_positive" ? ai.false_positive_probability : ai.confidence;
    return el("span", { class: `ai-badge ai-${ai.verdict}`, title: "AI suggestion — review before acting",
      text: `${VERDICT_LABELS[ai.verdict]}${pct != null ? ` ${Math.round(pct * 100)}%` : ""}` });
  }

  function fillSelect(select, counts, labels = {}) {
    const current = select.value;
    const keep = [...select.options].filter((o) => o.value === "");
    select.replaceChildren(...keep, ...Object.entries(counts || {}).sort((a, b) => b[1] - a[1]).map(([value, n]) =>
      el("option", { value, text: `${labels[value] || value} (${n})` })));
    select.value = current;
  }

  function renderFacets(facets) {
    fillSelect(form.category, facets.category);
    fillSelect(form.scanner, facets.scanner, SCANNER_LABELS);
    const box = document.getElementById("sev-filter");
    box.replaceChildren(...SEVERITIES.filter((s) => (facets.severity || {})[s]).map((s) =>
      el("button", {
        class: "chip-toggle", type: "button", "aria-pressed": String(severities.has(s)),
        onclick: () => { severities.has(s) ? severities.delete(s) : severities.add(s); page = 1; load(); },
      }, el("span", { class: `sev-text-${s}` }, s), ` ${facets.severity[s]}`)));
    const verdictCounts = facets.ai_verdict || {};
    for (const opt of form.ai_verdict.options) {
      if (opt.value && verdictCounts[opt.value] !== undefined) {
        opt.textContent = `${opt.textContent.replace(/ \(\d+\)$/, "")} (${verdictCounts[opt.value]})`;
      }
    }
  }

  function render(json) {
    const list = document.getElementById("list");
    const m = json.meta;
    document.getElementById("result-count").textContent = `${m.total} finding${m.total === 1 ? "" : "s"}`;
    if (!json.data.length) {
      list.replaceChildren(emptyState("No findings match these filters."));
    } else {
      list.replaceChildren(table(["Severity", "Finding", "Location", "Status", "AI"], json.data.map((f) =>
        el("tr", {},
          el("td", {}, el("span", { class: `sev-badge sev-${f.severity}`, text: f.severity })),
          el("td", {},
            el("a", { class: "finding-title", href: `/finding.html?id=${encodeURIComponent(f.id)}`, text: f.title }),
            el("div", { class: "muted small", text: [f.category, f.cwe, SCANNER_LABELS[f.scanner] || f.scanner].filter(Boolean).join(" · ") })),
          el("td", {}, el("span", { class: "path", text: `${f.file || "—"}${f.line_start ? ":" + f.line_start : ""}` }),
            f.function ? el("div", { class: "muted small", text: `in ${f.function}()` }) : null),
          el("td", {}, statusBadge(f.status)),
          el("td", {}, aiBadge(f.ai))))));
    }
    const pager = document.getElementById("pager");
    pager.replaceChildren(...(m.total_pages > 1 ? [
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page <= 1, onclick: () => { page -= 1; load(); } }, "Previous"),
      el("span", { class: "muted small", text: `Page ${m.page} of ${m.total_pages}` }),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page >= m.total_pages, onclick: () => { page += 1; load(); } }, "Next"),
    ] : []));
    renderFacets(m.facets || {});
  }

  async function load() {
    syncUrl();
    const q = query();
    q.set("page", page);
    q.set("per_page", PER_PAGE);
    try {
      render(await api("GET", `/audits/${encodeURIComponent(auditId)}/findings?${q}`));
    } catch (err) {
      document.getElementById("list").replaceChildren(emptyState(err.message));
    }
  }

  form.addEventListener("input", (e) => {
    clearTimeout(debounce);
    page = 1;
    debounce = setTimeout(load, e.target.tagName === "INPUT" ? 300 : 0);
  });
  form.addEventListener("submit", (e) => e.preventDefault());

  ready.then(async () => {
    try {
      const { data: a } = await api("GET", `/audits/${encodeURIComponent(auditId)}`);
      document.title = `Findings · ${a.display_id} · AI Code Auditor`;
      document.getElementById("title").textContent = `Findings · ${a.display_id}`;
      document.getElementById("subtitle").textContent = a.repository
        ? `${a.repository.name}${a.repository.provider === "github" ? " · " + a.branch : ""}` : "";
      const back = document.getElementById("back-link");
      back.href = `/audit.html?id=${encodeURIComponent(a.id)}`;
      back.textContent = `← ${a.display_id}`;
    } catch (err) {
      document.getElementById("title").textContent = err.message;
      return;
    }
    load();
  });
})();
