(function () {
  const { api, ready, el, table, formatDate, statusBadge, renderSeverityCards, emptyState, canManageRepos, SEVERITIES } = window.App;

  function renderBars(counts) {
    const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] || 0));
    document.getElementById("severity-bars").replaceChildren(
      ...SEVERITIES.slice(0, 4).map((s) =>
        el("div", { class: "bar-row" },
          el("span", { class: "bar-label", text: s }),
          el("div", { class: "bar-track" },
            el("div", { class: `bar-fill sev-bg-${s}`, style: `width:${((counts[s] || 0) / max) * 100}%` })),
          el("span", { class: "bar-value", text: counts[s] || 0 })))
    );
  }

  function renderRecent(audits) {
    const box = document.getElementById("recent-audits");
    if (!audits.length) {
      box.replaceChildren(emptyState("No audits yet. Add a repository to get started."));
      return;
    }
    box.replaceChildren(table(["Audit", "Repository", "Branch", "Status", "Started"], audits.map((a) =>
      el("tr", {},
        el("td", {}, el("a", { href: `/audit.html?id=${encodeURIComponent(a.id)}`, text: a.display_id })),
        el("td", {}, el("a", { href: `/repository.html?id=${encodeURIComponent(a.repository_id)}`, text: a.repository_name })),
        el("td", { text: a.branch }),
        el("td", {}, statusBadge(a.status)),
        el("td", { text: formatDate(a.started_at || a.created_at) })))));
  }

  // ---- trends (PRD §59) ----

  function stat(label, value, note) {
    return el("div", { class: "stat" }, el("div", { class: "sev-label", text: label }),
      el("div", { class: "stat-value", text: value }), note ? el("div", { class: "muted small", text: note }) : null);
  }

  async function loadTrends() {
    const days = document.getElementById("trend-days").value;
    const { data: t } = await api("GET", `/dashboard/trends?days=${days}`);
    const r = t.resolved_this_month;
    const pts = t.points;
    const last = pts[pts.length - 1];
    const first = pts[0];
    const delta = pts.length > 1 ? last.open_findings - first.open_findings : null;
    document.getElementById("trend-stats").replaceChildren(
      stat("Resolved this month", r.total, `${r.fixed_in_code} fixed in code · ${r.triaged} marked resolved`),
      stat("Open findings now", last ? last.open_findings : "—",
        delta === null ? null : `${delta > 0 ? "+" : ""}${delta} in this range`),
      stat("Audits in range", pts.length, null));
    const empty = document.getElementById("trend-empty");
    const charts = document.getElementById("trend-charts");
    if (!pts.length) {
      charts.hidden = true;
      empty.hidden = false;
      empty.replaceChildren(emptyState("No completed audits in this range yet."));
    } else {
      charts.hidden = false;
      empty.hidden = true;
      const series = pts.map((p) => ({
        at: new Date(p.at), title: `${p.display_id} · ${p.repository}`,
        rows: [["Critical", p.counts.critical], ["High", p.counts.high], ["Medium", p.counts.medium], ["Low", p.counts.low]],
        open: p.open_findings, score: p.security_score,
      }));
      window.Charts.lineChart(document.getElementById("chart-open"),
        series.map((p) => ({ ...p, value: p.open })), { valueLabel: "open findings" });
      window.Charts.lineChart(document.getElementById("chart-score"),
        series.map((p) => ({ ...p, value: p.score, rows: [["Open findings", p.open]] })), { valueLabel: "/ 100 score", yMax: 100 });
    }
    document.getElementById("trend-table").replaceChildren(pts.length ? table(
      ["Date", "Audit", "Repository", "Open", "Critical", "High", "Medium", "Low", "Score"],
      pts.map((p) => el("tr", {}, ...[formatDate(p.at), p.display_id, p.repository, p.open_findings, p.counts.critical,
        p.counts.high, p.counts.medium, p.counts.low, p.security_score].map((v) => el("td", { text: v }))))) : emptyState("No data."));

    const rec = document.getElementById("recurring-card");
    rec.hidden = !t.recurring.length;
    document.getElementById("recurring").replaceChildren(table(["Severity", "Issue", "Where", "Audits"], t.recurring.map((f) =>
      el("tr", {},
        el("td", {}, el("span", { class: `sev-badge sev-${f.severity}`, text: f.severity })),
        el("td", {}, el("a", { href: `/finding.html?id=${encodeURIComponent(f.finding_id)}`, text: f.title })),
        el("td", {}, el("div", { text: f.repository }), el("span", { class: "path", text: `${f.file}:${f.line_start}` })),
        el("td", { text: f.audits })))));
  }

  document.getElementById("trend-days").addEventListener("change", loadTrends);

  ready.then(async () => {
    document.getElementById("add-repo-link").hidden = !canManageRepos();
    const { data } = await api("GET", "/dashboard");
    renderSeverityCards(document.getElementById("severity-cards"), data.counts);
    const score = document.getElementById("score");
    if (data.security_score === null) {
      score.textContent = "–";
    } else {
      score.textContent = `${data.security_score}/100`;
      score.dataset.band = data.security_score >= 80 ? "good" : data.security_score >= 50 ? "fair" : "poor";
    }
    renderBars(data.counts);
    renderRecent(data.recent_audits);
    loadTrends();
  });
})();
