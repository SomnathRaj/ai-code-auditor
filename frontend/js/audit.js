(function () {
  const {
    api, ready, el, formatDate, statusBadge, renderSeverityCards, showError, canManageRepos, canRunAudits, download,
  } = window.App;
  const auditId = new URLSearchParams(window.location.search).get("id") || "";
  const path = `/audits/${encodeURIComponent(auditId)}`;
  const POLL_MS = 1500;
  const ICONS = { completed: "✓", running: "●", pending: "○", failed: "✗", cancelled: "✗", skipped: "–" };
  let pollTimer = null;

  const $ = (id) => document.getElementById(id);

  function elapsed(startIso, endIso) {
    if (!startIso) return "";
    const secs = Math.max(0, Math.round(((endIso ? new Date(endIso) : new Date()) - new Date(startIso)) / 1000));
    return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
  }

  function renderStatus(st) {
    const badge = $("status-badge");
    badge.className = `badge status-${st.status}`;
    badge.textContent = st.cancel_requested && !st.is_final ? "cancelling…" : st.status.replace(/_/g, " ");

    const bar = $("progress");
    bar.setAttribute("aria-valuenow", st.progress);
    bar.classList.toggle("done", st.status === "completed");
    bar.classList.toggle("failed", st.status === "failed" || st.status === "cancelled");
    $("progress-fill").style.width = `${st.status === "failed" || st.status === "cancelled" ? 100 : st.progress}%`;

    $("stages").replaceChildren(...st.stages.map((s) =>
      el("li", { class: `stage ${s.status}` },
        el("span", { class: "stage-icon", "aria-hidden": "true", text: ICONS[s.status] || "○" }),
        el("span", {},
          el("span", { class: "stage-name", text: s.label }),
          el("span", { class: "visually-hidden", text: ` (${s.status})` }),
          s.detail ? el("span", { class: "stage-detail", text: s.detail }) : null),
        el("span", { class: "stage-time", text: s.status === "running" || s.completed_at ? elapsed(s.started_at, s.completed_at) : "" }))));

    showError($("audit-error"), st.error && st.status !== "completed" ? st.error.message : "");
    const cancelBtn = $("cancel-btn");
    cancelBtn.hidden = st.is_final || !canRunAudits();
    cancelBtn.disabled = st.cancel_requested;
    $("delete-btn").hidden = !st.is_final || !canManageRepos();
    $("rerun-link").hidden = !st.is_final || !canRunAudits();
  }

  function aiSummary(ai) {
    if (!ai) return "—";
    if (ai.status === "disabled") return "Off for this repository (no code sent)";
    if (ai.status === "not_configured") return "Not configured on this server (no code sent)";
    if (ai.status === "failed") return `Failed: ${ai.error || "unknown error"}`;
    const parts = [`${ai.analyzed + ai.cached} of ${ai.selected} analysed (${ai.cached} cached)`];
    if (ai.likely_false_positives) parts.push(`${ai.likely_false_positives} likely false positive(s)`);
    if (ai.skipped_limit) parts.push(`${ai.skipped_limit} over the per-audit limit`);
    if (ai.failed) parts.push(`${ai.failed} failed`);
    const tokens = (ai.input_tokens || 0) + (ai.output_tokens || 0);
    return `${parts.join(", ")} · ${ai.model}${tokens ? ` · ${tokens.toLocaleString()} tokens` : ""}`;
  }

  let reportsReady = false;

  function setupReports(a) {
    const compare = $("compare-link");
    compare.href = `/compare.html?audit=${encodeURIComponent(a.id)}`;
    compare.hidden = false;
    if (reportsReady) return;
    reportsReady = true;
    for (const btn of document.querySelectorAll("[data-report]")) {
      btn.addEventListener("click", async () => {
        const { report, format } = btn.dataset;
        showError($("report-error"), "");
        const label = btn.textContent;
        btn.disabled = true;
        btn.textContent = "…";
        try {
          const q = `?type=${report}&format=${format}`;
          if (format === "json") {
            const { data } = await api("GET", `${path}/report${q}`);
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = el("a", { href: url, download: `${a.display_id}-${report}.json` });
            document.body.append(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          } else {
            await download(`${path}/report${q}`, `${a.display_id}-${report}.${format}`);
          }
        } catch (err) {
          showError($("report-error"), err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = label;
        }
      });
    }
  }

  function renderDetail(a) {
    document.title = `${a.display_id} · AI Code Auditor`;
    $("audit-title").textContent = `${a.display_id}${a.repository ? " · " + a.repository.name : ""}`;
    const bits = [a.audit_type + " audit"];
    if (a.repository && a.repository.provider === "github") bits.push(`branch ${a.branch}`);
    if (a.commit_hash) bits.push(`commit ${a.commit_hash.slice(0, 10)}`);
    bits.push(`queued ${formatDate(a.created_at)}`);
    $("audit-meta").textContent = bits.join(" · ");
    if (a.repository) {
      const repoUrl = `/repository.html?id=${encodeURIComponent(a.repository.id)}`;
      $("back-link").href = repoUrl;
      $("back-link").textContent = `← ${a.repository.name}`;
      $("rerun-link").href = `${repoUrl}#start`;
    }
    if (a.status !== "completed" || !a.summary) {
      $("results").hidden = true;
      return;
    }
    const s = a.summary;
    $("results").hidden = false;
    setupReports(a);
    const listUrl = `/findings.html?audit=${encodeURIComponent(a.id)}`;
    $("findings-link").href = listUrl;
    $("findings-link").hidden = false;
    renderSeverityCards($("severity-cards"), s.counts, (sev) => `${listUrl}&severity=${sev}`);
    const score = $("score");
    score.textContent = `${s.security_score}/100`;
    score.dataset.band = s.security_score >= 80 ? "good" : s.security_score >= 50 ? "fair" : "poor";
    $("score-note").textContent = `${s.total_findings} findings in total` +
      (s.carried_over ? `, ${s.carried_over} kept as false positive / accepted risk from earlier audits` : "") + ".";

    const langs = (s.languages || []).slice(0, 4).map((l) => `${l.name} ${l.percent}%`).join(", ") || "—";
    const versions = a.scanner_versions || {};
    const rows = [
      ["Stack", [...(s.frameworks || []), s.primary_language].filter(Boolean).join(" / ") || "—"],
      ["Languages", langs],
      ["Files scanned", `${s.file_count}` + (s.vendored_files_skipped ? ` (${s.vendored_files_skipped} minified/vendored skipped by code analysis)` : "")],
      ["By scanner", Object.entries(s.by_scanner || {}).map(([k, v]) => `${k} ${v}`).join(", ")],
      ["Dependencies", `${s.dependency_count} (${s.vulnerable_dependency_count} vulnerable)`],
      ["AI analysis", aiSummary(s.ai)],
      ["Duration", elapsed(a.started_at, a.completed_at)],
      ["Tools", Object.entries(versions).map(([k, v]) => `${k} ${v}`).join(" · ") || "—"],
    ];
    $("summary").replaceChildren(...rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));

    const warnings = [
      ...(s.scanner_errors || []).map((e) => `${e.scanner}: ${e.message}${e.path ? ` (${e.path})` : ""}`),
      ...(s.removed_control_files || []).map((f) => `Ignored the repository's scanner control file ${f} so it couldn't hide findings.`),
    ];
    $("warnings-card").hidden = !warnings.length;
    $("warnings").replaceChildren(...warnings.map((w) => el("li", { class: "small", text: w })));
  }

  async function loadDetail() {
    const { data } = await api("GET", path);
    renderDetail(data);
    renderStatus(data);
    return data;
  }

  async function poll() {
    try {
      const { data } = await api("GET", `${path}/status`);
      renderStatus(data);
      if (data.is_final) {
        await loadDetail();
        return;
      }
    } catch (err) {
      showError($("audit-error"), err.message);
    }
    pollTimer = setTimeout(poll, POLL_MS);
  }

  $("cancel-btn").addEventListener("click", async () => {
    if (!confirm("Cancel this audit? Running scanners are stopped and no results are saved.")) return;
    $("cancel-btn").disabled = true;
    try {
      const { data } = await api("POST", `${path}/cancel`);
      renderStatus(data);
    } catch (err) {
      showError($("audit-error"), err.message);
      $("cancel-btn").disabled = false;
    }
  });

  $("delete-btn").addEventListener("click", async () => {
    if (!confirm("Delete this audit and its findings? This cannot be undone.")) return;
    try {
      await api("DELETE", path);
      window.location.replace($("back-link").getAttribute("href"));
    } catch (err) {
      showError($("audit-error"), err.message);
    }
  });

  ready.then(async () => {
    try {
      const a = await loadDetail();
      $("loading").hidden = true;
      $("audit").hidden = false;
      if (!a.is_final) pollTimer = setTimeout(poll, POLL_MS);
    } catch (err) {
      $("loading").textContent = err.message;
    }
  });

  window.addEventListener("beforeunload", () => clearTimeout(pollTimer));
})();
