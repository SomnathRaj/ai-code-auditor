(function () {
  const { api, ready, el, formatDate, statusBadge, showError, canRunAudits } = window.App;
  const { highlightLine, newState } = window.Highlight;
  const findingId = new URLSearchParams(window.location.search).get("id") || "";
  const path = `/findings/${encodeURIComponent(findingId)}`;
  const $ = (id) => document.getElementById(id);
  const VERDICTS = {
    true_positive: "Likely a real issue",
    false_positive: "Likely a false positive",
    needs_more_context: "Needs more context",
  };
  const ACTIONS = {
    confirmed: "Confirm", in_progress: "Start fixing", resolved: "Mark resolved", verified: "Mark verified",
    false_positive: "False positive", accepted_risk: "Accept risk", ignored: "Ignore", new: "Reopen",
  };
  let finding = null;

  function details(dl, rows) {
    dl.replaceChildren(...rows.filter(([, v]) => v !== null && v !== undefined && v !== "")
      .flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v)]));
  }

  function prose(container, sections) {
    container.classList.add("prose");
    // replaceChildren() would render a null as the text "null", so only real nodes go in.
    container.replaceChildren(...sections.filter(([, text]) => text).flatMap(([heading, text]) =>
      heading ? [el("h3", { text: heading }), el("p", { text })] : [el("p", { text })]));
    if (!container.children.length) container.replaceChildren(el("p", { class: "muted", text: "—" }));
  }

  function pct(x) {
    return x === null || x === undefined ? "—" : `${Math.round(x * 100)}%`;
  }

  // ---- code viewer (PRD §36) ----

  function codeLines(container, lines, language, { numbers = true } = {}) {
    const state = newState();
    container.replaceChildren(...lines.map((l) => {
      const row = el("div", { class: `code-line${l.highlight ? " hl" : ""}${l.evidence ? " ev" : ""}` });
      if (numbers) row.append(el("span", { class: "ln", text: String(l.number) }), el("span", { class: "mk" }));
      else row.append(el("span", { class: "mk" }));
      const code = el("span", {});
      code.append(highlightLine(l.text, language, state));
      row.append(code);
      return row;
    }));
  }

  async function loadCode() {
    const { data: c } = await api("GET", `${path}/code`);
    const box = $("code");
    if (!c.available) {
      box.replaceChildren(el("p", { class: "muted small", text: "No code excerpt was stored for this finding." }));
      return;
    }
    codeLines(box, c.lines, c.language);
    if (c.marker) {  // "▲ └── message" under the flagged line, as in the PRD
      const after = [...box.children].find((row) => row.querySelector(".ln")?.textContent === String(c.marker.line));
      const marker = el("div", { class: "code-marker" }, el("span", { text: "" }), el("span", { text: `└─ ${c.marker.message}` }));
      after ? after.after(marker) : box.append(marker);
    }
    $("code-meta").textContent = `${c.file}${c.language ? " · " + c.language : ""} · audited version`;
    if (c.fixed_code) {
      $("fix-pane").hidden = false;
      $("code-layout").classList.add("split");
      codeLines($("fix"), c.fixed_code.split("\n").map((text, i) => ({ number: i + 1, text })), c.language, { numbers: false });
    }
  }

  // ---- AI analysis ----

  function renderAI(ai) {
    const card = $("ai-card");
    if (!ai) { card.hidden = true; return; }
    card.hidden = false;
    if (ai.status !== "completed") {
      const reasons = { not_applicable: "Not sent to AI (secrets and dependency findings never are).",
        below_threshold: "Below the severity threshold for AI analysis.", limit: "Over the per-audit AI limit.",
        no_context: "No code context was available." };
      $("ai-meta").textContent = "";
      $("ai-body").replaceChildren(el("p", { class: "muted", text: ai.status === "failed"
        ? `AI analysis failed: ${ai.error || "unknown error"}` : reasons[ai.reason] || "Not analysed." }));
      return;
    }
    $("ai-meta").textContent = `${ai.model}${ai.cached ? " · cached" : ""}${ai.analyzed_at ? " · " + formatDate(ai.analyzed_at) : ""}`;
    const body = $("ai-body");
    body.replaceChildren(
      el("p", {},
        el("span", { class: `ai-badge ai-${ai.verdict}`, text: VERDICTS[ai.verdict] || ai.verdict }),
        el("span", { class: "muted small", text: ` confidence ${pct(ai.confidence)} · false-positive probability ${pct(ai.false_positive_probability)} · assessed severity ${ai.severity}` })),
      el("p", { class: "muted small", text: "AI output is a suggestion for the reviewer. It doesn't change the finding's status." }));
    const text = el("div", {});
    prose(text, [["", ai.explanation], ["Impact", ai.impact], ["Attack scenario", ai.attack_scenario],
      ["What's missing to be sure", (ai.missing_context || []).join("\n")]]);
    body.append(text);
  }

  // ---- triage ----

  function renderStatus(f) {
    const badge = $("status-badge");
    badge.replaceChildren(statusBadge(f.status));
    $("history").replaceChildren(...[...f.status_history].reverse().map((h) =>
      el("li", {},
        el("div", {}, h.from ? `${h.from.replace(/_/g, " ")} → ` : "", el("strong", { text: h.status.replace(/_/g, " ") })),
        el("div", { class: "meta", text: `${h.user || "System"} · ${formatDate(h.at)}` }),
        h.comment ? el("div", { class: "small", text: h.comment }) : null)));
    if (!canRunAudits()) return;
    const form = $("triage-form");
    form.hidden = false;
    $("reason-label").hidden = false;
    $("transitions").replaceChildren(...f.allowed_transitions.map((status) =>
      el("button", {
        class: `btn btn-sm ${["false_positive", "accepted_risk", "ignored"].includes(status) ? "btn-ghost" : "btn-primary"}`,
        type: "button", onclick: () => changeStatus(status), text: ACTIONS[status] || status,
      })));
  }

  async function changeStatus(status) {
    const comment = $("triage-form").comment.value.trim();
    showError($("triage-error"), "");
    if (finding.reason_required_for.includes(status) && !comment) {
      showError($("triage-error"), "Add a reason first: it's kept with the decision and reused in later audits.");
      $("triage-form").comment.focus();
      return;
    }
    try {
      const { data } = await api("PATCH", path, { status, comment: comment || null });
      finding = data;
      $("triage-form").comment.value = "";
      renderStatus(data);
      loadComments();
    } catch (err) {
      showError($("triage-error"), err.message);
    }
  }

  // ---- comments ----

  async function loadComments() {
    const { data } = await api("GET", `${path}/comments?per_page=100`);
    $("comments").replaceChildren(...(data.length ? data.map((c) =>
      el("li", {},
        el("div", { class: "meta", text: `${c.user || "Unknown"} · ${formatDate(c.created_at)}${c.kind === "status_change" ? ` · marked ${c.status.replace(/_/g, " ")}` : ""}${c.earlier_audit ? " · earlier audit" : ""}` }),
        el("div", { class: "body", text: c.body })))
      : [el("li", { class: "muted small", text: "No comments yet." })]));
  }

  function setupCommentForm() {
    if (!canRunAudits()) return;
    const form = $("comment-form");
    form.hidden = false;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      showError($("comment-error"), "");
      try {
        await api("POST", `${path}/comments`, { body: form.body.value });
        form.reset();
        loadComments();
      } catch (err) {
        showError($("comment-error"), err.message);
      }
    });
  }

  // ---- page ----

  function render(f) {
    document.title = `${f.title} · AI Code Auditor`;
    $("title").textContent = f.title;
    $("badges").replaceChildren(...[
      el("span", { class: `sev-badge sev-${f.severity}`, text: f.severity }),
      el("span", { class: "chip", text: f.category || "—" }),
      f.cwe ? el("span", { class: "chip", text: f.cwe }) : null,
      f.ai && f.ai.verdict ? el("span", { class: `ai-badge ai-${f.ai.verdict}`, text: `AI: ${VERDICTS[f.ai.verdict]}` }) : null,
    ].filter(Boolean));
    if (f.audit) {
      $("back-link").href = document.referrer.includes(`/findings.html?`) && document.referrer.includes(f.audit.id)
        ? document.referrer : `/findings.html?audit=${encodeURIComponent(f.audit.id)}`;
      $("back-link").textContent = `← Findings · ${f.audit.display_id}`;
    }
    details($("overview"), [
      ["Severity", f.severity], ["Scanner confidence", pct(f.confidence)], ["Category", f.category],
      ["Rule", el("code", { class: "small", text: f.rule_id || "—" })], ["Scanner", f.scanner],
      ["File", el("span", { class: "path", text: `${f.file}${f.line_start ? ":" + f.line_start + (f.line_end && f.line_end !== f.line_start ? "-" + f.line_end : "") : ""}` })],
      ["Function", f.function ? `${f.function}()` : null],
      ["Repository", f.repository ? el("a", { href: `/repository.html?id=${encodeURIComponent(f.repository.id)}`, text: f.repository.name }) : null],
      ["Audit", f.audit ? el("a", { href: `/audit.html?id=${encodeURIComponent(f.audit.id)}`, text: f.audit.display_id + (f.audit.commit_hash ? ` @ ${f.audit.commit_hash.slice(0, 10)}` : "") }) : null],
    ]);
    prose($("explanation"), [["", f.description], ["Impact (AI)", f.impact]]);
    const ai = f.ai_analysis && f.ai_analysis.status === "completed" ? f.ai_analysis : null;
    prose($("recommendation"), [["", f.recommendation], ai && ai.recommendation ? ["AI suggestion", ai.recommendation] : ["", null]]);
    $("references").replaceChildren(...(f.references.length ? f.references.map((r) =>
      el("li", {}, el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: r.label })))
      : [el("li", { class: "muted", text: "—" })]));
    const ev = f.evidence || {};
    if (f.scanner === "osv" && ev.package) {
      $("evidence-card").hidden = false;
      details($("evidence"), [["Package", `${ev.package} (${ev.ecosystem})`], ["Current version", ev.current_version],
        ["Affected versions", ev.affected_range], ["Vulnerability", [ev.vulnerability, ...(ev.aliases || [])].join(", ")],
        ["CVSS", ev.cvss_score], ["Recommended version", ev.recommended_version],
        ["Scope", `${ev.scope}${ev.direct ? ", direct" : ", transitive"}`]]);
    }
    renderAI(f.ai_analysis);
    renderStatus(f);
  }

  ready.then(async () => {
    try {
      const { data } = await api("GET", path);
      finding = data;
      render(data);
      $("loading").hidden = true;
      $("finding").hidden = false;
      setupCommentForm();
      await Promise.all([loadCode(), loadComments()]);
    } catch (err) {
      $("loading").textContent = err.message;
    }
  });
})();
