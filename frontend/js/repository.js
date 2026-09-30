(function () {
  const {
    api, ready, el, table, formatDate, formatBytes, statusBadge, renderSeverityCards, emptyState, showError,
    canManageRepos, canRunAudits,
  } = window.App;
  const repoId = new URLSearchParams(window.location.search).get("id") || "";
  const path = `/repositories/${encodeURIComponent(repoId)}`;
  const nameEl = document.getElementById("repo-name");
  const sourceError = document.getElementById("source-error");
  const sourceOk = document.getElementById("source-ok");
  const loadedBranches = {};
  loadedBranches.promise = new Promise((resolve) => { loadedBranches.resolve = resolve; });

  function details(dl, rows) {
    dl.replaceChildren(...rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v ?? "—")]));
  }

  function notify(message, isError) {
    showError(sourceError, isError ? message : "");
    sourceOk.textContent = isError ? "" : message;
    sourceOk.hidden = isError || !message;
    sourceOk.classList.toggle("success", !isError);
  }

  function renderRepo(r) {
    nameEl.textContent = r.name;
    document.title = `${r.name} · AI Code Auditor`;
    const where = r.provider === "github" ? `GitHub · ${r.default_branch}` : "ZIP upload";
    document.getElementById("repo-meta").textContent =
      `${where}${r.security_score !== null ? ` · Score ${r.security_score}/100` : ""}`;
    renderSeverityCards(document.getElementById("severity-cards"), r.counts, r.last_audit
      ? (sev) => `/findings.html?audit=${encodeURIComponent(r.last_audit.audit_id)}&severity=${sev}` : null);

    details(document.getElementById("repo-details"), [
      ["Source", r.url ? el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: r.url }) : "ZIP upload"],
      ["Default branch", r.default_branch],
      ["Languages", r.languages.length
        ? el("div", { class: "chips" }, r.languages.slice(0, 6).map((l) => el("span", { class: "chip", text: `${l.name} ${l.percent}%` })))
        : "Detected on first audit"],
      ["Frameworks", r.frameworks.length ? r.frameworks.join(", ") : (r.last_audit ? "None detected" : "Detected on first audit")],
      ["Added", formatDate(r.created_at)],
    ]);

    renderSettings(r.settings || {});
  }

  // ---- audit settings (PRD §37) + AI disclosure (PRD §52) ----

  let features = null;

  function aiDisclosure(enabled) {
    const ai = features && features.ai;
    if (!ai || !ai.configured) return "AI analysis isn't configured on this server, so no code is sent to an AI provider.";
    if (!enabled) return "AI analysis is off for this repository: no code is sent to an AI provider.";
    return `When on, for up to ${ai.max_findings} code findings of ${ai.min_severity} severity or above per audit, ` +
      `the surrounding function (not whole files, secrets masked) is sent to ${ai.provider} (${ai.model}). ` +
      "Secrets and dependency findings are never sent. AI output is advice; it doesn't change findings.";
  }

  function renderSettings(s) {
    const labels = { semgrep: "Code analysis", gitleaks: "Secrets", dependencies: "Dependencies" };
    details(document.getElementById("repo-settings"), [
      ["Scanners", (s.enabled_scanners || []).map((n) => labels[n] || n).join(", ")],
      ["Excluded paths", (s.excluded_paths || []).join(" ") || "—"],
      ["Severity threshold", s.severity_threshold],
      ["AI analysis", el("span", {}, s.ai_enabled ? "Enabled" : "Disabled",
        el("span", { class: "muted small", text: ` — ${aiDisclosure(s.ai_enabled)}` }))],
    ]);
    const form = document.getElementById("settings-form");
    for (const box of form.querySelectorAll("input[name=scanner]")) box.checked = (s.enabled_scanners || []).includes(box.value);
    form.excluded_paths.value = (s.excluded_paths || []).join("\n");
    form.severity_threshold.value = s.severity_threshold || "low";
    form.ai_enabled.checked = !!s.ai_enabled;
    document.getElementById("ai-disclosure").textContent = aiDisclosure(form.ai_enabled.checked);
  }

  function setupSettings() {
    if (!canManageRepos()) return;
    const form = document.getElementById("settings-form");
    document.getElementById("repo-settings").hidden = true;
    form.hidden = false;
    form.ai_enabled.addEventListener("change", () => {
      document.getElementById("ai-disclosure").textContent = aiDisclosure(form.ai_enabled.checked);
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errorBox = document.getElementById("settings-error");
      const okBox = document.getElementById("settings-ok");
      showError(errorBox, "");
      okBox.hidden = true;
      const body = {
        enabled_scanners: [...form.querySelectorAll("input[name=scanner]:checked")].map((b) => b.value),
        excluded_paths: form.excluded_paths.value.split("\n").map((p) => p.trim()).filter(Boolean),
        severity_threshold: form.severity_threshold.value,
        ai_enabled: form.ai_enabled.checked,
      };
      try {
        const { data } = await api("PUT", `${path}/settings`, body);
        renderSettings(data);
        okBox.textContent = "Settings saved. They apply to the next audit.";
        okBox.hidden = false;
      } catch (err) {
        showError(errorBox, err.message);
      }
    });
  }

  // ---- GitHub: default branch + access token ----

  async function loadBranches(r) {
    const select = document.getElementById("branch-select");
    try {
      const json = await api("GET", `${path}/branches?per_page=100`);
      const names = json.data.map((b) => b.name);
      loadedBranches.resolve(names);
      if (!names.includes(r.default_branch)) names.unshift(r.default_branch);
      select.replaceChildren(...names.map((n) => el("option", { value: n, text: n, selected: n === r.default_branch })));
      if (json.meta.total > json.data.length) {
        select.append(el("option", { disabled: true, text: `…${json.meta.total - json.data.length} more not shown` }));
      }
      select.disabled = !canManageRepos();
    } catch (err) {
      loadedBranches.resolve(null);
      select.replaceChildren(el("option", { text: r.default_branch }));
      notify(`Could not load branches: ${err.message}`, true);
    }
  }

  function renderToken(r) {
    document.getElementById("token-status").textContent = r.has_access_token
      ? "Access token: saved (encrypted). It is never shown again."
      : "Access token: none (public repository access).";
    document.getElementById("token-remove").hidden = !r.has_access_token;
  }

  function setupGithub(r) {
    document.getElementById("github-source").hidden = false;
    renderToken(r);
    loadBranches(r);
    if (!canManageRepos()) return;

    const branchForm = document.getElementById("branch-form");
    const save = document.getElementById("branch-save");
    save.hidden = false;
    branchForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      save.disabled = true;
      try {
        const json = await api("PATCH", path, { default_branch: branchForm.default_branch.value });
        renderRepo(json.data);
        notify(`Default branch set to ${json.data.default_branch}.`);
      } catch (err) {
        notify(err.message, true);
      } finally {
        save.disabled = false;
      }
    });

    const tokenForm = document.getElementById("token-form");
    tokenForm.hidden = false;
    const patchToken = async (value, message) => {
      try {
        const json = await api("PATCH", path, { access_token: value });
        tokenForm.reset();
        renderToken(json.data);
        notify(message);
      } catch (err) {
        notify(err.message, true);
      }
    };
    tokenForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const value = tokenForm.access_token.value.trim();
      if (!value) return notify("Enter a token first.", true);
      patchToken(value, "Access token verified and saved.");
    });
    document.getElementById("token-remove").addEventListener("click", () => {
      if (confirm("Remove the stored access token? Private repositories will no longer be reachable.")) {
        patchToken(null, "Access token removed.");
      }
    });
  }

  // ---- ZIP: current archive + upload new version ----

  function renderZip(r) {
    const src = r.source || {};
    details(document.getElementById("zip-details"), [
      ["Archive", src.filename],
      ["Uploaded", formatDate(src.uploaded_at)],
      ["Size", `${formatBytes(src.size)} (${formatBytes(src.uncompressed_size)} extracted)`],
      ["Files", src.file_count],
      ["SHA-256", el("code", { class: "small", text: src.sha256 || "—" })],
    ]);
  }

  function setupZip(r) {
    document.getElementById("zip-source").hidden = false;
    renderZip(r);
    if (!canRunAudits()) return;
    const form = document.getElementById("upload-form");
    form.hidden = false;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!form.file.files.length) return notify("Choose a .zip file to upload.", true);
      const button = form.querySelector("button[type=submit]");
      button.disabled = true;
      button.textContent = "Uploading…";
      try {
        const json = await api("PUT", `${path}/source`, new FormData(form));
        form.reset();
        renderZip(json.data);
        notify("New version uploaded. The next audit will use it.");
      } catch (err) {
        notify(err.message, true);
      } finally {
        button.disabled = false;
        button.textContent = "Upload";
      }
    });
  }

  function renderAudits(audits) {
    const box = document.getElementById("audit-history");
    if (!audits.length) {
      box.replaceChildren(emptyState("No audits have been run for this repository yet."));
      return;
    }
    box.replaceChildren(table(["Audit", "Branch", "Status", "Findings", "Score", "Started", "Duration"], audits.map((a) => {
      const s = a.summary || {};
      const open = s.counts ? Object.values(s.counts).reduce((x, y) => x + y, 0) : null;
      return el("tr", {},
        el("td", {}, el("a", { href: `/audit.html?id=${encodeURIComponent(a.id)}`, text: a.display_id })),
        el("td", { text: a.branch }),
        el("td", {}, statusBadge(a.status), a.error ? el("div", { class: "muted small", text: a.error.message }) : null),
        el("td", { text: open === null ? "—" : `${open} open` }),
        el("td", { text: s.security_score ?? "—" }),
        el("td", { text: formatDate(a.started_at || a.created_at) }),
        el("td", { text: a.duration !== null ? `${a.duration}s` : "—" }));
    })));
  }

  // ---- dependencies (latest completed audit) ----

  const depsState = { page: 1, vulnerable: false };

  function sevBadge(sev) {
    return sev ? el("span", { class: `sev-badge sev-${sev}`, text: sev }) : el("span", { class: "muted", text: "—" });
  }

  async function loadDependencies(page = 1) {
    const params = new URLSearchParams({ page, per_page: 25 });
    if (depsState.vulnerable) params.set("vulnerable", "true");
    const json = await api("GET", `${path}/dependencies?${params}`);
    const card = document.getElementById("deps-card");
    if (!json.meta.audit_id) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    depsState.page = json.meta.page;
    document.getElementById("deps-meta").textContent =
      `${json.meta.total} ${depsState.vulnerable ? "vulnerable " : ""}dependencies from ${json.meta.display_id}. ` +
      "Only package names and versions are sent to OSV.dev for matching.";
    const list = document.getElementById("deps-list");
    if (!json.data.length) {
      list.replaceChildren(emptyState(depsState.vulnerable ? "No vulnerable dependencies." : "No dependencies found."));
    } else {
      list.replaceChildren(table(["Package", "Version", "Ecosystem", "Manifest", "Vulnerabilities", "Upgrade to"], json.data.map((d) =>
        el("tr", {},
          el("td", {}, el("code", { text: d.package_name }), d.scope === "dev" ? el("span", { class: "muted small", text: " dev" }) : null),
          el("td", { text: d.version || (d.declared ? `${d.declared} (not pinned)` : "—") }),
          el("td", { text: d.ecosystem }),
          el("td", { class: "small", text: d.line ? `${d.manifest}:${d.line}` : d.manifest }),
          el("td", {}, d.vulnerable
            ? [sevBadge(d.max_severity), " ", el("span", { class: "small", text: d.vulnerabilities.map((v) => v.id).join(", ") })]
            : el("span", { class: "muted", text: d.version ? "None known" : "Not checked" })),
          el("td", { text: d.recommended_version || "—" })))));
    }
    const pager = document.getElementById("deps-pager");
    const m = json.meta;
    pager.replaceChildren(...(m.total_pages > 1 ? [
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page <= 1, onclick: () => loadDependencies(m.page - 1) }, "Previous"),
      el("span", { class: "muted small", text: `Page ${m.page} of ${m.total_pages}` }),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: m.page >= m.total_pages, onclick: () => loadDependencies(m.page + 1) }, "Next"),
    ] : []));
  }

  document.getElementById("deps-vulnerable").addEventListener("change", (e) => {
    depsState.vulnerable = e.target.checked;
    loadDependencies(1);
  });

  // ---- start audit ----

  function renderActiveBanner(audits) {
    const active = audits.find((a) => !a.is_final);
    const banner = document.getElementById("active-banner");
    banner.hidden = !active;
    document.getElementById("start-toggle").disabled = !!active;
    if (active) {
      banner.replaceChildren(
        el("span", { text: `${active.display_id} is ${active.status === "queued" ? "queued" : "running (" + active.status.replace(/_/g, " ") + ")"}.` }),
        el("a", { class: "btn btn-primary btn-sm", href: `/audit.html?id=${encodeURIComponent(active.id)}`, text: "View progress" }));
    }
  }

  function setupStart(repo, branches) {
    if (!canRunAudits()) return;
    const toggle = document.getElementById("start-toggle");
    const card = document.getElementById("start-card");
    const form = document.getElementById("start-form");
    const select = document.getElementById("start-branch");
    toggle.hidden = false;
    if (repo.provider === "github") {
      const names = branches && branches.length ? branches : [repo.default_branch];
      select.replaceChildren(...names.map((n) => el("option", { value: n, text: n, selected: n === repo.default_branch })));
    } else {
      document.getElementById("start-branch-label").hidden = true;
    }
    const open = () => { card.hidden = false; form.audit_type.focus(); };
    toggle.addEventListener("click", () => (card.hidden ? open() : (card.hidden = true)));
    if (window.location.hash === "#start" && !toggle.disabled) open();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errorBox = document.getElementById("start-error");
      showError(errorBox, "");
      const body = { audit_type: form.audit_type.value };
      if (repo.provider === "github") body.branch = select.value;
      const button = form.querySelector("button[type=submit]");
      button.disabled = true;
      try {
        const { data } = await api("POST", `${path}/audits`, body);
        window.location.href = `/audit.html?id=${encodeURIComponent(data.id)}`;
      } catch (err) {
        showError(errorBox, err.message);
        button.disabled = false;
      }
    });
  }

  function setupDelete(repo) {
    if (!canManageRepos()) return;
    const btn = document.getElementById("delete-btn");
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      if (!confirm(`Delete ${repo.name} and all of its audits, findings and uploaded source? This cannot be undone.`)) return;
      btn.disabled = true;
      try {
        await api("DELETE", path);
        window.location.replace("/repositories.html");
      } catch (err) {
        alert(err.message);
        btn.disabled = false;
      }
    });
  }

  ready.then(async () => {
    try {
      const [repo, audits, feat] = await Promise.all([
        api("GET", path), api("GET", `${path}/audits?per_page=50`), api("GET", "/me/features")]);
      features = feat.data;
      renderRepo(repo.data);
      setupSettings();
      renderAudits(audits.data);
      renderActiveBanner(audits.data);
      loadDependencies(1);
      document.getElementById("source-card").hidden = false;
      if (repo.data.provider === "github") {
        setupGithub(repo.data);
        loadedBranches.promise.then((names) => setupStart(repo.data, names));
      } else {
        setupZip(repo.data);
        setupStart(repo.data, null);
      }
      setupDelete(repo.data);
    } catch (err) {
      nameEl.textContent = err.message;
    }
  });
})();
