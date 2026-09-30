(function () {
  const { api, ready, el, table, formatDate, emptyState, showError, canManageRepos } = window.App;
  const addCard = document.getElementById("add-card");
  const addToggle = document.getElementById("add-toggle");
  const githubForm = document.getElementById("github-form");
  const zipForm = document.getElementById("zip-form");
  const errorBox = document.getElementById("form-error");
  const list = document.getElementById("repo-list");
  const pager = document.getElementById("pager");
  const PER_PAGE = 25;
  let page = 1;

  addToggle.addEventListener("click", () => {
    addCard.hidden = !addCard.hidden;
    if (!addCard.hidden) githubForm.url.focus();
  });

  for (const tab of addCard.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      for (const t of addCard.querySelectorAll(".tab")) {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", String(active));
      }
      for (const panel of addCard.querySelectorAll("[data-panel]")) {
        panel.hidden = panel.dataset.panel !== tab.dataset.tab;
      }
      showError(errorBox, "");
    });
  }

  function sourceLabel(r) {
    if (r.provider === "zip") return r.source ? `ZIP · ${r.source.filename}` : "ZIP";
    return r.url || "";
  }

  function render(repos) {
    if (!repos.length) {
      list.replaceChildren(emptyState("No repositories yet."));
      return;
    }
    list.replaceChildren(table(["Repository", "Branch", "Language", "Last audit", "Score", "Open", "Critical"], repos.map((r) =>
      el("tr", {},
        el("td", {},
          el("a", { href: `/repository.html?id=${encodeURIComponent(r.id)}`, text: r.name }),
          el("div", { class: "muted small", text: sourceLabel(r) })),
        el("td", { text: r.default_branch || "—" }),
        el("td", { text: [r.language, r.framework].filter(Boolean).join(" / ") || "—" }),
        el("td", { text: r.last_audit ? formatDate(r.last_audit.completed_at) : "Never" }),
        el("td", { text: r.security_score ?? "—" }),
        el("td", { text: r.open_findings }),
        el("td", {}, el("span", { class: r.counts.critical ? "sev-text-critical" : "", text: r.counts.critical }))))));
  }

  function renderPager(meta) {
    if (meta.total_pages <= 1) {
      pager.replaceChildren();
      return;
    }
    pager.replaceChildren(
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: meta.page <= 1, onclick: () => load(meta.page - 1) }, "Previous"),
      el("span", { class: "muted small", text: `Page ${meta.page} of ${meta.total_pages}` }),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", disabled: meta.page >= meta.total_pages, onclick: () => load(meta.page + 1) }, "Next"));
  }

  async function load(p = page) {
    const json = await api("GET", `/repositories?page=${p}&per_page=${PER_PAGE}`);
    page = json.meta.page;
    render(json.data);
    renderPager(json.meta);
  }

  async function submit(form, busyText, send) {
    showError(errorBox, "");
    const button = form.querySelector("button[type=submit]");
    const label = button.textContent;
    button.disabled = true;
    button.textContent = busyText;
    try {
      const json = await send();
      window.location.href = `/repository.html?id=${encodeURIComponent(json.data.id)}`;
    } catch (err) {
      showError(errorBox, err.message);
      button.disabled = false;
      button.textContent = label;
    }
  }

  githubForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(githubForm));
    for (const k of ["default_branch", "name", "access_token"]) if (!body[k]) delete body[k];
    submit(githubForm, "Checking repository…", () => api("POST", "/repositories", body));
  });

  zipForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!zipForm.file.files.length) {
      showError(errorBox, "Choose a .zip file to upload");
      return;
    }
    const data = new FormData(zipForm);
    if (!data.get("name")) data.delete("name");
    submit(zipForm, "Uploading…", () => api("POST", "/repositories/uploads", data));
  });

  ready.then(() => {
    addToggle.hidden = !canManageRepos();
    return load(1);
  });
})();
