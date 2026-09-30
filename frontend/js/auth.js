(function () {
  const { authenticate, showError } = window.App;
  const form = document.getElementById("auth-form");
  const errorBox = document.getElementById("form-error");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError(errorBox, "");
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    const body = Object.fromEntries(new FormData(form));
    if (body.organization_name === "") delete body.organization_name;
    try {
      await authenticate(form.dataset.endpoint, body);
      window.location.replace("/");
    } catch (err) {
      showError(errorBox, err.message);
      button.disabled = false;
    }
  });
})();
