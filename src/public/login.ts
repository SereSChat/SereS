(() => {
  const t = SeresI18n.t;
  let mode: "login" | "register" = "login";
  let busy = false;

  function el<T extends HTMLElement = HTMLElement>(id: string): T {
    return document.getElementById(id) as T;
  }

  function setWarning(message: string) {
    el("warning").textContent = message;
  }

  function setBusy(value: boolean, label?: string) {
    busy = value;
    el<HTMLButtonElement>("login").disabled = value;
    el<HTMLButtonElement>("register_redirect").disabled =
      value || (mode === "register" && !el<HTMLInputElement>("tos-checkbox").checked);
    if (label !== undefined) setWarning(label);
  }

  async function postJson(url: string, body: object) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok && data.success, status: response.status, data };
  }

  /** Logs in, unlocks the private keys locally and stores them for this browser. */
  async function loginWith(nameomail: string, password: string) {
    const pre = await postJson("/api/prelogin", { nameomail });
    if (!pre.ok) throw new Error(pre.data.message || t("login.failed"));

    const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(
      password,
      pre.data.kdf_salt,
      pre.data.kdf_iterations,
    );
    const body: Record<string, unknown> = { nameomail, auth_hash: authHash };
    if (pre.data.legacy) {
      // Account from before end-to-end encryption: upgrade it on this login.
      body.passwd = password;
      body.keys = await SeresCrypto.createKeyBundle(wrapKey);
    }

    const res = await postJson("/api/login", body);
    if (!res.ok) {
      throw new Error(
        res.status === 429
          ? res.data.message
          : t("login.failedCredentials"),
      );
    }
    const user = res.data.user;
    let identity: SeresIdentity;
    try {
      identity = await SeresCrypto.unlockIdentity(
        user.id,
        user.enc_private,
        wrapKey,
        user.pub_ecdh,
        user.pub_sign,
      );
    } catch {
      await fetch("/api/logout", { method: "POST", credentials: "include" });
      throw new Error(t("login.unlockFailed"));
    }
    await SeresCrypto.clearIdentities();
    await SeresCrypto.saveIdentity(identity);
    const invite = new URLSearchParams(window.location.search).get("invite");
    window.location.href = "index.html?login=true" + (invite ? "&invite=" + encodeURIComponent(invite) : "");
  }

  async function login() {
    if (busy) return;
    const nameomail = el<HTMLInputElement>("email").value.trim();
    const password = el<HTMLInputElement>("password").value;
    if (!nameomail || !password) {
      setWarning(t("login.missingFields"));
      return;
    }
    setBusy(true, t("login.loggingIn"));
    try {
      await loginWith(nameomail, password);
    } catch (error) {
      setBusy(false, error instanceof Error ? error.message : t("common.unreachable"));
    }
  }

  async function register() {
    if (busy) return;
    const username = el<HTMLInputElement>("username").value.trim();
    const email = el<HTMLInputElement>("email").value.trim();
    const password = el<HTMLInputElement>("password").value;

    if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) {
      setWarning(t("login.invalidUsername"));
      return;
    }
    if (password.length < 8) {
      setWarning(t("login.passwordTooShort"));
      return;
    }

    setBusy(true, t("login.creating"));
    try {
      const kdfSalt = SeresCrypto.newSalt();
      const iterations = SeresCrypto.DEFAULT_ITERATIONS;
      const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(
        password,
        kdfSalt,
        iterations,
      );
      const keys = await SeresCrypto.createKeyBundle(wrapKey);
      const res = await postJson("/api/register", {
        username,
        email,
        auth_hash: authHash,
        kdf_salt: kdfSalt,
        kdf_iterations: iterations,
        keys,
      });
      if (!res.ok) {
        setBusy(false, res.data.message || t("login.registerFailed"));
        return;
      }
      setWarning(t("login.created"));
      await loginWith(username, password);
    } catch (error) {
      setBusy(false, error instanceof Error ? error.message : t("login.registerFailed"));
    }
  }

  function showMode(next: "login" | "register") {
    mode = next;
    const isRegister = next === "register";
    const loginButton = el<HTMLButtonElement>("login");
    const mainButton = el<HTMLButtonElement>("register_redirect");

    el("landr").textContent = t(isRegister ? "login.registerTitle" : "login.title");
    el("username").style.display = isRegister ? "block" : "none";
    el("tos-container").style.display = isRegister ? "flex" : "none";
    loginButton.style.display = isRegister ? "none" : "block";
    mainButton.className = isRegister ? "action-button" : "";
    mainButton.disabled = isRegister && !el<HTMLInputElement>("tos-checkbox").checked;
    el<HTMLInputElement>("email").placeholder = t(isRegister ? "login.email" : "login.usernameOrEmail");
    el<HTMLInputElement>("password").placeholder = t(isRegister ? "login.passwordNew" : "login.password");

    const switchLink = el("ahaa");
    switchLink.textContent = "";
    if (isRegister) {
      const link = document.createElement("a");
      link.textContent = t("login.haveAccount");
      link.href = "#";
      link.addEventListener("click", (event) => {
        event.preventDefault();
        showMode("login");
      });
      switchLink.appendChild(link);
    }
    setWarning("");
  }

  function applyLoginTheme() {
    const isBright = SeresI18n.getPreference("theme") === "bright";
    document.body.classList.toggle("bright-body", isBright);
    document.querySelector(".login")?.classList.toggle("bright-login", isBright);
    document.querySelector(".landr")?.classList.toggle("bright-landr", isBright);
    document.querySelector(".login-f")?.classList.toggle("bright-login-f", isBright);
    document.querySelector("#ahaa")?.classList.toggle("bright-ahaa", isBright);
    document
      .querySelector(".tos-container")
      ?.classList.toggle("bright-tos-container", isBright);
  }

  function toggleLoginTheme() {
    const newTheme = SeresI18n.getPreference("theme") === "bright" ? "dark" : "bright";
    SeresI18n.setPreference("theme", newTheme);
    applyLoginTheme();
  }

  document.addEventListener("DOMContentLoaded", () => {
    SeresI18n.apply();
    showMode("login");

    el("login").addEventListener("click", login);
    el("register_redirect").addEventListener("click", () => {
      if (mode === "register") register();
      else showMode("register");
    });
    el("tos-checkbox").addEventListener("change", () => {
      el<HTMLButtonElement>("register_redirect").disabled =
        busy || !el<HTMLInputElement>("tos-checkbox").checked;
    });
    el("tos-link").addEventListener("click", (event) => {
      event.preventDefault();
      el("tos-modal").style.display = "flex";
    });
    el("tos-close").addEventListener("click", () => {
      el("tos-modal").style.display = "none";
    });
    el("tos-modal").addEventListener("click", (event) => {
      if (event.target === el("tos-modal")) el("tos-modal").style.display = "none";
    });
    el("password").addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") {
        if (mode === "register") register();
        else login();
      }
    });

    const params = new URLSearchParams(window.location.search);
    const reason = params.get("reason");
    if (params.get("invite")) setWarning(t("invite.loginHint"));
    if (reason === "keys") {
      setWarning(t("login.reloginKeys"));
    }

    const toggleBtn = document.createElement("button");
    toggleBtn.className = "theme-toggle-floating";
    toggleBtn.type = "button";
    toggleBtn.dataset.i18n = "common.themeToggle";
    toggleBtn.textContent = t("common.themeToggle");
    toggleBtn.addEventListener("click", toggleLoginTheme);

    // Switching the language re-renders the texts that depend on the mode.
    const languageSelect = SeresI18n.languageSelect(() => showMode(mode));
    const controls = document.createElement("div");
    controls.className = "floating-controls";
    controls.append(languageSelect, toggleBtn);
    document.body.appendChild(controls);

    applyLoginTheme();
  });
})();
