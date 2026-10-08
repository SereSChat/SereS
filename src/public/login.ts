(() => {
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
    if (!pre.ok) throw new Error(pre.data.message || "Login failed");

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
          : "Login failed, check your credentials.",
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
      throw new Error("Your encryption keys could not be unlocked.");
    }
    await SeresCrypto.clearIdentities();
    await SeresCrypto.saveIdentity(identity);
    window.location.href = "index.html?login=true";
  }

  async function login() {
    if (busy) return;
    const nameomail = el<HTMLInputElement>("email").value.trim();
    const password = el<HTMLInputElement>("password").value;
    if (!nameomail || !password) {
      setWarning("Please enter your username or email and password.");
      return;
    }
    setBusy(true, "Unlocking your encrypted chats...");
    try {
      await loginWith(nameomail, password);
    } catch (error) {
      setBusy(false, error instanceof Error ? error.message : "Server unreachable. Please try again later.");
    }
  }

  async function register() {
    if (busy) return;
    const username = el<HTMLInputElement>("username").value.trim();
    const email = el<HTMLInputElement>("email").value.trim();
    const password = el<HTMLInputElement>("password").value;

    if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) {
      setWarning("Username must be 3-20 characters: letters, numbers, '_' or '-'.");
      return;
    }
    if (password.length < 8) {
      setWarning("Password must be at least 8 characters long.");
      return;
    }

    setBusy(true, "Creating your encryption keys...");
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
        setBusy(false, res.data.message || "An Error occurred during registration.");
        return;
      }
      setWarning("Account created, logging in...");
      await loginWith(username, password);
    } catch (error) {
      setBusy(false, error instanceof Error ? error.message : "An Error occurred during registration.");
    }
  }

  function showMode(next: "login" | "register") {
    mode = next;
    const isRegister = next === "register";
    const loginButton = el<HTMLButtonElement>("login");
    const mainButton = el<HTMLButtonElement>("register_redirect");

    el("landr").textContent = isRegister ? "Register" : "Login";
    el("username").style.display = isRegister ? "block" : "none";
    el("tos-container").style.display = isRegister ? "flex" : "none";
    loginButton.style.display = isRegister ? "none" : "block";
    mainButton.className = isRegister ? "action-button" : "";
    mainButton.disabled = isRegister && !el<HTMLInputElement>("tos-checkbox").checked;
    el<HTMLInputElement>("email").placeholder = isRegister ? "Email" : "Username or Email";
    el<HTMLInputElement>("password").placeholder = isRegister
      ? "Password (minimum 8 characters)"
      : "Password";

    const switchLink = el("ahaa");
    switchLink.textContent = "";
    if (isRegister) {
      const link = document.createElement("a");
      link.textContent = "Already have an account?";
      link.href = "#";
      link.addEventListener("click", (event) => {
        event.preventDefault();
        showMode("login");
      });
      switchLink.appendChild(link);
    }
    setWarning("");
  }

  function getCookie(name: string) {
    const match = document.cookie
      .split("; ")
      .find((part) => part.startsWith(name + "="));
    return match ? decodeURIComponent(match.slice(name.length + 1)) : undefined;
  }

  function applyLoginTheme() {
    const isBright = getCookie("theme") === "bright";
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
    const newTheme = getCookie("theme") === "bright" ? "dark" : "bright";
    document.cookie = "theme=" + newTheme + "; path=/; max-age=31536000; SameSite=Lax";
    applyLoginTheme();
  }

  document.addEventListener("DOMContentLoaded", () => {
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

    const reason = new URLSearchParams(window.location.search).get("reason");
    if (reason === "keys") {
      setWarning("Please log in again to unlock your end-to-end encrypted chats on this device.");
    }

    const toggleBtn = document.createElement("button");
    toggleBtn.className = "theme-toggle-floating";
    toggleBtn.type = "button";
    toggleBtn.innerText = "🌓 Mode";
    toggleBtn.addEventListener("click", toggleLoginTheme);
    document.body.appendChild(toggleBtn);

    applyLoginTheme();
  });
})();
