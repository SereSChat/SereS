// Shows freshly created backup codes exactly once (like Discord). They can be
// downloaded as a .txt file or copied; after closing they are gone for good,
// only new codes can be generated.

const SeresCodes = (() => {
  const t = SeresI18n.t;

  function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function fileText(codes: string[], username: string) {
    const date = new Date().toLocaleString(SeresI18n.getLanguage());
    return [
      t("codes.fileTitle", { name: username }),
      t("codes.fileCreated", { date }),
      "",
      t("codes.fileHint1"),
      t("codes.fileHint2"),
      "",
      ...codes.map((code, i) => `${String(i + 1).padStart(2, " ")}. ${code}`),
      "",
    ].join("\r\n");
  }

  function download(codes: string[], username: string) {
    const blob = new Blob([fileText(codes, username)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `seres-backup-codes-${username}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /** Shows the codes in a dialog; onClose runs after the user closed it. */
  function show(codes: string[], username: string, onClose?: () => void) {
    let saved = false;
    const overlay = el("div", "modal-overlay codes-overlay");
    const box = el("div", "modal-box codes-box");
    const list = el("ol", "codes-list");
    for (const code of codes) list.appendChild(el("li", undefined, code));

    const status = el("p", "codes-status");
    const downloadBtn = el("button", "modal-btn confirm-btn", t("codes.download"));
    downloadBtn.type = "button";
    downloadBtn.addEventListener("click", () => {
      download(codes, username);
      saved = true;
      status.textContent = t("codes.downloaded");
    });
    const copyBtn = el("button", "modal-btn secondary-btn", t("codes.copy"));
    copyBtn.type = "button";
    copyBtn.addEventListener("click", () => {
      navigator.clipboard
        .writeText(fileText(codes, username))
        .then(() => {
          saved = true;
          status.textContent = t("codes.copied");
        })
        .catch(() => (status.textContent = t("codes.copyFailed")));
    });
    const doneBtn = el("button", "modal-btn cancel-btn", t("codes.done"));
    doneBtn.type = "button";
    doneBtn.addEventListener("click", () => {
      if (!saved && !window.confirm(t("codes.closeConfirm"))) return;
      // The codes only exist in this dialog; removing it forgets them.
      list.textContent = "";
      overlay.remove();
      if (onClose) onClose();
    });

    const actions = el("div", "modal-buttons codes-actions");
    actions.append(copyBtn, downloadBtn, doneBtn);
    box.append(
      el("h3", undefined, t("codes.title")),
      el("p", undefined, t("codes.text")),
      el("p", "codes-warning", t("codes.warning")),
      list,
      status,
      actions,
    );
    overlay.appendChild(box);
    document.body.appendChild(overlay);
  }

  return { show };
})();

(window as any).SeresCodes = SeresCodes;
