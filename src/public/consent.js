"use strict";
// Cookie banner: asks once whether preference cookies (language, design) may be
// kept across browser sessions. Login cookies are necessary and always used.
const SeresConsent = (() => {
    function el(tag, className, key) {
        const element = document.createElement(tag);
        element.className = className;
        element.dataset.i18n = key;
        element.textContent = SeresI18n.t(key);
        return element;
    }
    /** Shows the banner (again); onDecide runs after a choice was made. */
    function show(onDecide) {
        document.getElementById("cookie-banner")?.remove();
        const banner = document.createElement("div");
        banner.id = "cookie-banner";
        banner.className = "cookie-banner";
        banner.setAttribute("role", "dialog");
        banner.setAttribute("aria-live", "polite");
        const choose = (accepted) => {
            SeresI18n.setConsent(accepted);
            banner.remove();
            if (onDecide)
                onDecide();
        };
        const deny = el("button", "cookie-btn cookie-deny", "consent.deny");
        deny.type = "button";
        deny.addEventListener("click", () => choose(false));
        const accept = el("button", "cookie-btn cookie-accept", "consent.accept");
        accept.type = "button";
        accept.addEventListener("click", () => choose(true));
        const buttons = document.createElement("div");
        buttons.className = "cookie-buttons";
        buttons.append(deny, accept);
        banner.append(el("strong", "cookie-title", "consent.title"), el("p", "cookie-text", "consent.text"), buttons);
        document.body.appendChild(banner);
    }
    function init() {
        if (!SeresI18n.getConsent())
            show();
    }
    return { show, init };
})();
window.SeresConsent = SeresConsent;
document.addEventListener("DOMContentLoaded", () => SeresConsent.init());
