"use strict";
// Translations and preference cookies shared by all pages.
//
// The dictionaries live in language/<code>.js and register themselves on
// window.SeresLang. The chosen language is stored in the "lang" cookie.
// Preference cookies (language, theme) are only kept across browser restarts
// when the user accepted cookies; otherwise they are session cookies.
const SeresI18n = (() => {
    const LANGUAGES = {
        en: "English",
        de: "Deutsch",
        fr: "Français",
    };
    const ONE_YEAR = 60 * 60 * 24 * 365;
    const PREFERENCE_COOKIES = ["lang", "theme"];
    function dictionaries() {
        return window.SeresLang || {};
    }
    function isLanguage(value) {
        return !!value && Object.prototype.hasOwnProperty.call(LANGUAGES, value);
    }
    function getCookie(name) {
        const match = document.cookie.split("; ").find((part) => part.startsWith(name + "="));
        return match ? decodeURIComponent(match.slice(name.length + 1)) : undefined;
    }
    function writeCookie(name, value, persistent) {
        const maxAge = persistent ? "; max-age=" + ONE_YEAR : "";
        document.cookie = name + "=" + encodeURIComponent(value) + "; path=/" + maxAge + "; SameSite=Lax";
    }
    /** "accepted", "denied" or undefined when the user has not decided yet. */
    function getConsent() {
        const value = getCookie("cookie_consent");
        return value === "accepted" || value === "denied" ? value : undefined;
    }
    /** Stores a preference; it only outlives the browser session with consent. */
    function setPreference(name, value) {
        writeCookie(name, value, getConsent() === "accepted");
    }
    function setConsent(accepted) {
        // Remembering the decision itself is necessary, so it is always persistent.
        writeCookie("cookie_consent", accepted ? "accepted" : "denied", true);
        for (const name of PREFERENCE_COOKIES) {
            const value = getCookie(name);
            if (value !== undefined)
                writeCookie(name, value, accepted);
        }
    }
    function detectLanguage() {
        const saved = getCookie("lang");
        if (isLanguage(saved))
            return saved;
        for (const preferred of navigator.languages || [navigator.language]) {
            const code = (preferred || "").slice(0, 2).toLowerCase();
            if (isLanguage(code))
                return code;
        }
        return "en";
    }
    let language = detectLanguage();
    document.documentElement.lang = language;
    /** Translates a key and fills in {placeholders}. Falls back to English, then to the key. */
    function t(key, params = {}) {
        const all = dictionaries();
        const text = all[language]?.[key] ?? all.en?.[key] ?? key;
        return text.replace(/\{(\w+)\}/g, (match, name) => Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match);
    }
    /** Fills every element marked with data-i18n(-placeholder|-title|-aria-label). */
    function apply(root = document) {
        root.querySelectorAll("[data-i18n]").forEach((el) => {
            el.textContent = t(el.dataset.i18n);
        });
        root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
            el.placeholder = t(el.dataset.i18nPlaceholder);
        });
        root.querySelectorAll("[data-i18n-title]").forEach((el) => {
            el.title = t(el.dataset.i18nTitle);
        });
        root.querySelectorAll("[data-i18n-aria-label]").forEach((el) => {
            el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
        });
    }
    function getLanguage() {
        return language;
    }
    function setLanguage(next) {
        if (!isLanguage(next))
            return;
        language = next;
        document.documentElement.lang = next;
        setPreference("lang", next);
        apply();
    }
    /** A <select> with all languages; calls onChange after the language was switched. */
    function languageSelect(onChange) {
        const select = document.createElement("select");
        select.className = "language-select";
        select.setAttribute("aria-label", t("common.language"));
        for (const [code, name] of Object.entries(LANGUAGES)) {
            const option = document.createElement("option");
            option.value = code;
            option.textContent = name;
            option.selected = code === language;
            select.appendChild(option);
        }
        select.addEventListener("change", () => {
            setLanguage(select.value);
            if (onChange)
                onChange(language);
        });
        return select;
    }
    return {
        LANGUAGES,
        t,
        apply,
        getLanguage,
        setLanguage,
        languageSelect,
        getCookie,
        getConsent,
        setConsent,
        setPreference,
    };
})();
window.SeresI18n = SeresI18n;
