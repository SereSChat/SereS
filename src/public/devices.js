"use strict";
// Turns a browser's user agent into what the device list shows:
// type (phone, tablet, computer), system and browser.
const SeresDevices = (() => {
    function describe(userAgent) {
        const ua = userAgent || "";
        // The native app doesn't send a browser user agent: on iOS it is like
        // "SereS/12 CFNetwork/1568.100.1 Darwin/24.0.0", on Android "okhttp/4.12.0".
        // A Mac app would say "Macintosh" or "x86_64", so the rest is an iPhone/iPad.
        if (!/Mozilla\//.test(ua) && /CFNetwork|Darwin/.test(ua) && !/Macintosh|x86_64|MacBook|iMac/.test(ua)) {
            const ipad = /iPad/.test(ua);
            return { type: ipad ? "tablet" : "phone", icon: ipad ? "tablet" : "smartphone", os: ipad ? "iPad" : "iPhone", browser: "SereS App" };
        }
        if (!/Mozilla\//.test(ua) && /okhttp|Dalvik|Android/i.test(ua)) {
            return { type: "phone", icon: "smartphone", os: "Android", browser: "SereS App" };
        }
        const os = /iPhone/.test(ua)
            ? "iPhone"
            : /iPad/.test(ua)
                ? "iPad"
                : /Android/.test(ua)
                    ? "Android"
                    : /Windows/.test(ua)
                        ? "Windows"
                        : /CrOS/.test(ua)
                            ? "ChromeOS"
                            : /Mac OS X|Macintosh/.test(ua)
                                ? "macOS"
                                : /Linux/.test(ua)
                                    ? "Linux"
                                    : "?";
        const browser = /Edg\//.test(ua)
            ? "Edge"
            : /OPR\//.test(ua)
                ? "Opera"
                : /SamsungBrowser\//.test(ua)
                    ? "Samsung Internet"
                    : /Firefox\/|FxiOS\//.test(ua)
                        ? "Firefox"
                        : /Chrome\/|CriOS\//.test(ua)
                            ? "Chrome"
                            : /Safari\//.test(ua)
                                ? "Safari"
                                : "?";
        const type = /iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))
            ? "tablet"
            : /iPhone|Mobile|Android/.test(ua)
                ? "phone"
                : "desktop";
        const icon = type === "phone" ? "smartphone" : type === "tablet" ? "tablet" : "computer";
        return { type, icon, os, browser };
    }
    return { describe };
})();
window.SeresDevices = SeresDevices;
