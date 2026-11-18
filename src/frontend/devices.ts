// Turns a browser's user agent into what the device list shows:
// type (phone, tablet, computer), system and browser.

interface SeresDevice {
  type: "phone" | "tablet" | "desktop";
  icon: string;
  os: string;
  browser: string;
}

const SeresDevices = (() => {
  function describe(userAgent: string | null | undefined): SeresDevice {
    const ua = userAgent || "";
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
    const type: SeresDevice["type"] =
      /iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))
        ? "tablet"
        : /iPhone|Mobile|Android/.test(ua)
          ? "phone"
          : "desktop";
    const icon = type === "phone" ? "smartphone" : type === "tablet" ? "tablet" : "computer";
    return { type, icon, os, browser };
  }

  return { describe };
})();

(window as any).SeresDevices = SeresDevices;
