// Service worker of SereS (plain JavaScript, not compiled from src/frontend).
// It makes SereS installable as an app and shows push notifications while
// SereS is closed. It doesn't cache anything: the app always loads fresh files.
//
// A push only says who wrote or calls; the message texts stay end-to-end
// encrypted and are shown once SereS is open.

const TEXT = {
  en: { message: "New message", call: "is calling you", callIn: "is calling in", login: "New login", loginBody: "wants to log in. Open SereS to allow or refuse it." },
  de: { message: "Neue Nachricht", call: "ruft dich an", callIn: "ruft an in", login: "Neue Anmeldung", loginBody: "möchte sich anmelden. Öffne SereS, um es zu erlauben oder abzulehnen." },
  fr: { message: "Nouveau message", call: "t'appelle", callIn: "appelle dans", login: "Nouvelle connexion", loginBody: "veut se connecter. Ouvre SereS pour l'autoriser ou la refuser." },
};

function text() {
  const lang = (self.navigator.language || "en").slice(0, 2).toLowerCase();
  return TEXT[lang] || TEXT.en;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  const t = text();
  const from = data.from || "SereS";
  let title;
  let options;
  if (data.type === "login") {
    // A password login waits for this device (the main device) to allow it.
    title = t.login;
    options = { body: `${data.device || "?"} ${t.loginBody}`, tag: "login", renotify: true, requireInteraction: true };
  } else if (data.type === "call") {
    title = data.group || from;
    options = {
      body: data.group ? `${from} ${t.callIn} ${data.group}` : `${from} ${t.call}`,
      tag: "call-" + data.call,
      requireInteraction: true,
      vibrate: [400, 200, 400, 200, 400],
    };
  } else {
    title = data.group || from;
    options = {
      body: data.group ? `${from}: ${t.message}` : t.message,
      // One notification per chat, replaced by the next one.
      tag: data.chat || "seres",
      renotify: true,
    };
  }
  options.icon = "/assets/icons/icon-192.png";
  options.badge = "/assets/icons/icon-192.png";
  options.data = { chat: data.chat || null };
  event.waitUntil(self.registration.showNotification(title, options));
});

// Opens the chat: in a SereS window that is already open, or in a new one.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const chat = event.notification.data && event.notification.data.chat;
  const url = chat ? "/?chat=" + encodeURIComponent(chat) : "/";
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      // Only the chat page (/ or /index.html) understands "open-chat".
      for (const client of windows) {
        const page = new URL(client.url);
        if (page.origin !== self.location.origin || !["/", "/index.html"].includes(page.pathname)) continue;
        await client.focus();
        if (chat) client.postMessage({ type: "open-chat", chat });
        return;
      }
      await self.clients.openWindow(url);
    })(),
  );
});
