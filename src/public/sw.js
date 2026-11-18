// Service worker of SereS (plain JavaScript, not compiled from src/frontend).
// It makes SereS installable as an app and shows push notifications while
// SereS is closed. It doesn't cache anything: the app always loads fresh files.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
