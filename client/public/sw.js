const CACHE_NAME = "3233-v2";

const PRECACHE = ["/", "/chats", "/newchat"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE)),
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== CACHE_NAME)
          .map((k) => caches.delete(k)),
      ),
    ),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith("/v1/")) return;

  if (event.request.method !== "GET") return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() => caches.match(event.request)),
  );
});

/**
 * Accept notification requests from the page. Needed for browsers that only
 * surface notifications from a service-worker registration when the page is
 * backgrounded, and as a single code path whether the page or a push event
 * shows the notification.
 */
self.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return;
  if (data.type === "3233:show-notification") {
    const { title, options } = data;
    event.waitUntil(self.registration.showNotification(title, options || {}));
  }
});

/**
 * Focus an existing tab if one is already open; otherwise open a new one at
 * the supplied URL. If a tab is found, post a message so the SPA can route to
 * the relevant thread without a full reload.
 */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const url = typeof data.url === "string" ? data.url : "/chats";

  event.waitUntil(
    (async () => {
      const clientsList = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });
      for (const client of clientsList) {
        if (new URL(client.url).origin !== self.location.origin) continue;
        try {
          client.postMessage({ type: "3233:notif-click", url, data });
        } catch (_) {
          /* ignore */
        }
        try {
          await client.focus();
          return;
        } catch (_) {
          /* fall through to open a new window */
        }
      }
      try {
        await self.clients.openWindow(url);
      } catch (_) {
        /* ignore */
      }
    })(),
  );
});

/**
 * Web Push entry point. The server delivers an opaque JSON payload with the
 * sender's short fingerprint; plaintext stays client-side because messages are
 * end-to-end encrypted. If no payload is delivered (e.g. privacy-preserving
 * push providers strip it) we fall back to a generic "new message" notice.
 */
self.addEventListener("push", (event) => {
  let title = "3233 · new message";
  let options = {
    body: "Open to decrypt.",
    icon: "/icon-192.png",
    badge: "/favicon-32.png",
    tag: "3233-msg",
    renotify: true,
    data: { url: "/chats" },
  };
  try {
    if (event.data) {
      const p = event.data.json();
      if (p && typeof p === "object") {
        if (typeof p.title === "string") title = p.title;
        if (p.options && typeof p.options === "object") {
          options = { ...options, ...p.options };
        }
      }
    }
  } catch (_) {
    /* keep defaults */
  }
  event.waitUntil(self.registration.showNotification(title, options));
});
