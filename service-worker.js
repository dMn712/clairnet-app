const CACHE_NAME = "clairnet-v5";

const APP_FILES = [
  "./",
  "./index.html",
  "./manifest.json",
  "./engine.js",
  "./icon-192.png",
  "./icon-512.png"
];

// Installation : mise en cache des fichiers essentiels
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(APP_FILES);
    })
  );

  self.skipWaiting();
});

// Activation : suppression des anciens caches CLAIRNET
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) =>
            key.startsWith("clairnet-") && key !== CACHE_NAME
          )
          .map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

// Navigation : réseau en priorité, cache en secours
self.addEventListener("fetch", (event) => {
  const request = event.request;

  if (request.method !== "GET") return;

  const url = new URL(request.url);

  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put("./index.html", copy);
            });
          }
          return response;
        })
        .catch(async () => {
          return (
            await caches.match("./index.html")
          ) || Response.error();
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then(async (cached) => {
      if (cached) return cached;

      try {
        return await fetch(request);
      } catch (error) {
        return Response.error();
      }
    })
  );
});
