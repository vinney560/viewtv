const CACHE_NAME = "app-cache-v2";
const urlsToCache = [
  "/",          // landing page route
  "/login",     
  "/register",  
  "/home_2",
  "/home_1",
  "/uploads/favicon.ico"
];

// Install: cache static assets
self.addEventListener("install", event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

// Activate: remove old caches
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => key !== CACHE_NAME && caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// Fetch: advanced network management
self.addEventListener("fetch", event => {
  const requestUrl = new URL(event.request.url);

  // 1. API requests: network-first
  if (requestUrl.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          const resClone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // 2. Static assets: cache-first
  if (urlsToCache.includes(requestUrl.pathname)) {
    event.respondWith(
      caches.match(event.request).then(cached => cached || fetch(event.request).then(response => {
        const resClone = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
        return response;
      }))
    );
    return;
  }

  // 3. Page routes: stale-while-revalidate
  if (event.request.mode === "navigate") {
    event.respondWith(
      caches.match(event.request).then(cached => {
        const networkFetch = fetch(event.request)
          .then(response => {
            const resClone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
            return response;
          })
          .catch(() => null); // fallback handled below
        return cached || networkFetch || caches.match("/"); // landing page fallback
      })
    );
    return;
  }

  // 4. Default: try network, fallback to cache
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});