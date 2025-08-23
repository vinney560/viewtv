const CACHE_NAME = 'viewtv-cache-v2';
const DYNAMIC_CACHE = 'viewtv-dynamic-v1';
const OFFLINE_URL = '/offline.html';
const STATIC_PAGES = ['/', '/home_2', OFFLINE_URL];
const LOCAL_PLAYER = '/local-player';
const DEBOUNCE_DELAY = 2000;

let onlineStatus = navigator.onLine;
let debounceTimer = null;

// Utility: broadcast to all clients
async function broadcast(type) {
  const clients = await self.clients.matchAll();
  clients.forEach(client => client.postMessage({ type }));
}

// Install: cache static pages
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_PAGES))
  );
  self.skipWaiting();
});

// Activate: cleanup old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.map(key => {
        if (![CACHE_NAME, DYNAMIC_CACHE].includes(key)) return caches.delete(key);
      })
    ))
  );
  self.clients.claim();
});

// Fetch handler
self.addEventListener('fetch', event => {
  const reqUrl = new URL(event.request.url);

  // Fully offline /local-player
  if(reqUrl.pathname.startsWith(LOCAL_PLAYER)) {
    event.respondWith(
      caches.match(event.request).then(resp => resp || fetch(event.request).catch(() => new Response('', {status:200})))
    );
    return;
  }

  // Static pages: stale-while-revalidate
  if(STATIC_PAGES.includes(reqUrl.pathname)) {
    event.respondWith(
      caches.match(event.request).then(cachedResp => {
        const fetchPromise = fetch(event.request).then(networkResp => {
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, networkResp.clone()));
          return networkResp;
        }).catch(() => null);
        return cachedResp || fetchPromise;
      })
    );
    return;
  }

  // Other requests: dynamic cache with offline fallback
  event.respondWith(
    fetch(event.request)
      .then(resp => {
        if(resp && resp.status === 200) {
          const respClone = resp.clone();
          caches.open(DYNAMIC_CACHE).then(cache => cache.put(event.request, respClone));
        }
        updateNetworkStatus(true);
        return resp;
      })
      .catch(() => {
        updateNetworkStatus(false);
        return caches.match(event.request).then(resp => resp || caches.match(OFFLINE_URL));
      })
  );
});

// Debounced network status update
function updateNetworkStatus(status) {
  if(status !== onlineStatus) {
    onlineStatus = status;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      broadcast(status ? 'ONLINE' : 'OFFLINE');
    }, DEBOUNCE_DELAY);
  }
}

// Optional: fallback offline overlay injection
self.addEventListener('message', event => {
  if(event.data && event.data.type === 'SHOW_OFFLINE_OVERLAY') {
    // Could inject offline UI overlay dynamically here
  }
});