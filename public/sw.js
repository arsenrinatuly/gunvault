// BoundStack Service Worker — real PWA offline support
const CACHE = 'boundstack-v2';
const STATIC = [
  '/',
  '/app',
  '/app.html',
  '/index.html',
  '/privacy',
  '/terms',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap'
];

// IndexedDB helpers for offline read cache + write queue
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('boundstack', 2);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('api_cache')) db.createObjectStore('api_cache', { keyPath: 'url' });
      if (!db.objectStoreNames.contains('write_queue')) db.createObjectStore('write_queue', { keyPath: 'id', autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC).catch(() => {})));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Whitelist of GET API routes we cache for offline reads
  const CACHEABLE_API = [
    '/api/app/firearms',
    '/api/app/customers',
    '/api/app/form4473',
    '/api/app/sales',
    '/api/app/dashboard',
    '/api/app/me',
    '/api/app/locations',
    '/api/app/readiness-score',
  ];

  if (url.pathname.startsWith('/api/')) {
    const isReadable = e.request.method === 'GET' && CACHEABLE_API.some(p => url.pathname.startsWith(p));

    if (isReadable) {
      // Network-first, fall back to IndexedDB cache
      e.respondWith((async () => {
        try {
          const res = await fetch(e.request);
          if (res.ok) {
            const clone = res.clone();
            const text = await clone.text();
            await idbPut('api_cache', { url: url.pathname + url.search, body: text, ts: Date.now() });
            return new Response(text, { status: res.status, headers: res.headers });
          }
          return res;
        } catch (err) {
          const cached = await idbGet('api_cache', url.pathname + url.search);
          if (cached) {
            return new Response(cached.body, {
              status: 200,
              headers: { 'Content-Type': 'application/json', 'X-From-Cache': '1' }
            });
          }
          return new Response(JSON.stringify({ error: 'Offline and no cached data available' }), {
            status: 503, headers: { 'Content-Type': 'application/json' }
          });
        }
      })());
      return;
    }

    // Non-cacheable API calls: pure network with clean error
    e.respondWith(
      fetch(e.request).catch(() =>
        new Response(JSON.stringify({ error: 'Offline — request queued. Reconnect to sync.' }), {
          status: 503, headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }

  // App shell: cache-first
  if (e.request.mode === 'navigate' || url.pathname === '/app' || url.pathname.endsWith('.html')) {
    e.respondWith(
      caches.match(e.request).then(cached => {
        const net = fetch(e.request).then(res => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE).then(c => c.put(e.request, clone));
          }
          return res;
        }).catch(() => cached || caches.match('/app.html'));
        return cached || net;
      })
    );
    return;
  }

  // Everything else: stale-while-revalidate
  e.respondWith(
    caches.open(CACHE).then(cache =>
      cache.match(e.request).then(cached => {
        const net = fetch(e.request).then(res => {
          if (res.ok) cache.put(e.request, res.clone());
          return res;
        }).catch(() => cached);
        return cached || net;
      })
    )
  );
});

// Background sync trigger: replay queued writes
self.addEventListener('sync', (e) => {
  if (e.tag === 'boundstack-sync-queue') {
    e.waitUntil((async () => {
      const clients = await self.clients.matchAll();
      clients.forEach(c => c.postMessage({ type: 'sync-trigger' }));
    })());
  }
});
