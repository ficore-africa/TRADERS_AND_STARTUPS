const CACHE_NAME = 'ficore-accounting-v1';
const urlsToCache = [
    '/',
    '/users/login',
    '/users/signup',
    '/users/profile',
    '/users/setup_wizard',
    '{{ url_for("static", filename="css/styles.css") }}',
    '{{ url_for("static", filename="img/logo.png") }}',
    '{{ url_for("static", filename="img/favicon.ico") }}',
    '{{ url_for("static", filename="img/icons/icon-192x192.png") }}',
    '{{ url_for("static", filename="img/icons/icon-512x512.png") }}',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
    'https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js',
    '/templates/base.html',
    '/templates/users/login.html',
    '/templates/users/signup.html',
    '/templates/users/profile.html',
    '/templates/users/setup.html'
];

// Install event: Cache static assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Caching static assets');
                return cache.addAll(urlsToCache);
            })
            .catch(error => {
                console.error('Cache installation failed:', error);
            })
    );
    self.skipWaiting();
});

// Activate event: Clean up old caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames
                    .filter(cacheName => cacheName !== CACHE_NAME)
                    .map(cacheName => caches.delete(cacheName))
            );
        })
    );
    self.clients.claim();
});

// Fetch event: Serve from cache or fetch from network
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                if (response) {
                    return response; // Return cached response
                }
                return fetch(event.request)
                    .then(networkResponse => {
                        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
                            return networkResponse;
                        }
                        // Clone response for caching
                        const responseToCache = networkResponse.clone();
                        caches.open(CACHE_NAME)
                            .then(cache => {
                                cache.put(event.request, responseToCache);
                            });
                        return networkResponse;
                    })
                    .catch(error => {
                        console.error('Fetch failed:', error);
                        return caches.match('/templates/users/offline.html') || new Response('Offline', { status: 503 });
                    });
            })
    );
});
