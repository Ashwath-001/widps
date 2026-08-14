// WIDPS Service Worker — Background Push Notifications
// =====================================================
// This service worker enables notifications even when the dashboard tab
// is closed or the browser is in the background.
//
// It listens for 'push' events (from Web Push API) and 'message' events
// (from the main thread when SSE receives a critical alert).

const CACHE_NAME = 'widps-v1';

// Install: cache critical assets for offline shell
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});

// Listen for messages from the main thread (SSE alert forwarding)
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'CRITICAL_ALERT') {
    const { title, body, tag } = event.data;
    self.registration.showNotification(title, {
      body,
      icon: '/favicon.svg',
      badge: '/favicon.svg',
      tag: tag || 'widps-alert',
      vibrate: [200, 100, 200],
      requireInteraction: true,
      actions: [
        { action: 'view', title: 'View Dashboard' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
    });
  }
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  // Open or focus the dashboard
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(self.location.origin)) {
          return client.focus();
        }
      }
      return clients.openWindow('/');
    })
  );
});

// Web Push event (for future server-push implementation)
self.addEventListener('push', (event) => {
  if (!event.data) return;

  try {
    const data = event.data.json();
    event.waitUntil(
      self.registration.showNotification(data.title || 'WIDPS Alert', {
        body: data.body || 'New security alert detected',
        icon: '/favicon.svg',
        badge: '/favicon.svg',
        tag: 'widps-push',
        vibrate: [200, 100, 200],
        requireInteraction: data.severity === 'Critical',
      })
    );
  } catch (e) {
    // Fallback for plain text push
    event.waitUntil(
      self.registration.showNotification('WIDPS Alert', {
        body: event.data.text(),
        icon: '/favicon.svg',
      })
    );
  }
});
