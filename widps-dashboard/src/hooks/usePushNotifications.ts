/**
 * Push Notifications Hook
 * ========================
 * Registers the service worker and provides a function to send
 * background notifications (even when the tab is not focused).
 *
 * Uses the Service Worker postMessage API for immediate notifications
 * from SSE events. No external push server needed.
 */

import { useEffect, useRef, useCallback, useState } from 'react';

interface PushState {
  supported: boolean;
  permission: NotificationPermission;
  registered: boolean;
}

export function usePushNotifications() {
  const [state, setState] = useState<PushState>({
    supported: false,
    permission: 'default',
    registered: false,
  });
  const swRef = useRef<ServiceWorkerRegistration | null>(null);

  useEffect(() => {
    const supported = 'serviceWorker' in navigator && 'Notification' in window;
    setState((s) => ({ ...s, supported, permission: supported ? Notification.permission : 'denied' }));

    if (!supported) return;

    // Register service worker
    navigator.serviceWorker.register('/sw.js')
      .then((reg) => {
        swRef.current = reg;
        setState((s) => ({ ...s, registered: true }));
      })
      .catch((err) => {
        console.warn('[SW] Registration failed:', err);
      });
  }, []);

  const requestPermission = useCallback(async () => {
    if (!state.supported) return false;

    const result = await Notification.requestPermission();
    setState((s) => ({ ...s, permission: result }));
    return result === 'granted';
  }, [state.supported]);

  const sendNotification = useCallback((title: string, body: string, tag?: string) => {
    // Only send if permission granted and enabled in settings
    if (state.permission !== 'granted') return;
    if (localStorage.getItem('widps_setting_desktop_notif') !== 'true') return;

    // Try via service worker (works in background)
    if (swRef.current?.active) {
      swRef.current.active.postMessage({
        type: 'CRITICAL_ALERT',
        title,
        body,
        tag: tag || `widps-${Date.now()}`,
      });
    } else {
      // Fallback: direct notification (only works when tab is active)
      new Notification(title, {
        body,
        icon: '/favicon.svg',
        tag: tag || 'widps-alert',
      });
    }
  }, [state.permission]);

  return {
    ...state,
    requestPermission,
    sendNotification,
  };
}
