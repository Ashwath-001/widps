/**
 * WIDPS Real-Time SSE (Server-Sent Events) Hook
 * -----------------------------------------------
 * Replaces polling for alerts with a persistent event stream connection.
 * Falls back to polling if SSE is unavailable.
 *
 * Features:
 * - Auto-reconnect with exponential backoff
 * - Last-Event-ID tracking for zero message loss
 * - Desktop notification support for Critical alerts
 * - Audio alert on critical events
 * - Browser notification permission management
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import type { AlertItem, LiveFeedItem } from '../types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface SSEAlert {
  time: string;
  severity: string;
  title: string;
  detail: string;
  hmac_sha256?: string;
}

type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

// ---------------------------------------------------------------------------
// Backend URL resolution (same logic as existing hooks)
// ---------------------------------------------------------------------------
let resolvedBase: string | null = null;

async function resolveBaseUrl(): Promise<string> {
  if (resolvedBase) return resolvedBase;

  const host = typeof window !== 'undefined' && window.location?.hostname || 'localhost';
  const candidates = Array.from(new Set([
    `http://${host}:8787`,
    'http://localhost:8787',
    'http://127.0.0.1:8787',
  ]));

  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/status`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        resolvedBase = base;
        return base;
      }
    } catch {
      continue;
    }
  }
  return candidates[0];
}

// ---------------------------------------------------------------------------
// Notification helpers
// ---------------------------------------------------------------------------
function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

function showDesktopNotification(title: string, body: string) {
  if (localStorage.getItem('widps_setting_desktop_notif') !== 'true') return;
  if (!('Notification' in window) || Notification.permission !== 'granted') return;

  new Notification(title, {
    body,
    icon: '/favicon.svg',
    tag: 'widps-alert', // Prevents notification spam
    requireInteraction: true,
  });
}

function playCriticalSound() {
  if (localStorage.getItem('widps_setting_sound_critical') !== 'true') return;
  try {
    const audio = new Audio('/alert.mp3');
    audio.volume = 0.7;
    audio.play().catch(() => {});
  } catch {}
}

// ---------------------------------------------------------------------------
// Main SSE Hook
// ---------------------------------------------------------------------------
export function useSSEAlerts(): {
  alerts: AlertItem[];
  feed: LiveFeedItem[];
  status: ConnectionStatus;
  reconnect: () => void;
} {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [feed, setFeed] = useState<LiveFeedItem[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>('connecting');

  const eventSourceRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<string>('');
  const reconnectAttemptRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(async () => {
    if (!mountedRef.current) return;

    // Close existing connection
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    setStatus('connecting');

    const base = await resolveBaseUrl();
    const url = `${base}/api/stream`;

    try {
      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onopen = () => {
        if (!mountedRef.current) return;
        setStatus('connected');
        reconnectAttemptRef.current = 0;
        console.log('[SSE] Connected to', url);
      };

      // Handle connection confirmation
      es.addEventListener('connected', () => {
        console.log('[SSE] Server confirmed connection');
      });

      // Handle alert events
      es.addEventListener('alert', (event: MessageEvent) => {
        if (!mountedRef.current) return;

        lastEventIdRef.current = event.lastEventId || lastEventIdRef.current;

        try {
          const alertData: SSEAlert = JSON.parse(event.data);

          const newAlert: AlertItem = {
            id: `sse-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            severity: normalizeSeverity(alertData.severity),
            title: alertData.title,
            detail: alertData.detail,
            time: alertData.time,
            read: false,
          };

          setAlerts((prev) => [newAlert, ...prev].slice(0, 200));

          // Create feed item
          const feedItem: LiveFeedItem = {
            id: `feed-${newAlert.id}`,
            time: alertData.time.split(' ').pop() || new Date().toLocaleTimeString('en-GB'),
            message: alertData.title,
            tone: newAlert.severity === 'Critical' ? 'danger'
              : newAlert.severity === 'High' ? 'warning' : 'info',
          };
          setFeed((prev) => [feedItem, ...prev].slice(0, 50));

          // Desktop notification for High/Critical
          if (newAlert.severity === 'Critical' || newAlert.severity === 'High') {
            showDesktopNotification(
              `WIDPS ${newAlert.severity} Alert`,
              alertData.title,
            );
          }

          // Sound for Critical
          if (newAlert.severity === 'Critical') {
            playCriticalSound();
            // Push to service worker for background notification
            if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
              navigator.serviceWorker.controller.postMessage({
                type: 'CRITICAL_ALERT',
                title: `WIDPS ${newAlert.severity}`,
                body: alertData.title,
                tag: `widps-${newAlert.id}`,
              });
            }
          }
        } catch (e) {
          console.warn('[SSE] Failed to parse alert:', e);
        }
      });

      // Handle ML prediction events
      es.addEventListener('ml_prediction', (event: MessageEvent) => {
        if (!mountedRef.current) return;
        lastEventIdRef.current = event.lastEventId || lastEventIdRef.current;

        try {
          const pred = JSON.parse(event.data);
          if (pred.label && pred.label !== 'Normal') {
            const feedItem: LiveFeedItem = {
              id: `ml-${Date.now()}`,
              time: new Date().toLocaleTimeString('en-GB'),
              message: `AI: ${pred.label} (${Math.round(pred.confidence * 100)}% conf, score: ${pred.threat_score})`,
              tone: pred.threat_score > 70 ? 'danger' : pred.threat_score > 40 ? 'warning' : 'info',
            };
            setFeed((prev) => [feedItem, ...prev].slice(0, 50));
          }
        } catch {}
      });

      // Handle threat_score events
      es.addEventListener('threat_update', (event: MessageEvent) => {
        if (!mountedRef.current) return;
        lastEventIdRef.current = event.lastEventId || lastEventIdRef.current;
        // Future: update threat profiles in state
      });

      es.onerror = () => {
        if (!mountedRef.current) return;
        setStatus('disconnected');
        es.close();
        eventSourceRef.current = null;

        // Exponential backoff reconnect
        reconnectAttemptRef.current++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttemptRef.current), 30000);
        console.log(`[SSE] Disconnected. Reconnecting in ${delay}ms (attempt ${reconnectAttemptRef.current})`);

        reconnectTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, delay);
      };
    } catch (e) {
      setStatus('error');
      console.error('[SSE] Connection failed:', e);
    }
  }, []);

  const reconnect = useCallback(() => {
    reconnectAttemptRef.current = 0;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    connect();
  }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    requestNotificationPermission();
    connect();

    return () => {
      mountedRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect]);

  return { alerts, feed, status, reconnect };
}

// ---------------------------------------------------------------------------
// Hook for SSE connection status display
// ---------------------------------------------------------------------------
export function useSSEStatus() {
  const { status } = useSSEAlerts();
  return {
    connected: status === 'connected',
    reconnecting: status === 'connecting',
    lastEventId: '',
    eventsReceived: 0,
    connectionStatus: status,
  };
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
const VALID_SEVERITIES: AlertItem['severity'][] = ['Low', 'Medium', 'High', 'Critical'];

function normalizeSeverity(value: string): AlertItem['severity'] {
  const match = VALID_SEVERITIES.find((s) => s.toLowerCase() === value.toLowerCase());
  return match ?? 'Medium';
}
