import { useState, useEffect, useRef } from 'react';
import type { AccessPoint, AlertItem, LiveFeedItem, SystemStatus, TrafficPoint } from '../types';
import {
  alerts as initialAlerts,
  systemStatus as initialSystemStatus,
  generateTrafficHistory,
} from '../data/mockData';

const VALID_SEVERITIES: AlertItem['severity'][] = ['Low', 'Medium', 'High', 'Critical'];

function normalizeSeverity(value: string): AlertItem['severity'] {
  const match = VALID_SEVERITIES.find((s) => s.toLowerCase() === value.toLowerCase());
  return match ?? 'Medium';
}

let resolvedBase: string | null = null;
let lastFailTime = 0;
const BACKOFF_MS = 10000;

async function fetchApi<T>(endpoint: string): Promise<T | null> {
  if (Date.now() - lastFailTime < BACKOFF_MS && !resolvedBase) {
    return null;
  }

  if (resolvedBase) {
    try {
      const res = await fetch(`${resolvedBase}${endpoint}`);
      if (res.ok) return res.json();
      resolvedBase = null;
    } catch {
      resolvedBase = null;
      lastFailTime = Date.now();
      return null;
    }
  }

  const host = typeof window !== 'undefined' && window.location?.hostname || 'localhost';
  const candidates = Array.from(new Set([
    `http://${host}:8787`,
    'http://localhost:8787',
    'http://127.0.0.1:8787',
  ]));

  for (const base of candidates) {
    try {
      const res = await fetch(`${base}${endpoint}`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        resolvedBase = base;
        return res.json();
      }
    } catch {
      continue;
    }
  }

  lastFailTime = Date.now();
  return null;
}

interface RawAlert {
  time: string;
  severity: string;
  title: string;
  detail: string;
}

function useSequentialPoll<T>(
  fetcher: () => Promise<T | null>,
  onData: (data: T) => void,
  intervalMs: number,
) {
  const cancelledRef = useRef(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const failCountRef = useRef(0);

  useEffect(() => {
    cancelledRef.current = false;
    failCountRef.current = 0;

    const poll = async () => {
      const data = await fetcher();
      if (cancelledRef.current) return;

      if (data !== null) {
        failCountRef.current = 0;
        onData(data);
      } else {
        failCountRef.current++;
      }

      if (!cancelledRef.current) {
        const backoff = Math.min(intervalMs * Math.pow(1.5, failCountRef.current), 30000);
        const nextDelay = failCountRef.current > 0 ? backoff : intervalMs;
        timeoutRef.current = setTimeout(poll, nextDelay);
      }
    };

    poll();

    return () => {
      cancelledRef.current = true;
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [intervalMs]);
}

export function useScannedNetworks(pollMs = 2000): AccessPoint[] {
  const [networks, setNetworks] = useState<AccessPoint[]>([]);

  useSequentialPoll(
    async () => {
      const apiNetworks = await fetchApi<AccessPoint[]>('/api/networks');
      const rawAlerts = await fetchApi<RawAlert[]>('/api/alerts');
      return { apiNetworks, rawAlerts };
    },
    ({ apiNetworks, rawAlerts }) => {
      const apMap = new Map<string, AccessPoint>();

      if (Array.isArray(apiNetworks)) {
        for (const ap of apiNetworks) {
          if (ap && ap.bssid) {
            apMap.set(ap.bssid.toUpperCase(), ap);
          }
        }
      }

      if (Array.isArray(rawAlerts)) {
        for (const a of rawAlerts) {
          if (!a.detail) continue;

          const macMatches = a.detail.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/g);
          if (!macMatches || macMatches.length === 0) continue;

          const bssid = macMatches[0].toUpperCase();

          const ssidMatch = a.detail.match(/SSID[:\s]+['"]?([^'|\n]+)['"]?/i);
          const ssid = ssidMatch ? ssidMatch[1].trim() : '<hidden>';

          const chMatch = a.detail.match(/CH:\s*(\d+)/i);
          const channel = chMatch ? parseInt(chMatch[1], 10) : 6;

          const rssiMatch = a.detail.match(/RSSI:\s*(-?\d+)/i);
          const rssi = rssiMatch ? parseInt(rssiMatch[1], 10) : -75;

          const vendorMatch = a.detail.match(/Vendor:\s*([^|\n]+)/i);
          const vendor = vendorMatch ? vendorMatch[1].trim() : 'Unknown';

          const secMatch = a.detail.match(/Sec:\s*([^|\n]+)/i);
          const encryption = secMatch ? secMatch[1].trim() : 'WPA2';

          const existing = apMap.get(bssid);
          if (!existing) {
            apMap.set(bssid, {
              id: `ap-${bssid.replace(/:/g, '')}`,
              ssid,
              bssid,
              channel,
              rssi,
              vendor,
              encryption,
              beaconIntervalMs: 100,
              clientCount: 0,
              status: a.severity === 'Critical' ? 'Malicious' : 'Suspicious',
              firstSeen: a.time,
              lastSeen: a.time,
            });
          } else if (existing.ssid === '<hidden>' && ssid !== '<hidden>') {
            existing.ssid = ssid;
          }
        }
      }

      const merged = Array.from(apMap.values());
      if (merged.length > 0) {
        setNetworks(merged);
      }
    },
    pollMs,
  );

  return networks;
}

export function useLiveAlerts(pollMs = 2000): AlertItem[] {
  const [alerts, setAlerts] = useState<AlertItem[]>(initialAlerts);

  useSequentialPoll(
    () => fetchApi<RawAlert[]>('/api/alerts'),
    (raw) => {
      if (Array.isArray(raw) && raw.length > 0) {
        setAlerts(
          raw
            .slice()
            .reverse()
            .map((a, i) => ({
              id: `${a.time}-${i}`,
              severity: normalizeSeverity(a.severity),
              title: a.title,
              detail: a.detail,
              time: a.time,
              read: false,
            }))
        );
      }
    },
    pollMs,
  );

  return alerts;
}

export function useLiveFeed(): LiveFeedItem[] {
  const [feed, setFeed] = useState<LiveFeedItem[]>([]);
  const lastEventIdRef = useRef(0);
  const alerts = useLiveAlerts(3000);
  const prevAlertCountRef = useRef(0);

  useEffect(() => {
    if (alerts.length > prevAlertCountRef.current && prevAlertCountRef.current > 0) {
      const newAlerts = alerts.slice(0, alerts.length - prevAlertCountRef.current);
      const newItems: LiveFeedItem[] = newAlerts.map((a) => ({
        id: `feed-${a.id}`,
        time: a.time,
        message: a.title,
        tone: a.severity === 'Critical' ? 'danger' : a.severity === 'High' ? 'warning' : 'info',
      }));
      setFeed((prev) => [...newItems, ...prev].slice(0, 30));

      const hasCritical = newAlerts.some((a) => a.severity === 'Critical');
      if (hasCritical && localStorage.getItem('widps_setting_sound_critical') === 'true') {
        try { new Audio('/alert.mp3').play(); } catch {}
      }
      if (hasCritical && localStorage.getItem('widps_setting_desktop_notif') === 'true' && 'Notification' in window && Notification.permission === 'granted') {
        new Notification('WIDPS Critical Alert', { body: newAlerts[0].title, icon: '/favicon.svg' });
      }
    }
    prevAlertCountRef.current = alerts.length;
  }, [alerts]);

  useSequentialPoll(
    async () => {
      const events = await fetchApi<any[]>(`/api/events?last_id=${lastEventIdRef.current}`);
      return events;
    },
    (events) => {
      if (!Array.isArray(events) || events.length === 0) return;

      const newItems: LiveFeedItem[] = [];
      for (const evt of events) {
        if (evt.id > lastEventIdRef.current) {
          lastEventIdRef.current = evt.id;
        }

        let message = '';
        let tone: LiveFeedItem['tone'] = 'info';

        if (evt.type === 'alert') {
          try {
            const data = JSON.parse(evt.data);
            message = data.title || 'Alert';
            tone = data.severity === 'Critical' ? 'danger' : data.severity === 'High' ? 'warning' : 'info';
          } catch {
            message = 'New alert';
          }
        } else if (evt.type === 'ml_prediction') {
          try {
            const data = JSON.parse(evt.data);
            message = `AI: ${data.label} (${Math.round(data.confidence * 100)}% conf)`;
            tone = data.threat_score > 70 ? 'danger' : data.threat_score > 40 ? 'warning' : 'info';
          } catch {
            message = 'ML prediction';
          }
        }

        if (message) {
          newItems.push({
            id: `sse-${evt.id}`,
            time: new Date().toLocaleTimeString('en-GB'),
            message,
            tone,
          });
        }
      }

      if (newItems.length > 0) {
        setFeed((prev) => [...newItems, ...prev].slice(0, 30));
      }
    },
    2000,
  );

  useSequentialPoll(
    () => fetchApi<any>('/api/status'),
    (status) => {
      if (status && status.packetsPerSecond > 0) {
        const item: LiveFeedItem = {
          id: `pps-${Date.now()}`,
          time: new Date().toLocaleTimeString('en-GB'),
          message: `${status.packetsPerSecond} pkt/s on Ch ${status.currentChannel} (${status.nearbyApCount} APs)`,
          tone: 'success',
        };
        setFeed((prev) => [item, ...prev.filter((p) => !p.id.startsWith('pps-'))].slice(0, 30));
      }
    },
    8000,
  );

  return feed;
}

export function useSystemStatus(): SystemStatus {
  const [status, setStatus] = useState<SystemStatus>(initialSystemStatus);

  useSequentialPoll(
    () => fetchApi<SystemStatus>('/api/status'),
    (data) => setStatus(data),
    3000,
  );

  return status;
}

export function useTrafficHistory(): TrafficPoint[] {
  const [traffic, setTraffic] = useState<TrafficPoint[]>(() => generateTrafficHistory(30));

  useSequentialPoll(
    () => fetchApi<any[]>('/api/traffic'),
    (data) => {
      if (Array.isArray(data) && data.length > 0) {
        const points: TrafficPoint[] = data.map((d) => ({
          t: d.timestamp || '',
          beacon: d.beacon || 0,
          probeRequest: d.probe_req || 0,
          auth: d.auth || 0,
          assoc: 0,
          disassoc: d.disassoc || 0,
          deauth: d.deauth || 0,
          packetRate: d.total_pps || 0,
        }));
        setTraffic(points);
      }
    },
    2000,
  );

  return traffic;
}
