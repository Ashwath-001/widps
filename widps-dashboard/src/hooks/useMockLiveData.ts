import { useState, useEffect, useRef } from 'react';
import type { AccessPoint, AlertItem, LiveFeedItem, SystemStatus, TrafficPoint } from '../types';
import {
  alerts as initialAlerts,
  liveFeed as initialLiveFeed,
  systemStatus as initialSystemStatus,
  generateTrafficHistory,
} from '../data/mockData';

async function fetchApiEndpoint<T>(endpoint: string): Promise<T | null> {
  const host = typeof window !== 'undefined' && window.location && window.location.hostname
    ? window.location.hostname
    : 'localhost';

  const candidates = Array.from(new Set([
    `http://${host}:8787`,
    'http://localhost:8787',
    'http://127.0.0.1:8787',
  ]));

  for (const base of candidates) {
    try {
      const res = await fetch(`${base}${endpoint}`);
      if (res.ok) {
        const json = await res.json();
        return json;
      }
    } catch {
      // try next candidate
    }
  }
  return null;
}

interface RawAlert {
  time: string;
  severity: string;
  title: string;
  detail: string;
}

const VALID_SEVERITIES: AlertItem['severity'][] = ['Low', 'Medium', 'High', 'Critical'];

function normalizeSeverity(value: string): AlertItem['severity'] {
  const match = VALID_SEVERITIES.find((s) => s.toLowerCase() === value.toLowerCase());
  return match ?? 'Medium';
}

// RC-7 FIX: Sequential polling hook. Instead of setInterval (which can overlap
// if a response is slow), this schedules the NEXT poll only AFTER the current
// one completes. Prevents multiple in-flight requests racing to set state.
function useSequentialPoll<T>(
  fetcher: () => Promise<T | null>,
  onData: (data: T) => void,
  intervalMs: number,
) {
  const cancelledRef = useRef(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    cancelledRef.current = false;

    const poll = async () => {
      const data = await fetcher();
      if (cancelledRef.current) return;
      if (data !== null) {
        onData(data);
      }
      if (!cancelledRef.current) {
        timeoutRef.current = setTimeout(poll, intervalMs);
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

export function useScannedNetworks(pollMs = 1000): AccessPoint[] {
  const [networks, setNetworks] = useState<AccessPoint[]>([]);

  useSequentialPoll(
    async () => {
      const apiNetworks = await fetchApiEndpoint<AccessPoint[]>('/api/networks');
      const rawAlerts = await fetchApiEndpoint<RawAlert[]>('/api/alerts');
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

export function useLiveAlerts(pollMs = 1500): AlertItem[] {
  const [alerts, setAlerts] = useState<AlertItem[]>(initialAlerts);

  useSequentialPoll(
    () => fetchApiEndpoint<RawAlert[]>('/api/alerts'),
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
  const [feed, setFeed] = useState<LiveFeedItem[]>(initialLiveFeed);

  useEffect(() => {
    const interval = setInterval(() => {
      setFeed((prev) => {
        const nowStr = new Date().toLocaleTimeString('en-GB');
        const newItem: LiveFeedItem = {
          id: `lf-${Date.now()}`,
          time: nowStr,
          message: 'Captured beacon & probe frames on wlan1mon (channel hopper active)',
          tone: 'info',
        };
        return [newItem, ...prev.slice(0, 14)];
      });
    }, 8000);

    return () => clearInterval(interval);
  }, []);

  return feed;
}

export function useSystemStatus(): SystemStatus {
  const [status, setStatus] = useState<SystemStatus>(initialSystemStatus);

  useSequentialPoll(
    () => fetchApiEndpoint<SystemStatus>('/api/status'),
    (data) => setStatus(data),
    2000,
  );

  return status;
}

export function useTrafficHistory(): TrafficPoint[] {
  const [traffic, setTraffic] = useState<TrafficPoint[]>(() => generateTrafficHistory(30));

  useSequentialPoll(
    () => fetchApiEndpoint<any[]>('/api/traffic'),
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
    1000,
  );

  return traffic;
}
