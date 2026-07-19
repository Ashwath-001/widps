import { useState, useEffect } from 'react';
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
      // try next URL candidate
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

export function useScannedNetworks(pollMs = 1000): AccessPoint[] {
  const [networks, setNetworks] = useState<AccessPoint[]>([]);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      const apiNetworks = await fetchApiEndpoint<AccessPoint[]>('/api/networks');
      const rawAlerts = await fetchApiEndpoint<RawAlert[]>('/api/alerts');

      if (cancelled) return;

      const apMap = new Map<string, AccessPoint>();

      // 1. Populate from /api/networks if available
      if (Array.isArray(apiNetworks)) {
        for (const ap of apiNetworks) {
          if (ap && ap.bssid) {
            apMap.set(ap.bssid.toUpperCase(), ap);
          }
        }
      }

      // 2. Extract and parse any networks mentioned in alerts
      if (Array.isArray(rawAlerts)) {
        for (const a of rawAlerts) {
          if (!a.detail) continue;
          const segments = a.detail.split(/\n|(?=SSID:)/);
          for (const seg of segments) {
            const bssidMatch = seg.match(/BSSID:\s*([0-9A-Fa-f:]{17})/i);
            if (!bssidMatch) continue;

            const bssid = bssidMatch[1].toUpperCase();
            const existing = apMap.get(bssid);

            const ssidMatch = seg.match(/SSID:\s*([^|\n]+)/i);
            const ssid = ssidMatch ? ssidMatch[1].trim() : '<hidden>';

            const chMatch = seg.match(/CH:\s*(\d+)/i);
            const channel = chMatch ? parseInt(chMatch[1], 10) : 1;

            const rssiMatch = seg.match(/RSSI:\s*(-?\d+)/i);
            const rssi = rssiMatch ? parseInt(rssiMatch[1], 10) : -70;

            const vendorMatch = seg.match(/Vendor:\s*([^|\n]+)/i);
            const vendor = vendorMatch ? vendorMatch[1].trim() : 'Unknown';

            const secMatch = seg.match(/Sec:\s*([^|\n]+)/i);
            const encryption = secMatch ? secMatch[1].trim() : 'WPA2';

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
      }

      const merged = Array.from(apMap.values());
      if (merged.length > 0) {
        setNetworks(merged);
      }
    };

    poll();
    const id = setInterval(poll, pollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [pollMs]);

  return networks;
}

export function useLiveAlerts(pollMs = 1500): AlertItem[] {
  const [alerts, setAlerts] = useState<AlertItem[]>(initialAlerts);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      const raw = await fetchApiEndpoint<RawAlert[]>('/api/alerts');
      if (!cancelled && Array.isArray(raw) && raw.length > 0) {
        setAlerts(
          raw
            .slice()
            .reverse() // newest first
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
    };

    poll();
    const id = setInterval(poll, pollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [pollMs]);

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

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      const data = await fetchApiEndpoint<SystemStatus>('/api/status');
      if (!cancelled && data) {
        setStatus(data);
      }
    };

    poll();
    const id = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return status;
}

export function useTrafficHistory(): TrafficPoint[] {
  const [traffic, setTraffic] = useState<TrafficPoint[]>(() => generateTrafficHistory(30));

  useEffect(() => {
    const id = setInterval(() => {
      setTraffic(generateTrafficHistory(30));
    }, 2000);

    return () => clearInterval(id);
  }, []);

  return traffic;
}