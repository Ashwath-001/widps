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
      const data = await fetchApiEndpoint<AccessPoint[]>('/api/networks');
      if (!cancelled && Array.isArray(data) && data.length > 0) {
        setNetworks(data);
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