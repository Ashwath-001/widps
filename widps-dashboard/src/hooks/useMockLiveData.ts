import { useState, useEffect } from 'react';
import type { AccessPoint, AlertItem, LiveFeedItem, SystemStatus, TrafficPoint } from '../types';
import {
  alerts as initialAlerts,
  liveFeed as initialLiveFeed,
  systemStatus as initialSystemStatus,
  generateTrafficHistory,
} from '../data/mockData';

function getApiBase(): string {
  if (typeof window !== 'undefined' && window.location && window.location.hostname) {
    return `http://${window.location.hostname}:8787`;
  }
  return 'http://localhost:8787';
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
      try {
        const apiBase = getApiBase();
        const res = await fetch(`${apiBase}/api/networks`);
        if (!res.ok) return;
        const data: AccessPoint[] = await res.json();
        if (!cancelled && Array.isArray(data)) {
          setNetworks(data);
        }
      } catch (err) {
        // Backend starting or offline
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
      try {
        const apiBase = getApiBase();
        const res = await fetch(`${apiBase}/api/alerts`);
        if (!res.ok) return;
        const raw: RawAlert[] = await res.json();
        if (cancelled) return;

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
      } catch {
        // Keep alerts state
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
      try {
        const apiBase = getApiBase();
        const res = await fetch(`${apiBase}/api/status`);
        if (!res.ok) return;
        const data: SystemStatus = await res.json();
        if (!cancelled) setStatus(data);
      } catch {
        // Backend offline
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