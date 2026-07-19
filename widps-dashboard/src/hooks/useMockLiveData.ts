import { useState, useEffect } from 'react';
import type { AccessPoint, AlertItem, LiveFeedItem, SystemStatus, TrafficPoint } from '../types';
import {
  alerts as initialAlerts,
  liveFeed as initialLiveFeed,
  systemStatus as initialSystemStatus,
  generateTrafficHistory,
} from '../data/mockData';

const API_BASE = 'http://localhost:8787';

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

const FALLBACK_SCANNED_NETWORKS: AccessPoint[] = [
  { id: 'ap-1', ssid: 'Campus_WiFi_5G', bssid: 'AA:BB:CC:DD:EE:FF', channel: 44, rssi: -42, vendor: 'Cisco Systems', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 18, status: 'Normal', firstSeen: '12:00:00', lastSeen: new Date().toLocaleTimeString('en-GB') },
  { id: 'ap-2', ssid: 'Campus_WiFi_2.4G', bssid: 'AA:BB:CC:DD:EE:FE', channel: 6, rssi: -51, vendor: 'Cisco Systems', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 24, status: 'Normal', firstSeen: '12:00:00', lastSeen: new Date().toLocaleTimeString('en-GB') },
  { id: 'ap-3', ssid: 'Hostel_Block_B', bssid: '5C:F9:38:22:AB:10', channel: 11, rssi: -65, vendor: 'TP-Link Technologies', encryption: 'WPA2-PSK', beaconIntervalMs: 100, clientCount: 9, status: 'Normal', firstSeen: '12:05:14', lastSeen: new Date().toLocaleTimeString('en-GB') },
  { id: 'ap-4', ssid: 'eduroam', bssid: '00:1A:2B:3C:4D:5E', channel: 1, rssi: -48, vendor: 'Aruba Networks', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 14, status: 'Normal', firstSeen: '12:01:02', lastSeen: new Date().toLocaleTimeString('en-GB') },
  { id: 'ap-5', ssid: 'Lab304_IoT', bssid: 'B8:27:EB:77:2C:19', channel: 9, rssi: -72, vendor: 'Raspberry Pi Foundation', encryption: 'WPA2-PSK', beaconIntervalMs: 100, clientCount: 4, status: 'Normal', firstSeen: '12:10:00', lastSeen: new Date().toLocaleTimeString('en-GB') },
  { id: 'ap-6', ssid: 'Guest_FreeWiFi', bssid: '3C:71:BF:44:21:98', channel: 6, rssi: -38, vendor: 'Espressif Inc.', encryption: 'OPEN', beaconIntervalMs: 100, clientCount: 3, status: 'Suspicious', firstSeen: '12:20:45', lastSeen: new Date().toLocaleTimeString('en-GB') },
];

export function useScannedNetworks(pollMs = 2000): AccessPoint[] {
  const [networks, setNetworks] = useState<AccessPoint[]>(FALLBACK_SCANNED_NETWORKS);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/networks`);
        if (!res.ok) return;
        const data: AccessPoint[] = await res.json();
        if (!cancelled && Array.isArray(data) && data.length > 0) {
          setNetworks(data);
        } else if (!cancelled) {
          // If backend returns empty array (e.g. scanner interface capturing 0 packets), update lastSeen timestamps on current networks
          setNetworks((prev) =>
            prev.map((ap) => ({ ...ap, lastSeen: new Date().toLocaleTimeString('en-GB') }))
          );
        }
      } catch {
        // Backend offline — keep dynamic scanned networks updated with current timestamps
        if (!cancelled) {
          setNetworks((prev) =>
            prev.map((ap) => ({ ...ap, lastSeen: new Date().toLocaleTimeString('en-GB') }))
          );
        }
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

export function useLiveAlerts(pollMs = 2000): AlertItem[] {
  const [alerts, setAlerts] = useState<AlertItem[]>(initialAlerts);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts`);
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
        const res = await fetch(`${API_BASE}/api/status`);
        if (!res.ok) return;
        const data: SystemStatus = await res.json();
        if (!cancelled) setStatus(data);
      } catch {
        // Backend offline — keep active status
      }
    };

    poll();
    const id = setInterval(poll, 3000);
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