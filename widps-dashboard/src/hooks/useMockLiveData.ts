import { useEffect, useState } from 'react';
import { systemStatus as initialStatus, liveFeed as initialFeed, generateTrafficHistory } from '../data/mockData';
import type { LiveFeedItem, SystemStatus, TrafficPoint } from '../types';

/**
 * -------------------------------------------------------------------------
 * LIVE DATA SEAM
 * -------------------------------------------------------------------------
 * Everything in this hook is mocked with setInterval so the UI has
 * something believable to animate against during development/demo.
 *
 * To wire this to the real Rust backend later, replace the intervals below
 * with Tauri event listeners, e.g.:
 *
 *   import { listen } from '@tauri-apps/api/event';
 *
 *   useEffect(() => {
 *     const unlisten = listen<SystemStatus>('system-status', (event) => {
 *       setStatus(event.payload);
 *     });
 *     return () => { unlisten.then((f) => f()); };
 *   }, []);
 *
 * Or, if bridging over a WebSocket from the Rust WIDPS process instead of
 * Tauri's IPC, swap the interval for a `ws.onmessage` handler that parses
 * the same JSON shape and calls the same setState functions. Because every
 * page reads from these typed hooks (not from mockData directly), no page
 * component needs to change when the real data source is connected.
 * -------------------------------------------------------------------------
 */
export function useSystemStatus(): SystemStatus {
  const [status, setStatus] = useState<SystemStatus>(initialStatus);

  useEffect(() => {
    const id = setInterval(() => {
      setStatus((prev) => ({
        ...prev,
        packetsPerSecond: Math.max(0, prev.packetsPerSecond + Math.round((Math.random() - 0.5) * 120)),
        cpuUsagePct: Math.min(100, Math.max(10, prev.cpuUsagePct + Math.round((Math.random() - 0.5) * 6))),
        memoryUsagePct: Math.min(100, Math.max(10, prev.memoryUsagePct + Math.round((Math.random() - 0.5) * 4))),
        piTemperatureC: Math.min(85, Math.max(40, prev.piTemperatureC + Math.round((Math.random() - 0.5) * 2))),
      }));
    }, 2000);
    return () => clearInterval(id);
  }, []);

  return status;
}

export function useTrafficHistory(): TrafficPoint[] {
  const [history, setHistory] = useState<TrafficPoint[]>(() => generateTrafficHistory());

  useEffect(() => {
    const id = setInterval(() => {
      setHistory((prev) => {
        const next = generateTrafficHistory(1)[0];
        return [...prev.slice(1), next];
      });
    }, 1000);
    return () => clearInterval(id);
  }, []);

  return history;
}

export function useLiveFeed(maxItems = 12): LiveFeedItem[] {
  const [feed, setFeed] = useState<LiveFeedItem[]>(initialFeed);

  useEffect(() => {
    const messages: Array<[string, LiveFeedItem['tone']]> = [
      ['Beacon scan cycle complete', 'info'],
      ['Probe request burst on channel 6', 'info'],
      ['AI inference completed in 4.1ms', 'info'],
      ['Client roaming event observed', 'info'],
      ['Signal strength anomaly flagged', 'warning'],
      ['Deauthentication frame observed', 'danger'],
      ['Mitigation action completed', 'success'],
    ];

    const id = setInterval(() => {
      const [message, tone] = messages[Math.floor(Math.random() * messages.length)];
      setFeed((prev) => [
        { id: `lf-${Date.now()}`, time: new Date().toLocaleTimeString('en-GB'), message, tone },
        ...prev,
      ].slice(0, maxItems));
    }, 4000);

    return () => clearInterval(id);
  }, [maxItems]);

  return feed;
}
