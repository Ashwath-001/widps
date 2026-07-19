import type { AlertItem } from '../types';

const API_BASE = 'http://localhost:8787';

interface RawAlert {
  time: string;
  severity: string;
  title: string;
  detail: string;
}

export function useLiveAlerts(pollMs = 2000) {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts`);
        const raw: RawAlert[] = await res.json();
        if (cancelled) return;
        setAlerts(
          raw
            .slice()
            .reverse() // newest first
            .map((a, i) => ({
              id: `${a.time}-${i}`,
              severity: (a.severity as AlertItem['severity']) ?? 'Medium',
              title: a.title,
              detail: a.detail,
              time: a.time,
              read: false,
            }))
        );
      } catch {
        // backend not running yet — keep last known alerts, don't crash the UI
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