// Tracks when the sensor last answered, so the UI can show "offline" or "stale" instead of old data as live.
import { useEffect, useState } from 'react';

export const STALE_AFTER_MS = 12_000;
let lastOk = 0;

export function markBackendOk() {
  lastOk = Date.now();
}

export function useBackendHealth(): { online: boolean; lastOk: number } {
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return { online: lastOk > 0 && Date.now() - lastOk < STALE_AFTER_MS, lastOk };
}
