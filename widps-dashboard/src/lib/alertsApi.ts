// Client for the /api/v1 alert endpoints; alert ids are the database ids, so they survive reloads.
export interface AlertV1 {
  id: number;
  ts: string;
  time: string;
  severity: string;
  title: string;
  detail: string;
  detector: string;
  bssid: string | null;
  acknowledged: boolean;
  ack_by: string | null;
  ack_at: string | null;
  verdict: 'true_positive' | 'false_positive' | 'benign' | null;
  verdict_label: string | null;
  verdict_by: string | null;
  verdict_at: string | null;
  archived: boolean;
  record_hash: string | null;
}

export type Verdict = 'true_positive' | 'false_positive' | 'benign';
export type ApiResult = { ok: true } | { ok: false; error: string };

async function post(path: string, body?: unknown): Promise<ApiResult> {
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.ok) return { ok: true };
    const err = await res.json().catch(() => ({}));
    return { ok: false, error: err?.error?.message || `HTTP ${res.status}` };
  } catch {
    return { ok: false, error: 'sensor unreachable' };
  }
}

export async function fetchAlerts(limit = 200): Promise<AlertV1[] | null> {
  try {
    const res = await fetch(`/api/v1/alerts?limit=${limit}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const body = await res.json();
    return Array.isArray(body?.items) ? (body.items as AlertV1[]) : null;
  } catch {
    return null;
  }
}

export const ackAlert = (id: number) => post(`/api/v1/alerts/${id}/ack`);
export const setVerdict = (id: number, verdict: Verdict, label?: string) =>
  post(`/api/v1/alerts/${id}/verdict`, label ? { verdict, label } : { verdict });
export const archiveAllAlerts = () => post('/api/v1/alerts/archive', { confirm: 'CLEAR' });
