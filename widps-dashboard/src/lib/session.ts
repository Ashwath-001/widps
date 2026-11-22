// Same-origin fetch wrapper: adds the CSRF token, marks polling as background, and reports 401s.
export interface SessionInfo {
  username: string;
  role: 'admin' | 'viewer';
  csrf_token: string;
  idle_expires_at: number;
  absolute_expires_at: number;
}

export type UnauthorizedReason = 'missing' | 'expired' | 'invalid' | 'anomaly' | string;

const nativeFetch = window.fetch.bind(window);
let csrfToken = '';
let installed = false;

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function isSameOriginApi(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    return u.origin === window.location.origin && u.pathname.startsWith('/api/');
  } catch {
    return false;
  }
}

export function setSession(s: SessionInfo | null) {
  csrfToken = s?.csrf_token ?? '';
}

export function installFetchWrapper() {
  if (installed) return;
  installed = true;
  window.fetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = urlOf(input);
    if (!isSameOriginApi(url)) return nativeFetch(input, init);
    const method = (init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
    if (method !== 'GET' && method !== 'HEAD') {
      if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
    } else if (!headers.has('X-WIDPS-Background')) {
      // Automatic polling must not keep an idle session alive; user activity is reported by trackActivity().
      headers.set('X-WIDPS-Background', '1');
    }
    const res = await nativeFetch(input, { ...init, headers, credentials: 'same-origin' });
    if (res.status === 401 && !url.includes('/api/auth/login')) {
      const reason = await res.clone().json().then((b) => b.reason as string).catch(() => 'invalid');
      window.dispatchEvent(new CustomEvent<UnauthorizedReason>('widps:unauthorized', { detail: reason }));
    }
    return res;
  };
}

export async function fetchSession(): Promise<SessionInfo | null> {
  const res = await nativeFetch('/api/auth/session', { credentials: 'same-origin' });
  if (!res.ok) return null;
  const s = (await res.json()) as SessionInfo;
  setSession(s);
  return s;
}

export async function login(username: string, password: string): Promise<{ ok: true; session: SessionInfo } | { ok: false; error: string }> {
  const res = await nativeFetch('/api/auth/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (res.ok) {
    const session = (await res.json()) as SessionInfo;
    setSession(session);
    return { ok: true, session };
  }
  if (res.status === 429) {
    const wait = Number(res.headers.get('Retry-After') || '0');
    return { ok: false, error: `Too many failed attempts. Try again in ${Math.max(1, Math.ceil(wait / 60))} min.` };
  }
  if (res.status === 401) return { ok: false, error: 'Invalid username or password.' };
  return { ok: false, error: 'Sign-in failed. Check that the sensor is reachable over HTTPS.' };
}

export async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  setSession(null);
}

/** Reports real user activity (at most once a minute) so the idle timer only counts inactivity. */
export function trackActivity(): () => void {
  let last = 0;
  const ping = () => {
    const now = Date.now();
    if (now - last < 60_000) return;
    last = now;
    nativeFetch('/api/auth/session', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json().then((s: SessionInfo) => setSession(s)) : undefined))
      .catch(() => {});
  };
  const events = ['pointerdown', 'keydown', 'wheel'] as const;
  events.forEach((e) => window.addEventListener(e, ping, { passive: true }));
  return () => events.forEach((e) => window.removeEventListener(e, ping));
}
