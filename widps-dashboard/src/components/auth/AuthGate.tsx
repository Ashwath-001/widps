import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { ShieldCheck, LogIn } from 'lucide-react';
import { fetchSession, login, trackActivity, type SessionInfo, type UnauthorizedReason } from '../../lib/session';
import { SessionContext } from './SessionContext';

const REASON_TEXT: Record<string, string> = {
  expired: 'Your session expired. Sign in again.',
  anomaly: 'Your session was used from a different browser or network and was ended. Sign in again.',
  invalid: 'Your session is no longer valid. Sign in again.',
};

/** Shows the sign-in screen until a valid session exists, and again whenever the API returns 401. */
export default function AuthGate({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [notice, setNotice] = useState('');

  useEffect(() => {
    fetchSession()
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setChecking(false));
    const onUnauthorized = (e: Event) => {
      const reason = (e as CustomEvent<UnauthorizedReason>).detail;
      setSession(null);
      setNotice(REASON_TEXT[reason] ?? '');
    };
    window.addEventListener('widps:unauthorized', onUnauthorized);
    return () => window.removeEventListener('widps:unauthorized', onUnauthorized);
  }, []);

  useEffect(() => (session ? trackActivity() : undefined), [session]);

  if (checking) {
    return <div className="min-h-screen bg-[var(--color-bg)]" aria-busy="true" />;
  }
  if (!session) {
    return <LoginScreen notice={notice} onSignedIn={(s) => { setNotice(''); setSession(s); }} />;
  }
  return <SessionContext.Provider value={{ session, onSignedOut: () => setSession(null) }}>{children}</SessionContext.Provider>;
}

function LoginScreen({ notice, onSignedIn }: { notice: string; onSignedIn: (s: SessionInfo) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    const res = await login(username.trim(), password).catch(() => ({ ok: false as const, error: 'Sensor unreachable.' }));
    setBusy(false);
    setPassword('');
    if (res.ok) onSignedIn(res.session);
    else setError(res.error);
  };

  return (
    <div className="min-h-screen bg-[var(--color-bg)] ops-grid-bg flex items-center justify-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-elevated)] p-6 space-y-4" aria-labelledby="login-title">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[var(--color-accent-blue)]/10 flex items-center justify-center">
            <ShieldCheck size={20} className="text-[var(--color-accent-blue)]" />
          </div>
          <div>
            <h1 id="login-title" className="text-base font-semibold">WIDPS console</h1>
            <p className="text-xs text-[var(--color-text-muted)]">Sign in to the sensor</p>
          </div>
        </div>
        {notice && <p role="status" className="text-xs rounded-md border border-yellow-500/30 bg-yellow-500/10 text-yellow-300 px-3 py-2">{notice}</p>}
        <label className="block text-xs space-y-1">
          <span className="text-[var(--color-text-secondary)]">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
            maxLength={32}
            className="w-full h-9 px-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-accent-blue)]"
          />
        </label>
        <label className="block text-xs space-y-1">
          <span className="text-[var(--color-text-secondary)]">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="w-full h-9 px-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-accent-blue)]"
          />
        </label>
        {error && <p role="alert" className="text-xs text-[var(--color-accent-danger)]">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full h-9 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-60"
        >
          <LogIn size={15} /> {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="text-[10px] text-[var(--color-text-muted)]">Sessions end after 15 minutes of inactivity or 8 hours in total.</p>
      </form>
    </div>
  );
}
