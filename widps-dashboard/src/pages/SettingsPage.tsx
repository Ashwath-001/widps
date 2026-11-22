import { useState, useEffect } from 'react';
import Card from '../components/common/Card';
import QRScanner from '../components/common/QRScanner';
import { useToastContext } from '../hooks/ToastContext';
import { useSession } from '../components/auth/SessionContext';

function getSetting(id: string, defaultValue: boolean): boolean {
  const saved = localStorage.getItem(`widps_setting_${id}`);
  return saved !== null ? saved === 'true' : defaultValue;
}

function ToggleRow({
  id,
  label,
  description,
  defaultChecked = false,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  defaultChecked?: boolean;
  onChange?: (checked: boolean) => void;
}) {
  const [checked, setChecked] = useState<boolean>(() => getSetting(id, defaultChecked));

  const toggle = () => {
    const next = !checked;
    setChecked(next);
    localStorage.setItem(`widps_setting_${id}`, String(next));
    onChange?.(next);
  };

  return (
    <div
      onClick={toggle}
      className="flex items-center justify-between py-3.5 border-b border-[var(--color-border-soft)] last:border-0 cursor-pointer group select-none hover:bg-white/[0.01] px-1 rounded-md transition-colors"
    >
      <div className="pr-6">
        <p className="text-sm font-medium text-[var(--color-text)]">{label}</p>
        <p className="text-xs text-[var(--color-text-muted)] mt-0.5 leading-relaxed">{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={(e) => {
          e.stopPropagation();
          toggle();
        }}
        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-[var(--color-accent-blue)] ${
          checked ? 'bg-[var(--color-accent-green)]' : 'bg-[var(--color-border)]'
        }`}
      >
        <span
          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
            checked ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </button>
    </div>
  );
}

interface SensorConfig {
  channel_hopping: boolean;
  client_tracking: boolean;
  passive_blocking: boolean;
  retention_days: number;
  auto_archive_hours: number;
}

/** A switch whose state lives on the sensor (not in localStorage); shows "unknown" until loaded. */
function SensorToggle({ label, description, value, disabled, onChange }: {
  label: string;
  description: string;
  value: boolean | undefined;
  disabled: boolean;
  onChange: (v: boolean) => void;
}) {
  const unknown = value === undefined;
  return (
    <div className="flex items-center justify-between py-3.5 border-b border-[var(--color-border-soft)] px-1">
      <div className="pr-6">
        <p className="text-sm font-medium text-[var(--color-text)]">{label}</p>
        <p className="text-xs text-[var(--color-text-muted)] mt-0.5 leading-relaxed">{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={unknown ? 'mixed' : value}
        aria-label={label}
        disabled={disabled || unknown}
        onClick={() => !unknown && onChange(!value)}
        className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
          value ? 'bg-[var(--color-accent-green)]' : 'bg-[var(--color-border)]'
        }`}
      >
        <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-md transition ${value ? 'translate-x-5' : 'translate-x-0'}`} />
      </button>
    </div>
  );
}

export default function SettingsPage() {
  const toast = useToastContext();
  const [qrOpen, setQrOpen] = useState(false);
  const { session } = useSession() ?? {};
  const isAdmin = session?.role === 'admin';
  const [cfg, setCfg] = useState<SensorConfig | null>(null);
  const [cfgError, setCfgError] = useState(false);

  useEffect(() => {
    fetch('/api/v1/config')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((c: SensorConfig) => setCfg(c))
      .catch(() => setCfgError(true));
  }, []);

  // Sends only the changed setting; the backend merges it, so other settings keep their values.
  const updateSensor = async (patch: Partial<SensorConfig>, label: string) => {
    try {
      const r = await fetch('/api/v1/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        toast.show(`Not saved: ${body?.error?.message || body?.error || `HTTP ${r.status}`}`, 'error');
        return;
      }
      setCfg(body.config as SensorConfig);
      toast.show(`Saved: ${label}`, 'success');
    } catch {
      toast.show('Sensor unreachable; setting not saved', 'error');
    }
  };

  const handleReducedMotion = (enabled: boolean) => {
    if (enabled) {
      document.documentElement.style.setProperty('--motion-duration', '0s');
    } else {
      document.documentElement.style.removeProperty('--motion-duration');
    }
    toast.show(enabled ? 'Animations disabled' : 'Animations enabled', 'info');
  };

  const handleCompactTables = (enabled: boolean) => {
    if (enabled) {
      document.documentElement.classList.add('compact-tables');
    } else {
      document.documentElement.classList.remove('compact-tables');
    }
    toast.show(enabled ? 'Compact mode enabled' : 'Standard density restored', 'info');
  };

  const handleDesktopNotif = (enabled: boolean) => {
    if (enabled && 'Notification' in window) {
      Notification.requestPermission().then((perm) => {
        if (perm === 'granted') {
          toast.show('Desktop notifications enabled', 'success');
        } else {
          toast.show('Notification permission denied by browser', 'error');
          localStorage.setItem('widps_setting_desktop_notif', 'false');
        }
      });
    } else if (!enabled) {
      toast.show('Desktop notifications disabled', 'info');
    }
  };

  useEffect(() => {
    if (getSetting('reduced_motion', false)) {
      document.documentElement.style.setProperty('--motion-duration', '0s');
    }
    if (getSetting('compact_tables', false)) {
      document.documentElement.classList.add('compact-tables');
    }
  }, []);

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Configure monitoring behavior, alerting, and display preferences.</p>
      </div>

      <Card className="p-5" delay={0.03}>
        <h3 className="text-sm font-semibold mb-1 text-[var(--color-accent-blue)]">Sensor</h3>
        <p className="text-[10px] text-[var(--color-text-muted)] mb-2">
          Stored on the sensor and applied immediately.{!isAdmin && ' Read-only: your role is viewer.'}
          {cfgError && ' Could not load the current settings.'}
        </p>
        <SensorToggle label="Channel hopping" description="Cycle through channels 1–11 every 300 ms on the monitor interface"
          value={cfg?.channel_hopping} disabled={!isAdmin} onChange={(v) => updateSensor({ channel_hopping: v }, 'channel hopping')} />
        <SensorToggle label="Client association tracking" description="Record probe requests, association hints and deauth victims per client MAC"
          value={cfg?.client_tracking} disabled={!isAdmin} onChange={(v) => updateSensor({ client_tracking: v }, 'client tracking')} />
        <SensorToggle label="Passive blocking (blacklist)" description="Raise a Critical alert when a blacklisted MAC transmits again (once per 5 minutes per device)"
          value={cfg?.passive_blocking} disabled={!isAdmin} onChange={(v) => updateSensor({ passive_blocking: v }, 'passive blocking')} />
        <SensorToggle label="Auto-mark old alerts as read" description="Alerts older than 24 hours are marked as acknowledged"
          value={cfg ? cfg.auto_archive_hours > 0 : undefined} disabled={!isAdmin} onChange={(v) => updateSensor({ auto_archive_hours: v ? 24 : 0 }, 'auto-mark as read')} />
        <div className="flex items-center justify-between py-3.5 px-1">
          <div className="pr-6">
            <p className="text-sm font-medium text-[var(--color-text)]">Data retention</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">Delete alerts and ML predictions older than this. Pruning runs every 5 minutes and is recorded in the audit log.</p>
          </div>
          <select
            aria-label="Data retention"
            value={cfg?.retention_days ?? ''}
            disabled={!isAdmin || !cfg}
            onChange={(e) => updateSensor({ retention_days: Number(e.target.value) }, 'data retention')}
            className="h-8 px-2 rounded-lg text-xs bg-[var(--color-bg)] border border-[var(--color-border)] disabled:opacity-50"
          >
            {cfg && ![0, 7, 30, 90].includes(cfg.retention_days) && <option value={cfg.retention_days}>{cfg.retention_days} days</option>}
            <option value={0}>Keep everything</option>
            <option value={90}>90 days</option>
            <option value={30}>30 days</option>
            <option value={7}>7 days</option>
          </select>
        </div>
        <p className="text-[10px] text-[var(--color-text-muted)] pt-2 border-t border-[var(--color-border-soft)]">
          The sensor is passive: it never transmits probe, deauthentication or other frames. Active containment is not implemented.
        </p>
      </Card>

      <Card className="p-5" delay={0.06}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Alerting</h3>
        <ToggleRow id="desktop_notif" label="Desktop notifications" description="Show a browser notification on new critical alerts" defaultChecked onChange={handleDesktopNotif} />
        <ToggleRow id="sound_critical" label="Audio alarm on critical threats" description="Play an alert tone when Critical severity events are detected" />
      </Card>


      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Display</h3>
        <ToggleRow id="reduced_motion" label="Reduced motion" description="Disable page transitions and card animations" onChange={handleReducedMotion} />
        <ToggleRow id="compact_tables" label="High-density tables" description="Tighter row spacing in Network and Event Log tables" onChange={handleCompactTables} />
      </Card>


      <Card className="p-5" delay={0.15}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">AP Trust Enrollment</h3>
        <p className="text-xs text-[var(--color-text-muted)] mb-3">
          Add trusted access points via QR code scan or manual entry. Trusted APs are excluded from rogue AP detection.
        </p>
        <button
          onClick={() => setQrOpen(true)}
          className="px-4 py-2 rounded-lg bg-[var(--color-accent-blue)] text-white text-xs font-medium hover:opacity-90 transition-opacity"
        >
          Scan QR Code / Add AP
        </button>
      </Card>

      <Card className="p-5" delay={0.17}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-text-muted)]">About</h3>
        <div className="text-xs text-[var(--color-text-muted)] space-y-1">
          <p><span className="text-[var(--color-text)]">WIDPS</span> - Wireless Intrusion Detection & Prevention System</p>
          <p>Version 1.0.0 | Backend: Rust | ML: Random Forest on management-frame windows (results on the AI page)</p>
          <p>7 rule detectors | composite threat scoring | hash-chained audit log | SQLite persistence</p>
          <p className="mt-2">Signed in as <span className="text-[var(--color-text)]">{session?.username ?? 'unknown'}</span> ({session?.role ?? 'unknown'})</p>
        </div>
      </Card>

      {qrOpen && (
        <QRScanner
          onSuccess={(ssid, bssid) => {
            fetch('/api/whitelist', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ssid, bssid }),
            })
              .then((r) => r.json())
              .then((data) => {
                if (data.status === 'added') {
                  toast.show(`Trusted AP added: ${ssid} (${bssid})`, 'success');
                } else if (data.status === 'already_trusted') {
                  toast.show('AP is already in the whitelist', 'info');
                }
              })
              .catch(() => toast.show('Failed to add AP', 'error'));
            setQrOpen(false);
          }}
          onClose={() => setQrOpen(false)}
        />
      )}
    </div>
  );
}
