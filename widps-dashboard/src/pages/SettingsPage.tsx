import { useState, useEffect } from 'react';
import Card from '../components/common/Card';
import { useToastContext } from '../hooks/ToastContext';

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

export default function SettingsPage() {
  const toast = useToastContext();
  const [backendOnline, setBackendOnline] = useState(false);

  useEffect(() => {
    const host = window.location.hostname || 'localhost';
    fetch(`http://${host}:8787/api/config`)
      .then((r) => { if (r.ok) { setBackendOnline(true); return r.json(); } return null; })
      .then((cfg) => {
        if (cfg) {
          localStorage.setItem('widps_setting_channel_hopping', String(cfg.channel_hopping));
          localStorage.setItem('widps_setting_client_tracking', String(cfg.client_tracking));
        }
      })
      .catch(() => {});
  }, []);

  const syncToBackend = (id: string, checked: boolean) => {
    const mapping: Record<string, string> = {
      channel_hopping: 'channel_hopping',
      client_tracking: 'client_tracking',
      passive_scan: 'passive_scan',
    };
    const key = mapping[id];
    if (!key) return;

    const host = window.location.hostname || 'localhost';
    const body: any = {};
    body.channel_hopping = getSetting('channel_hopping', true);
    body.passive_scan = getSetting('passive_scan', true);
    body.client_tracking = getSetting('client_tracking', true);
    body[key] = checked;

    fetch(`http://${host}:8787/api/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then((r) => {
        if (r.ok) toast.show(`Backend updated: ${id.replace('_', ' ')}`, 'success');
        else toast.show('Failed to sync with backend', 'error');
      })
      .catch(() => toast.show('Backend unreachable', 'error'));
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
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Wireless Monitoring</h3>
        <ToggleRow id="channel_hopping" label="Channel hopping" description="Cycle through channels 1–11 automatically on wlan1mon" defaultChecked onChange={(v) => syncToBackend('channel_hopping', v)} />
        <ToggleRow id="passive_scan" label="Passive scan mode" description="Never transmit probe or deauth frames from local interface" defaultChecked onChange={(v) => syncToBackend('passive_scan', v)} />
        <ToggleRow id="client_tracking" label="Client association tracking" description="Correlate probe requests and deauth victims with client MACs" defaultChecked onChange={(v) => syncToBackend('client_tracking', v)} />
      </Card>

      <Card className="p-5" delay={0.06}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Alerting</h3>
        <ToggleRow id="desktop_notif" label="Desktop notifications" description="Show a browser notification on new critical alerts" defaultChecked onChange={handleDesktopNotif} />
        <ToggleRow id="sound_critical" label="Audio alarm on critical threats" description="Play an alert tone when Critical severity events are detected" />
        <ToggleRow id="auto_mark_read" label="Auto-archive old alerts" description="Alerts older than 24 hours are marked as read automatically" />
      </Card>

      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Data Retention</h3>
        <ToggleRow id="retain_forever" label="Keep all history" description="Never auto-delete alerts or network scan records from the database" defaultChecked />
        <ToggleRow id="retain_30d" label="Auto-prune after 30 days" description="Automatically delete alerts and ML predictions older than 30 days" />
        <ToggleRow id="retain_7d" label="Auto-prune after 7 days" description="Aggressive cleanup — keeps only last 7 days of data (saves disk on Pi)" />
      </Card>

      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Display</h3>
        <ToggleRow id="reduced_motion" label="Reduced motion" description="Disable page transitions and card animations" onChange={handleReducedMotion} />
        <ToggleRow id="compact_tables" label="High-density tables" description="Tighter row spacing in Network and Event Log tables" onChange={handleCompactTables} />
      </Card>

      <Card className="p-5" delay={0.12}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Mitigation Actions</h3>
        <ToggleRow id="passive_block" label="Passive blocking (blacklist)" description="Mark rogue APs as Malicious — triggers immediate Critical alerts on future activity" defaultChecked />
        <ToggleRow id="client_warn" label="Client warning notifications" description="Notify when your tracked devices connect to a flagged AP" />
        <ToggleRow id="active_contain" label="Active containment (deauth)" description="Send deauth frames to disconnect clients from rogue APs. Requires network admin authorization. Legal gray area." />
      </Card>

      <Card className="p-5" delay={0.15}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-text-muted)]">About</h3>
        <div className="text-xs text-[var(--color-text-muted)] space-y-1">
          <p><span className="text-[var(--color-text)]">WIDPS</span> — Wireless Intrusion Detection & Prevention System</p>
          <p>Version 1.0.0 | Backend: Rust | ML: ONNX (99.55% accuracy)</p>
          <p>7 detectors | 3-layer detection fusion | SQLite persistence</p>
          <p className="mt-2">Backend: <span className={backendOnline ? 'text-[var(--color-accent-green)]' : 'text-[var(--color-accent-danger)]'}>{backendOnline ? 'Connected' : 'Offline'}</span></p>
        </div>
      </Card>
    </div>
  );
}
