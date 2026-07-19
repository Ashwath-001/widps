import { useState } from 'react';
import Card from '../components/common/Card';

function ToggleRow({
  id,
  label,
  description,
  defaultChecked = false,
}: {
  id: string;
  label: string;
  description: string;
  defaultChecked?: boolean;
}) {
  const [checked, setChecked] = useState<boolean>(() => {
    const saved = localStorage.getItem(`widps_setting_${id}`);
    return saved !== null ? saved === 'true' : defaultChecked;
  });

  const toggle = () => {
    const next = !checked;
    setChecked(next);
    localStorage.setItem(`widps_setting_${id}`, String(next));
  };

  return (
    <div
      onClick={toggle}
      className="flex items-center justify-between py-3.5 border-b border-[var(--color-border-soft)] last:border-0 cursor-pointer group select-none hover:bg-white/[0.01] px-1 rounded-md transition-colors"
    >
      <div className="pr-6">
        <p className="text-sm font-medium text-[var(--color-text)] group-hover:text-white transition-colors">{label}</p>
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
          checked ? 'bg-[var(--color-accent-green)]' : 'bg-slate-700'
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
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Configure wireless monitoring, threat alerting, and UI behavior.</p>
      </div>

      <Card className="p-5" delay={0.03}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Wireless Monitoring Telemetry</h3>
        <ToggleRow id="channel_hopping" label="Channel hopping" description="Cycle through channels 1–11 automatically on wlan1mon" defaultChecked />
        <ToggleRow id="passive_scan" label="Passive scan mode" description="Never transmit probe or deauth frames from local interface" defaultChecked />
        <ToggleRow id="client_tracking" label="Client association tracking" description="Correlate probe requests and deauth victims with client MACs" defaultChecked />
      </Card>

      <Card className="p-5" delay={0.06}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Threat Alerting</h3>
        <ToggleRow id="desktop_notif" label="Desktop notifications" description="Show a system popup notification on new critical alerts" defaultChecked />
        <ToggleRow id="sound_critical" label="Audio alarm on critical threats" description="Trigger an audio alert tone when a critical Rogue AP or Evil Twin is flagged" />
        <ToggleRow id="auto_mark_read" label="Auto-purge read alerts" description="Alerts older than 24 hours are archived automatically" />
      </Card>

      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-2 text-[var(--color-accent-blue)]">Interface & Display</h3>
        <ToggleRow id="reduced_motion" label="Reduced UI motion" description="Minimize animation across dashboard widgets" />
        <ToggleRow id="compact_tables" label="High-density tables" description="Tighter row spacing in Network and Event Log telemetry tables" />
      </Card>
    </div>
  );
}
