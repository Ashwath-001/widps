import { useState } from 'react';
import Card from '../components/common/Card';

interface ToggleRowProps {
  label: string;
  description: string;
  defaultChecked?: boolean;
}

function ToggleRow({ label, description, defaultChecked }: ToggleRowProps) {
  const [checked, setChecked] = useState(!!defaultChecked);
  return (
    <div className="flex items-center justify-between py-3 border-b border-[var(--color-border-soft)] last:border-0">
      <div className="pr-6">
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-[var(--color-text-muted)] mt-0.5">{description}</p>
      </div>
      <button
        onClick={() => setChecked((c) => !c)}
        className={`relative w-10 h-6 rounded-full shrink-0 transition-colors ${
          checked ? 'bg-[var(--color-accent-blue)]' : 'bg-[var(--color-border)]'
        }`}
        aria-pressed={checked}
      >
        <span
          className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-[18px]' : 'translate-x-0.5'
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
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Configure monitoring, alerting, and interface behavior.</p>
      </div>

      <Card className="p-5" delay={0.03}>
        <h3 className="text-sm font-semibold mb-1">Monitoring</h3>
        <ToggleRow label="Channel hopping" description="Cycle through channels 1–11 automatically" defaultChecked />
        <ToggleRow label="Passive scan only" description="Never transmit probe or deauth frames" defaultChecked />
        <ToggleRow label="Client tracking" description="Correlate probe requests with client MACs" defaultChecked />
      </Card>

      <Card className="p-5" delay={0.06}>
        <h3 className="text-sm font-semibold mb-1">Alerting</h3>
        <ToggleRow label="Desktop notifications" description="Show a system notification on new critical alerts" defaultChecked />
        <ToggleRow label="Sound on critical" description="Play a tone when a critical-severity threat is detected" />
        <ToggleRow label="Auto-mark read after 24h" description="Alerts older than a day are marked read automatically" />
      </Card>

      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-1">Interface</h3>
        <ToggleRow label="Reduced motion" description="Minimize animation across the dashboard" />
        <ToggleRow label="Compact tables" description="Tighter row spacing in Network and Event Log tables" />
      </Card>
    </div>
  );
}
