import { useState } from 'react';
import { ShieldAlert, Crosshair, Wifi, Clock, Gauge, Eye, EyeOff, Ban } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { threatEvents as initialThreats } from '../data/mockData';
import type { ThreatEvent } from '../types';

export default function ThreatMap() {
  const [threats, setThreats] = useState<ThreatEvent[]>(initialThreats);

  const updateStatus = (id: string, status: ThreatEvent['status']) => {
    setThreats((prev) => prev.map((t) => (t.id === id ? { ...t, status } : t)));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Threat Map</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Active and historical attacks detected by the AI engine, ready for triage.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threats.map((t, i) => (
          <Card key={t.id} className="p-5" delay={0.03 * i}>
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-lg bg-[var(--color-accent-danger)]/10 flex items-center justify-center">
                  <ShieldAlert size={17} className="text-[var(--color-accent-danger)]" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">{t.attackName}</h3>
                  <p className="text-xs text-[var(--color-text-muted)]">{t.ssid}</p>
                </div>
              </div>
              <StatusBadge status={t.severity} />
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm mb-4">
              <InfoRow icon={Crosshair} label="Target MAC" value={t.targetMac} mono />
              <InfoRow icon={Crosshair} label="Attacker MAC" value={t.attackerMac} mono />
              <InfoRow icon={Wifi} label="Channel" value={String(t.channel)} mono />
              <InfoRow icon={Clock} label="Detected" value={t.detectedAt} mono />
              <InfoRow icon={Gauge} label="AI Confidence" value={`${t.aiConfidencePct}%`} mono />
              <InfoRow icon={ShieldAlert} label="Status" value="" custom={<StatusBadge status={t.status} />} />
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-border-soft)]">
              <ActionButton
                icon={Eye}
                label="Investigate"
                onClick={() => updateStatus(t.id, 'Investigating')}
                active={t.status === 'Investigating'}
              />
              <ActionButton
                icon={EyeOff}
                label="Ignore"
                onClick={() => updateStatus(t.id, 'Ignored')}
                active={t.status === 'Ignored'}
              />
              <ActionButton
                icon={Ban}
                label="Block"
                onClick={() => updateStatus(t.id, 'Mitigated')}
                active={t.status === 'Mitigated'}
                danger
              />
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function InfoRow({
  icon: Icon,
  label,
  value,
  mono,
  custom,
}: {
  icon: typeof Crosshair;
  label: string;
  value: string;
  mono?: boolean;
  custom?: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[var(--color-text-muted)] text-xs mb-1">
        <Icon size={12} />
        {label}
      </div>
      {custom ?? <span className={mono ? 'data-mono text-xs' : 'text-xs'}>{value}</span>}
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  onClick,
  active,
  danger,
}: {
  icon: typeof Eye;
  label: string;
  onClick: () => void;
  active?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)] ${
        active
          ? danger
            ? 'bg-[var(--color-accent-danger)] text-white'
            : 'bg-[var(--color-accent-blue)] text-white'
          : 'bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:border-[var(--color-border-soft)]'
      }`}
    >
      <Icon size={13} />
      {label}
    </button>
  );
}
