import { useMemo, useState } from 'react';
import { ShieldAlert, Crosshair, Wifi, Clock, Gauge, Eye, EyeOff, Ban, ShieldCheck } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { useLiveAlerts } from '../hooks/useMockLiveData';
import type { ThreatEvent } from '../types';

export default function ThreatMap() {
  const alerts = useLiveAlerts();
  const [overrideStatuses, setOverrideStatuses] = useState<Record<string, ThreatEvent['status']>>({});

  const threats: ThreatEvent[] = useMemo(() => {
    return alerts.map((a, i) => {
      const bssidMatch = a.detail?.match(/BSSID:\s*([0-9A-Fa-f:]{17})/i);
      const ssidMatch = a.detail?.match(/SSID:\s*([^|\n]+)/i);
      const chMatch = a.detail?.match(/CH:\s*(\d+)/i);

      return {
        id: a.id || `th-${i}`,
        attackName: a.title,
        severity: a.severity,
        targetMac: 'Broadcast / All Clients',
        attackerMac: bssidMatch ? bssidMatch[1].toUpperCase() : 'Unknown MAC',
        ssid: ssidMatch ? ssidMatch[1].trim() : '(Scanned Network)',
        channel: chMatch ? parseInt(chMatch[1], 10) : 6,
        detectedAt: a.time,
        aiConfidencePct: a.severity === 'Critical' ? 96 : a.severity === 'High' ? 88 : 74,
        status: overrideStatuses[a.id] || 'Active',
      };
    });
  }, [alerts, overrideStatuses]);

  const updateStatus = (id: string, status: ThreatEvent['status']) => {
    setOverrideStatuses((prev) => ({ ...prev, [id]: status }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Threat Map ({threats.length})</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Active and historical attack events detected on scanned channels, ready for triage.
        </p>
      </div>

      {threats.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <ShieldCheck size={36} className="mx-auto text-[var(--color-accent-green)] mb-3 opacity-80" />
          <h3 className="text-base font-semibold">No Active Threat Anomalies</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            The detection engine is monitoring frames on wlan1mon. Rogue APs, Evil Twins, or Deauth floods will be flagged here immediately upon detection.
          </p>
        </Card>
      ) : (
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
                <InfoRow icon={Crosshair} label="Attacker BSSID" value={t.attackerMac} mono />
                <InfoRow icon={Wifi} label="Channel" value={String(t.channel)} mono />
                <InfoRow icon={Clock} label="Detected At" value={t.detectedAt} mono />
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
      )}
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
