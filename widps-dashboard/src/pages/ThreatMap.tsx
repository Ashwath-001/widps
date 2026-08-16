import { useMemo, useState } from 'react';
import { ShieldAlert, Crosshair, Wifi, Clock, Gauge, Eye, EyeOff, Ban, ShieldCheck } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { useLiveAlerts } from '../hooks/useMockLiveData';
import { useToastContext } from '../hooks/ToastContext';
import type { ThreatEvent } from '../types';

export default function ThreatMap() {
  const alerts = useLiveAlerts();
  const toast = useToastContext();
  const [overrideStatuses, setOverrideStatuses] = useState<Record<string, ThreatEvent['status']>>({});
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

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

  const filteredThreats = useMemo(() => {
    let result = threats;
    if (severityFilter !== 'all') {
      result = result.filter(t => t.severity === severityFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(t =>
        t.attackName.toLowerCase().includes(q) ||
        t.attackerMac.toLowerCase().includes(q) ||
        t.ssid.toLowerCase().includes(q)
      );
    }
    return result;
  }, [threats, severityFilter, search]);

  const updateStatus = (id: string, status: ThreatEvent['status']) => {
    setOverrideStatuses((prev) => ({ ...prev, [id]: status }));

    const alertIndex = id.replace('th-', '');
    fetch(`/api/alerts/${alertIndex}/ack`, { method: 'POST' })
      .then((r) => {
        if (r.ok) toast.show(`Threat ${status.toLowerCase()}`, 'success');
      })
      .catch(() => {});
  };

  const confirmAttack = (threat: ThreatEvent) => {
    // Determine attack label from the alert title
    let label = 'Unknown';
    const title = threat.attackName.toLowerCase();
    if (title.includes('deauth')) label = 'Deauth_Flood';
    else if (title.includes('evil twin') || title.includes('rogue')) label = 'Evil_Twin';
    else if (title.includes('auth') || title.includes('assoc')) label = 'Auth_Flood';
    else if (title.includes('karma')) label = 'Evil_Twin';
    else if (title.includes('krack')) label = 'Krack';
    else if (title.includes('kr00k')) label = 'Kr00k';
    else if (title.includes('sequence') || title.includes('spoof')) label = 'Deauth_Flood';

    const payload = { label, features: [] };

    fetch('/api/alerts/' + threat.id.replace('th-', '') + '/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then((r) => {
        if (r.ok) {
          toast.show(`Attack confirmed as ${label} - saved for model retraining`, 'success');
          updateStatus(threat.id, 'Mitigated');
        } else {
          toast.show('Failed to confirm attack', 'error');
        }
      })
      .catch(() => toast.show('Backend unreachable', 'error'));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Threat Map ({filteredThreats.length})</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Active attack events detected on scanned channels.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-2 h-[30px] px-2.5 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-full sm:w-48">
            <Crosshair size={12} className="text-[var(--color-text-muted)] shrink-0" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search BSSID, attack..."
              className="bg-transparent text-xs outline-none w-full placeholder:text-[var(--color-text-muted)]"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-[30px] px-2 rounded-lg text-xs bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text-secondary)]"
          >
            <option value="all">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>
        </div>
      </div>

      {filteredThreats.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <ShieldCheck size={36} className="mx-auto text-[var(--color-accent-green)] mb-3 opacity-80" />
          <h3 className="text-base font-semibold">No Active Threats</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            {search || severityFilter !== 'all' ? 'No threats match your filters.' : 'The detection engine is monitoring. Threats appear here upon detection.'}
          </p>
        </Card>
      ) : (
        <>
        {/* Timeline strip */}
        <Card className="p-3 overflow-x-auto" delay={0.03}>
          <div className="flex items-center gap-1 min-w-max">
            {filteredThreats.slice(0, 20).map((t, i) => (
              <div key={i} className="flex flex-col items-center gap-1 min-w-[40px]" title={`${t.detectedAt} - ${t.attackName}`}>
                <span className={`w-3 h-3 rounded-full shrink-0 ${
                  t.severity === 'Critical' ? 'bg-red-500' : t.severity === 'High' ? 'bg-orange-500' : 'bg-yellow-500'
                }`} />
                <span className="text-[8px] text-[var(--color-text-muted)] data-mono">{t.detectedAt.split(' ').pop()?.slice(0, 5)}</span>
              </div>
            ))}
            {filteredThreats.length > 20 && <span className="text-[9px] text-[var(--color-text-muted)] ml-2">+{filteredThreats.length - 20} more</span>}
          </div>
        </Card>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredThreats.slice(0, 50).map((t, i) => (
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
                  icon={ShieldCheck}
                  label="Confirm Attack"
                  onClick={() => confirmAttack(t)}
                  active={false}
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
        </>
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
