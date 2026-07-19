import { useMemo, useState } from 'react';
import { Search, X, SignalHigh, Radio, ShieldQuestion } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { accessPoints } from '../data/mockData';
import type { AccessPoint } from '../types';

function rssiBars(rssi: number) {
  // Rough bucket: -30 excellent -> -90 unusable
  const strength = Math.max(0, Math.min(4, Math.round((rssi + 90) / 15)));
  return strength;
}

export default function LiveNetwork() {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<AccessPoint | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return accessPoints;
    return accessPoints.filter(
      (ap) => ap.ssid.toLowerCase().includes(q) || ap.bssid.toLowerCase().includes(q) || ap.vendor.toLowerCase().includes(q)
    );
  }, [query]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Live Network</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {accessPoints.length} access points observed across channels 1–11.
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-full sm:w-80">
          <Search size={15} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search SSID, BSSID, or vendor..."
            className="bg-transparent text-sm outline-none w-full placeholder:text-[var(--color-text-muted)]"
          />
        </div>
      </div>

      <Card className="overflow-x-auto" hover={false} delay={0.05}>
        <table className="w-full text-sm min-w-[900px]">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
              <th className="px-4 py-3 font-medium">SSID</th>
              <th className="px-4 py-3 font-medium">BSSID</th>
              <th className="px-4 py-3 font-medium">Ch</th>
              <th className="px-4 py-3 font-medium">RSSI</th>
              <th className="px-4 py-3 font-medium">Vendor</th>
              <th className="px-4 py-3 font-medium">Encryption</th>
              <th className="px-4 py-3 font-medium">Beacon</th>
              <th className="px-4 py-3 font-medium">Clients</th>
              <th className="px-4 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ap) => (
              <tr
                key={ap.id}
                onClick={() => setSelected(ap)}
                className="border-b border-[var(--color-border-soft)] last:border-0 cursor-pointer hover:bg-white/[0.03] transition-colors"
              >
                <td className="px-4 py-3 font-medium">{ap.ssid}</td>
                <td className="px-4 py-3 data-mono text-[var(--color-text-secondary)]">{ap.bssid}</td>
                <td className="px-4 py-3 data-mono">{ap.channel}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="data-mono">{ap.rssi} dBm</span>
                    <div className="flex items-end gap-[2px] h-3">
                      {[0, 1, 2, 3].map((i) => (
                        <span
                          key={i}
                          className={`w-[3px] rounded-sm ${i < rssiBars(ap.rssi) ? 'bg-[var(--color-accent-blue)]' : 'bg-[var(--color-border)]'}`}
                          style={{ height: `${(i + 1) * 3}px` }}
                        />
                      ))}
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 text-[var(--color-text-secondary)]">{ap.vendor}</td>
                <td className="px-4 py-3 text-[var(--color-text-secondary)]">{ap.encryption}</td>
                <td className="px-4 py-3 data-mono">{ap.beaconIntervalMs}ms</td>
                <td className="px-4 py-3 data-mono">{ap.clientCount}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={ap.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {selected && (
        <div
          className="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 flex items-center justify-end"
          onClick={() => setSelected(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md h-full bg-[var(--color-bg-elevated)] border-l border-[var(--color-border)] p-6 overflow-y-auto animate-[slideIn_0.25s_ease-out]"
          >
            <div className="flex items-start justify-between mb-6">
              <div>
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide">Access Point</p>
                <h2 className="text-lg font-semibold mt-1">{selected.ssid}</h2>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5"
              >
                <X size={16} />
              </button>
            </div>

            <div className="mb-5">
              <StatusBadge status={selected.status} />
            </div>

            <div className="space-y-4">
              <DetailRow icon={Radio} label="BSSID" value={selected.bssid} mono />
              <DetailRow icon={SignalHigh} label="RSSI" value={`${selected.rssi} dBm`} mono />
              <DetailRow icon={ShieldQuestion} label="Vendor" value={selected.vendor} />
              <DetailRow icon={ShieldQuestion} label="Channel" value={String(selected.channel)} mono />
              <DetailRow icon={ShieldQuestion} label="Encryption" value={selected.encryption} />
              <DetailRow icon={ShieldQuestion} label="Beacon interval" value={`${selected.beaconIntervalMs} ms`} mono />
              <DetailRow icon={ShieldQuestion} label="Connected clients" value={String(selected.clientCount)} mono />
              <DetailRow icon={ShieldQuestion} label="First seen" value={selected.firstSeen} mono />
              <DetailRow icon={ShieldQuestion} label="Last seen" value={selected.lastSeen} mono />
            </div>

            {selected.status !== 'Normal' && (
              <div className="mt-6 p-4 rounded-lg bg-[var(--color-accent-danger)]/10 border border-[var(--color-accent-danger)]/25 text-sm text-[var(--color-accent-danger)]">
                This BSSID shares an SSID with a whitelisted access point but does not match its known BSSID —
                flagged as a possible evil twin.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ icon: Icon, label, value, mono }: { icon: typeof Radio; label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-[var(--color-border-soft)]">
      <div className="flex items-center gap-2 text-[var(--color-text-secondary)] text-sm">
        <Icon size={14} />
        {label}
      </div>
      <span className={`text-sm ${mono ? 'data-mono' : ''}`}>{value}</span>
    </div>
  );
}
