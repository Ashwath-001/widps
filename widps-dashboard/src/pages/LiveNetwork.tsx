import { useMemo, useState } from 'react';
import { Search, X, SignalHigh, Radio, Shield, Wifi } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { useScannedNetworks } from '../hooks/useMockLiveData';
import type { AccessPoint } from '../types';

function rssiBars(rssi: number) {
  const strength = Math.max(0, Math.min(4, Math.round((rssi + 90) / 15)));
  return strength;
}

export default function LiveNetwork() {
  const accessPoints = useScannedNetworks();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<AccessPoint | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return accessPoints;
    return accessPoints.filter(
      (ap) =>
        ap.ssid.toLowerCase().includes(q) ||
        ap.bssid.toLowerCase().includes(q) ||
        ap.vendor.toLowerCase().includes(q)
    );
  }, [query, accessPoints]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Live Scanned Networks</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {accessPoints.length} wireless access points collected across scanned channels.
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-full sm:w-80">
          <Search size={15} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search SSID, BSSID MAC..."
            className="bg-transparent text-sm outline-none w-full placeholder:text-[var(--color-text-muted)]"
          />
        </div>
      </div>

      {accessPoints.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <Wifi size={36} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
          <h3 className="text-base font-semibold">No Wireless Networks Collected Yet</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            The WIDPS backend is scanning on <span className="data-mono text-[var(--color-accent-blue)]">wlan1mon</span>. Discovered wireless networks (SSID and BSSID) will populate here live in real-time.
          </p>
        </Card>
      ) : (
        <Card className="overflow-x-auto" hover={false} delay={0.05}>
          <table className="w-full text-sm min-w-[900px]">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
                <th className="px-4 py-3 font-medium">Network Name (SSID)</th>
                <th className="px-4 py-3 font-medium">BSSID (MAC Address)</th>
                <th className="px-4 py-3 font-medium">Channel</th>
                <th className="px-4 py-3 font-medium">Signal (RSSI)</th>
                <th className="px-4 py-3 font-medium">Vendor</th>
                <th className="px-4 py-3 font-medium">Encryption</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium text-right">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border-soft)]">
              {filtered.map((ap) => (
                <tr
                  key={ap.bssid}
                  onClick={() => setSelected(ap)}
                  className="hover:bg-white/[0.03] transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 font-medium text-[var(--color-text)]">
                    {ap.ssid || <span className="italic text-[var(--color-text-muted)]">&lt;Hidden SSID&gt;</span>}
                  </td>
                  <td className="px-4 py-3 data-mono text-[var(--color-accent-blue)]">{ap.bssid}</td>
                  <td className="px-4 py-3 data-mono">{ap.channel}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="data-mono text-xs">{ap.rssi} dBm</span>
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
                  <td className="px-4 py-3 text-[var(--color-text-secondary)] text-xs">{ap.vendor || 'Unknown'}</td>
                  <td className="px-4 py-3 text-xs text-[var(--color-text-secondary)]">{ap.encryption || 'OPEN'}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={ap.status || 'Normal'} />
                  </td>
                  <td className="px-4 py-3 data-mono text-xs text-right text-[var(--color-text-muted)]">{ap.lastSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {selected && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 flex items-center justify-end"
          onClick={() => setSelected(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md h-full bg-[var(--color-bg-elevated)] border-l border-[var(--color-border)] p-6 overflow-y-auto"
          >
            <div className="flex items-start justify-between mb-6">
              <div>
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide">Access Point Details</p>
                <h2 className="text-lg font-semibold mt-1">{selected.ssid || '<Hidden SSID>'}</h2>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5"
              >
                <X size={16} />
              </button>
            </div>

            <div className="mb-5">
              <StatusBadge status={selected.status || 'Normal'} />
            </div>

            <div className="space-y-4">
              <DetailRow icon={Radio} label="BSSID" value={selected.bssid} mono />
              <DetailRow icon={SignalHigh} label="RSSI Signal" value={`${selected.rssi} dBm`} mono />
              <DetailRow icon={Shield} label="Vendor" value={selected.vendor || 'Unknown'} />
              <DetailRow icon={Radio} label="Channel" value={String(selected.channel)} mono />
              <DetailRow icon={Shield} label="Encryption" value={selected.encryption || 'OPEN'} />
              <DetailRow icon={Radio} label="First Seen" value={selected.firstSeen} mono />
              <DetailRow icon={Radio} label="Last Seen" value={selected.lastSeen} mono />
            </div>
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
