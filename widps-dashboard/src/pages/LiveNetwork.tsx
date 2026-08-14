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

function RssiSparkline({ history }: { history?: number[] }) {
  if (!history || history.length < 2) return <span className="text-[var(--color-text-muted)] text-[10px]">—</span>;

  const min = Math.min(...history);
  const max = Math.max(...history);
  const range = max - min || 1;
  const w = 60;
  const h = 16;
  const padding = 1;

  const points = history.map((v, i) => {
    const x = padding + (i / (history.length - 1)) * (w - 2 * padding);
    const y = h - padding - ((v - min) / range) * (h - 2 * padding);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  // Color based on latest value
  const latest = history[history.length - 1];
  const color = latest >= -50 ? 'var(--color-accent-green)' : latest >= -70 ? 'var(--color-accent-blue)' : 'var(--color-accent-warning)';

  return (
    <svg width={w} height={h} className="inline-block align-middle">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Live Scanned Networks</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {accessPoints.length} wireless access points collected across scanned channels.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-2 h-[30px] px-2.5 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-full sm:w-56">
            <Search size={12} className="text-[var(--color-text-muted)] shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search SSID, BSSID, vendor..."
              className="bg-transparent text-xs outline-none w-full placeholder:text-[var(--color-text-muted)]"
            />
          </div>
          <button
            onClick={() => {
              const csv = ['SSID,BSSID,Channel,RSSI,Vendor,Encryption,Status,Last Seen']
                .concat(accessPoints.map(ap => `"${ap.ssid}",${ap.bssid},${ap.channel},${ap.rssi},"${ap.vendor}",${ap.encryption},${ap.status},${ap.lastSeen}`))
                .join('\n');
              const blob = new Blob([csv], { type: 'text/csv' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a'); a.href = url; a.download = `widps_networks_${new Date().toISOString().slice(0,10)}.csv`; a.click();
            }}
            disabled={accessPoints.length === 0}
            className="h-[30px] px-3 rounded-lg text-xs font-medium border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors disabled:opacity-40 shrink-0"
          >
            Export CSV
          </button>
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
                <th className="px-4 py-3 font-medium">RSSI History</th>
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
                  <td className="px-4 py-3">
                    <RssiSparkline history={ap.rssiHistory} />
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

            {/* Actions */}
            <div className="mt-6 pt-4 border-t border-[var(--color-border-soft)] space-y-2">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase mb-2">Actions</p>
              <button
                onClick={() => {
                  fetch('/api/whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ssid: selected.ssid, bssid: selected.bssid }),
                  }).then(r => { if (r.ok) setSelected(null); });
                }}
                className="w-full h-[32px] rounded-lg text-xs font-medium border border-green-500/30 text-green-400 hover:bg-green-500/10 flex items-center justify-center gap-2 transition-colors"
              >
                <Shield size={12} /> Mark as Trusted (Whitelist)
              </button>
              <button
                onClick={() => {
                  fetch(`/api/intel/${selected.bssid.replace(/:/g, '-')}/blacklist`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ reason: 'Blacklisted from Network panel' }),
                  }).then(r => { if (r.ok) setSelected(null); });
                }}
                className="w-full h-[32px] rounded-lg text-xs font-medium border border-red-500/30 text-red-400 hover:bg-red-500/10 flex items-center justify-center gap-2 transition-colors"
              >
                <X size={12} /> Mark as Threat (Blacklist)
              </button>
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
