import { useState } from 'react';
import { Wifi, Activity, Cpu, ShieldCheck, Radio, Search } from 'lucide-react';
import StatCard from '../components/common/StatCard';
import Card from '../components/common/Card';
import { useSystemStatus, useScannedNetworks } from '../hooks/useMockLiveData';

export default function Overview() {
  const status = useSystemStatus();
  const networks = useScannedNetworks();
  const [search, setSearch] = useState('');

  const filteredNetworks = networks.filter(
    (ap) =>
      ap.ssid.toLowerCase().includes(search.toLowerCase()) ||
      ap.bssid.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Wireless Operations & Scanned Networks</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Real-time interface telemetry and collected wireless access points scanned on <span className="data-mono text-[var(--color-accent-blue)]">{status.interfaceName}</span>.
        </p>
      </div>

      {/* Monitoring Status Banner */}
      <Card className="p-4 flex items-center justify-between flex-wrap gap-3" delay={0.02}>
        <div className="flex items-center gap-3">
          <span className="relative flex items-center justify-center w-3 h-3">
            <span className="inline-flex w-2.5 h-2.5 rounded-full bg-[var(--color-accent-green)]" />
          </span>
          <div>
            <p className="text-sm font-medium">
              Monitor Mode: {status.monitoringActive ? 'Active' : 'Stopped'} on{' '}
              <span className="data-mono text-[var(--color-accent-blue)]">{status.interfaceName}</span>
            </p>
            <p className="text-xs text-[var(--color-text-muted)]">
              Hopper Thread: Cycling 2.4 GHz channels 1–11 · Engine: {status.detectionEngineStatus}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
          <Radio size={14} className="text-[var(--color-accent-blue)]" />
          Active Channel
          <span className="data-mono text-[var(--color-text)] font-semibold text-base">{status.currentChannel}</span>
        </div>
      </Card>

      {/* Core Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Wifi}
          label="Collected Networks"
          value={networks.length}
          tone="blue"
          subtext="Unique BSSIDs captured"
          delay={0.03}
        />
        <StatCard
          icon={Activity}
          label="Engine Status"
          value={status.monitoringActive ? 1 : 0}
          decimals={0}
          tone="green"
          subtext={status.detectionEngineStatus}
          delay={0.06}
        />
        <StatCard
          icon={Cpu}
          label="CPU Load"
          value={status.cpuUsagePct}
          suffix="%"
          tone="default"
          subtext="Host device CPU"
          delay={0.09}
        />
        <StatCard
          icon={ShieldCheck}
          label="AI Model Engine"
          value={0}
          subtext="Upcoming (MVP Roadmap)"
          tone="default"
          delay={0.12}
        />
      </div>

      {/* Real Collected Scanned Networks Section */}
      <Card className="p-5" delay={0.15}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-base font-semibold">Collected Scanned Networks ({networks.length})</h2>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
              Live wireless access points identified via beacon & probe response frames.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs w-64 max-w-full">
              <Search size={14} className="text-[var(--color-text-muted)] shrink-0" />
              <input
                type="text"
                placeholder="Search SSID or BSSID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-transparent outline-none w-full placeholder:text-[var(--color-text-muted)] text-[var(--color-text)]"
              />
            </div>
          </div>
        </div>

        {filteredNetworks.length === 0 ? (
          <div className="py-12 px-4 text-center rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-bg)]/40">
            <Wifi size={32} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
            <p className="text-sm font-medium text-[var(--color-text-secondary)]">
              {search ? 'No scanned networks match your search' : 'No Scanned Networks Collected Yet'}
            </p>
            <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1">
              {search
                ? 'Try searching with a different SSID or BSSID MAC address.'
                : 'The WIDPS backend is actively hopping channels on wlan1mon. As beacon frames are captured, detected networks will automatically appear here.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-2.5 px-3 font-semibold">Network Name (SSID)</th>
                  <th className="py-2.5 px-3 font-semibold">BSSID (MAC Address)</th>
                  <th className="py-2.5 px-3 font-semibold">Channel</th>
                  <th className="py-2.5 px-3 font-semibold">Signal (RSSI)</th>
                  <th className="py-2.5 px-3 font-semibold">Vendor</th>
                  <th className="py-2.5 px-3 font-semibold">Security</th>
                  <th className="py-2.5 px-3 font-semibold text-right">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-soft)]">
                {filteredNetworks.map((ap) => (
                  <tr key={ap.bssid} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 px-3 font-medium text-[var(--color-text)]">
                      {ap.ssid || <span className="italic text-[var(--color-text-muted)]">&lt;Hidden SSID&gt;</span>}
                    </td>
                    <td className="py-3 px-3 data-mono text-[var(--color-accent-blue)]">{ap.bssid}</td>
                    <td className="py-3 px-3 data-mono">{ap.channel}</td>
                    <td className="py-3 px-3 data-mono">
                      <span className={ap.rssi > -60 ? 'text-[var(--color-accent-green)]' : ap.rssi > -75 ? 'text-[var(--color-accent-warning)]' : 'text-[var(--color-text-muted)]'}>
                        {ap.rssi} dBm
                      </span>
                    </td>
                    <td className="py-3 px-3 text-[var(--color-text-secondary)]">{ap.vendor || 'Unknown'}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-[var(--color-card)] text-[var(--color-text-secondary)] border border-[var(--color-border-soft)]">
                        {ap.encryption || 'OPEN'}
                      </span>
                    </td>
                    <td className="py-3 px-3 data-mono text-right text-[var(--color-text-muted)]">{ap.lastSeen}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
