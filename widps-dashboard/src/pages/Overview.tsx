import { useState, useEffect } from 'react';
import { Wifi, Activity, Cpu, ShieldCheck, Radio, Search, Thermometer, AlertTriangle, Zap } from 'lucide-react';
import StatCard from '../components/common/StatCard';
import Card from '../components/common/Card';
import { useSystemStatus, useScannedNetworks, useLiveAlerts } from '../hooks/useMockLiveData';
import { useToastContext } from '../hooks/ToastContext';

export default function Overview() {
  const status = useSystemStatus();
  const networks = useScannedNetworks();
  const alerts = useLiveAlerts();
  const toast = useToastContext();
  const [search, setSearch] = useState('');
  const [uptime, setUptime] = useState('0m');

  // Calculate uptime from first alert timestamp
  useEffect(() => {
    const interval = setInterval(() => {
      const startTime = sessionStorage.getItem('widps_start_time');
      if (!startTime) {
        sessionStorage.setItem('widps_start_time', String(Date.now()));
        setUptime('0m');
        return;
      }
      const elapsed = Math.floor((Date.now() - Number(startTime)) / 1000);
      if (elapsed < 60) setUptime(`${elapsed}s`);
      else if (elapsed < 3600) setUptime(`${Math.floor(elapsed / 60)}m`);
      else setUptime(`${Math.floor(elapsed / 3600)}h ${Math.floor((elapsed % 3600) / 60)}m`);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const criticalAlerts = alerts.filter(a => a.severity === 'Critical');
  const highAlerts = alerts.filter(a => a.severity === 'High');
  const suspiciousNets = networks.filter(n => n.status !== 'Normal');

  const filteredNetworks = networks.filter(
    (ap) =>
      ap.ssid.toLowerCase().includes(search.toLowerCase()) ||
      ap.bssid.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Dashboard</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          System overview and real-time wireless monitoring status.
        </p>
      </div>

      {/* Alert Summary Banner */}
      {(criticalAlerts.length > 0 || highAlerts.length > 0) && (
        <Card className={`p-4 border-l-4 ${criticalAlerts.length > 0 ? 'border-l-red-500 bg-red-500/5' : 'border-l-orange-500 bg-orange-500/5'}`} delay={0.01}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-3">
              <AlertTriangle size={18} className={criticalAlerts.length > 0 ? 'text-red-400' : 'text-orange-400'} />
              <div>
                <p className="text-sm font-medium">
                  {criticalAlerts.length > 0
                    ? `${criticalAlerts.length} Critical alert${criticalAlerts.length > 1 ? 's' : ''} active`
                    : `${highAlerts.length} High severity alert${highAlerts.length > 1 ? 's' : ''}`
                  }
                </p>
                <p className="text-xs text-[var(--color-text-muted)]">
                  {criticalAlerts.length > 0 ? criticalAlerts[0].title : highAlerts[0]?.title}
                </p>
              </div>
            </div>
            <button
              onClick={() => { window.location.hash = ''; setTimeout(() => window.location.hash = '/threats', 10); }}
              className="h-[28px] px-3 rounded text-[10px] font-medium border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:bg-[var(--color-card)] transition-colors shrink-0"
            >
              View Threats →
            </button>
          </div>
        </Card>
      )}

      {/* Monitoring Status */}
      <Card className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3" delay={0.02}>
        <div className="flex items-center gap-3">
          <span className="relative flex items-center justify-center w-3 h-3">
            <span className={`inline-flex w-2.5 h-2.5 rounded-full ${status.monitoringActive ? 'bg-[var(--color-accent-green)]' : 'bg-[var(--color-accent-danger)]'}`} />
            {status.monitoringActive && <span className="absolute inline-flex w-full h-full rounded-full bg-[var(--color-accent-green)] animate-ping opacity-50" />}
          </span>
          <div>
            <p className="text-sm font-medium">
              {status.monitoringActive ? 'Monitor Active' : 'Monitor Stopped'} - <span className="data-mono text-[var(--color-accent-blue)]">{status.interfaceName}</span>
            </p>
            <p className="text-xs text-[var(--color-text-muted)]">
              Channel hopping 1–11 • {status.packetsPerSecond} pkt/s • Uptime: {uptime}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <Radio size={12} className="text-[var(--color-accent-blue)]" />
            <span className="text-[var(--color-text-muted)]">Ch</span>
            <span className="data-mono font-bold text-base">{status.currentChannel}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Zap size={12} className="text-[var(--color-accent-warning)]" />
            <span className="text-[var(--color-text-muted)]">PPS</span>
            <span className="data-mono font-bold">{status.packetsPerSecond}</span>
          </div>
        </div>
      </Card>

      {/* Telemetry Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard icon={Wifi} label="Networks" value={networks.length} tone="blue" subtext="Unique BSSIDs" delay={0.03} />
        <StatCard icon={Activity} label="Stations" value={status.connectedStationCount} tone="green" subtext="Tracked clients" delay={0.04} />
        <StatCard icon={AlertTriangle} label="Alerts" value={alerts.length} tone={criticalAlerts.length > 0 ? 'danger' : 'default'} subtext={`${criticalAlerts.length} critical`} delay={0.05} />
        <StatCard icon={ShieldCheck} label="Suspicious" value={suspiciousNets.length} tone={suspiciousNets.length > 0 ? 'warning' : 'green'} subtext="Flagged APs" delay={0.06} />
        <StatCard icon={Cpu} label="CPU" value={status.cpuUsagePct} suffix="%" tone="default" subtext="System load" delay={0.07} />
        <StatCard icon={Thermometer} label="Temp" value={status.piTemperatureC} suffix="°C" tone={status.piTemperatureC > 70 ? 'danger' : 'default'} subtext="SoC thermal" delay={0.08} />
      </div>

      {/* System Health + Quick Actions row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* System Health */}
        <Card className="p-4" delay={0.10}>
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase mb-3">System Health</h3>
          <div className="space-y-3">
            <HealthBar label="CPU" value={status.cpuUsagePct} />
            <HealthBar label="Memory" value={status.memoryUsagePct} />
            <HealthBar label="Temperature" value={Math.min(100, (status.piTemperatureC / 85) * 100)} suffix={`${status.piTemperatureC}°C`} />
          </div>
        </Card>

        {/* Alert Breakdown */}
        <Card className="p-4" delay={0.12}>
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase mb-3">Alert Summary</h3>
          {alerts.length === 0 ? (
            <p className="text-xs text-[var(--color-text-muted)] text-center py-4">No alerts - system is clean</p>
          ) : (
            <div className="space-y-2">
              <AlertRow label="Critical" count={criticalAlerts.length} color="bg-red-500" />
              <AlertRow label="High" count={highAlerts.length} color="bg-orange-500" />
              <AlertRow label="Medium" count={alerts.filter(a => a.severity === 'Medium').length} color="bg-yellow-500" />
              <AlertRow label="Low" count={alerts.filter(a => a.severity === 'Low').length} color="bg-blue-500" />
            </div>
          )}
        </Card>

        {/* Quick Actions */}
        <Card className="p-4" delay={0.14}>
          <h3 className="text-xs font-semibold text-[var(--color-text-muted)] uppercase mb-3">Quick Actions</h3>
          <div className="space-y-2">
            <QuickAction label="Generate Incident Report" onClick={() => {
              window.open('/api/report', '_blank');
              toast.show('Opening incident report', 'info');
            }} />
            <QuickAction label="Export Alerts as CSV" onClick={() => {
              if (alerts.length === 0) { toast.show('No alerts to export', 'warning'); return; }
              const csv = ['Time,Severity,Title'].concat(alerts.map(a => `${a.time},${a.severity},"${a.title}"`)).join('\n');
              const blob = new Blob([csv], { type: 'text/csv' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a'); a.href = url; a.download = `widps_alerts_${new Date().toISOString().slice(0,10)}.csv`; a.click();
              URL.revokeObjectURL(url);
              toast.show(`Exported ${alerts.length} alerts`, 'success');
            }} />
            <QuickAction label="Verify Alert Integrity" onClick={() => {
              fetch('/api/audit/integrity')
                .then(r => r.json())
                .then(d => {
                  if (d.tampered === 0) {
                    toast.show(`Integrity OK - ${d.valid} alerts verified, none tampered`, 'success');
                  } else {
                    toast.show(`WARNING: ${d.tampered} tampered alerts detected!`, 'error');
                  }
                })
                .catch(() => toast.show('Backend unreachable - cannot verify', 'error'));
            }} />
            <QuickAction label="Clear All Alerts" onClick={() => {
              fetch('/api/alerts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'clear' }),
              })
                .then(r => r.json())
                .then(() => {
                  toast.show('All alerts cleared', 'success');
                  setTimeout(() => window.location.reload(), 500);
                })
                .catch(() => toast.show('Failed to clear alerts', 'error'));
            }} />
          </div>
        </Card>
      </div>

      {/* Network Table */}
      <Card className="p-5" delay={0.16}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-semibold">Scanned Networks ({networks.length})</h2>
            <p className="text-[10px] text-[var(--color-text-muted)]">Live APs from beacon/probe frames</p>
          </div>
          <div className="flex items-center gap-2 h-[30px] px-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs w-full sm:w-56">
            <Search size={12} className="text-[var(--color-text-muted)] shrink-0" />
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent outline-none w-full placeholder:text-[var(--color-text-muted)] text-[var(--color-text)] text-xs"
            />
          </div>
        </div>

        {filteredNetworks.length === 0 ? (
          <div className="py-8 text-center">
            <Wifi size={28} className="mx-auto text-[var(--color-text-muted)] mb-2 opacity-50" />
            <p className="text-xs text-[var(--color-text-muted)]">
              {search ? 'No networks match search' : 'Waiting for beacon frames...'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[10px] text-[var(--color-text-muted)] uppercase">
                  <th className="py-2 px-2 text-left">SSID</th>
                  <th className="py-2 px-2 text-left hidden sm:table-cell">BSSID</th>
                  <th className="py-2 px-2 text-center">Ch</th>
                  <th className="py-2 px-2 text-center">RSSI</th>
                  <th className="py-2 px-2 text-left hidden md:table-cell">Vendor</th>
                  <th className="py-2 px-2 text-left hidden lg:table-cell">Security</th>
                  <th className="py-2 px-2 text-left">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-soft)]">
                {filteredNetworks.slice(0, 15).map((ap) => (
                  <tr key={ap.bssid} className="hover:bg-white/[0.02]">
                    <td className="py-2 px-2 font-medium truncate max-w-[120px]">{ap.ssid || '<hidden>'}</td>
                    <td className="py-2 px-2 data-mono text-[var(--color-accent-blue)] hidden sm:table-cell">{ap.bssid}</td>
                    <td className="py-2 px-2 text-center data-mono">{ap.channel}</td>
                    <td className="py-2 px-2 text-center data-mono">
                      <span className={ap.rssi > -60 ? 'text-green-400' : ap.rssi > -75 ? 'text-yellow-400' : 'text-[var(--color-text-muted)]'}>
                        {ap.rssi}
                      </span>
                    </td>
                    <td className="py-2 px-2 text-[var(--color-text-muted)] truncate max-w-[100px] hidden md:table-cell">{ap.vendor || '-'}</td>
                    <td className="py-2 px-2 hidden lg:table-cell">
                      <span className="px-1.5 py-0.5 rounded text-[9px] bg-[var(--color-card)] border border-[var(--color-border-soft)]">{ap.encryption || 'OPEN'}</span>
                    </td>
                    <td className="py-2 px-2">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium ${
                        ap.status === 'Malicious' ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : ap.status === 'Suspicious' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                        : 'bg-green-500/10 text-green-400 border border-green-500/30'
                      }`}>{ap.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredNetworks.length > 15 && (
              <p className="text-[10px] text-[var(--color-text-muted)] text-center mt-2">
                Showing 15 of {filteredNetworks.length} - view all in Network page
              </p>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

function HealthBar({ label, value, suffix }: { label: string; value: number; suffix?: string }) {
  const pct = Math.min(100, Math.max(0, value));
  const color = pct > 80 ? 'bg-red-500' : pct > 60 ? 'bg-yellow-500' : 'bg-green-500';
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] text-[var(--color-text-muted)] w-16 shrink-0">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-[var(--color-border)] overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] data-mono text-[var(--color-text-secondary)] w-10 text-right">
        {suffix || `${Math.round(pct)}%`}
      </span>
    </div>
  );
}

function AlertRow({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${color}`} />
        <span className="text-xs text-[var(--color-text-secondary)]">{label}</span>
      </div>
      <span className="text-xs data-mono font-medium">{count}</span>
    </div>
  );
}

function QuickAction({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full h-[30px] px-3 rounded-lg text-xs text-left font-medium border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:bg-[var(--color-card)] transition-colors"
    >
      {label}
    </button>
  );
}
