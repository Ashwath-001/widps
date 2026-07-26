import { FileText, FileJson, FileSpreadsheet, CalendarClock, ShieldAlert } from 'lucide-react';
import Card from '../components/common/Card';
import { useLiveAlerts, useScannedNetworks, useSystemStatus } from '../hooks/useMockLiveData';
import { useToastContext } from '../hooks/ToastContext';

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const alerts = useLiveAlerts();
  const networks = useScannedNetworks();
  const status = useSystemStatus();
  const toast = useToastContext();
  const dateStr = new Date().toISOString().slice(0, 10);

  const exportJson = () => {
    const payload = {
      exportDate: new Date().toISOString(),
      systemStatus: status,
      networks,
      alerts,
      summary: {
        totalAlerts: alerts.length,
        totalNetworks: networks.length,
        criticalAlerts: alerts.filter((a) => a.severity === 'Critical').length,
        highAlerts: alerts.filter((a) => a.severity === 'High').length,
        suspiciousNetworks: networks.filter((n) => n.status === 'Suspicious' || n.status === 'Malicious').length,
      },
    };
    download(`incident_report_${dateStr}.json`, JSON.stringify(payload, null, 2), 'application/json');
    setTimeout(() => toast.show(`Exported incident_report_${dateStr}.json`, 'success'), 500);
  };

  const exportCsv = () => {
    const headers = ['Time', 'Severity', 'Attack', 'Detail'];
    const rows = alerts.map((a) => [a.time, a.severity, a.title, a.detail.replace(/,/g, ';')]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    download(`security_alerts_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
    setTimeout(() => toast.show(`Exported ${alerts.length} alerts to CSV`, 'success'), 500);
  };

  const exportNetworksCsv = () => {
    const headers = ['SSID', 'BSSID', 'Channel', 'RSSI', 'Vendor', 'Encryption', 'Status', 'First Seen', 'Last Seen'];
    const rows = networks.map((n) => [n.ssid, n.bssid, n.channel, n.rssi, n.vendor, n.encryption, n.status, n.firstSeen, n.lastSeen]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    download(`network_scan_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
    setTimeout(() => toast.show(`Exported ${networks.length} networks to CSV`, 'success'), 500);
  };

  const exportPdf = () => {
    const printContent = document.getElementById('print-report');
    if (printContent) {
      printContent.style.display = 'block';
    }
    window.print();
    if (printContent) {
      setTimeout(() => { printContent.style.display = 'none'; }, 500);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Reports</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Generate and export incident documentation. Data pulled live from backend.
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
        <Card className="p-4" delay={0.02}>
          <p className="text-2xl font-bold text-[var(--color-text)]">{alerts.length}</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">Total Alerts</p>
        </Card>
        <Card className="p-4" delay={0.04}>
          <p className="text-2xl font-bold text-[var(--color-accent-danger)]">
            {alerts.filter((a) => a.severity === 'Critical').length}
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">Critical</p>
        </Card>
        <Card className="p-4" delay={0.06}>
          <p className="text-2xl font-bold text-[var(--color-accent-blue)]">{networks.length}</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">Networks Scanned</p>
        </Card>
        <Card className="p-4" delay={0.08}>
          <p className="text-2xl font-bold text-[var(--color-accent-warning)]">
            {networks.filter((n) => n.status !== 'Normal').length}
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">Suspicious</p>
        </Card>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <ReportAction icon={FileJson} label="Export Full JSON" desc="Alerts + networks + status" onClick={exportJson} delay={0.10} />
        <ReportAction icon={FileSpreadsheet} label="Export Alerts CSV" desc={`${alerts.length} alert records`} onClick={exportCsv} delay={0.12} />
        <ReportAction icon={FileSpreadsheet} label="Export Networks CSV" desc={`${networks.length} scanned APs`} onClick={exportNetworksCsv} delay={0.14} />
        <ReportAction icon={FileText} label="Print Report" desc="Browser print dialog" onClick={exportPdf} delay={0.16} />
      </div>

      <Card className="p-5" delay={0.18}>
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert size={16} className="text-[var(--color-accent-blue)]" />
          <h3 className="text-sm font-semibold">Generate Incident Report</h3>
        </div>
        <p className="text-sm text-[var(--color-text-secondary)] mb-4">
          Bundles all current alerts, scanned networks, and system status into a downloadable JSON file
          with summary statistics. Use the CSV exports for spreadsheet analysis.
        </p>
        <button
          onClick={exportJson}
          className="px-4 py-2.5 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium hover:bg-[var(--color-accent-blue-soft)] transition-colors"
        >
          Generate Full Report (JSON)
        </button>
      </Card>

      <Card className="p-5" delay={0.20}>
        <h3 className="text-sm font-semibold mb-3">Export Info</h3>
        <div className="text-xs text-[var(--color-text-muted)] space-y-1">
          <p>JSON export includes: system status, all scanned networks, all alerts, and summary counts.</p>
          <p>CSV exports are tab-compatible with Excel/Google Sheets for filtering and pivot tables.</p>
          <p>Print uses the browser's native print dialog - use "Save as PDF" for PDF output.</p>
        </div>
      </Card>

      <div id="print-report" className="hidden print:block" style={{ display: 'none' }}>
        <div className="p-8 max-w-3xl mx-auto text-black bg-white">
          <h1 className="text-2xl font-bold mb-1">WIDPS - Incident Report</h1>
          <p className="text-sm text-gray-600 mb-6">Generated: {new Date().toLocaleString()}</p>

          <h2 className="text-lg font-semibold mt-6 mb-2 border-b pb-1">Summary</h2>
          <table className="w-full text-sm mb-6">
            <tbody>
              <tr><td className="py-1 font-medium">Total Alerts</td><td>{alerts.length}</td></tr>
              <tr><td className="py-1 font-medium">Critical Alerts</td><td>{alerts.filter(a => a.severity === 'Critical').length}</td></tr>
              <tr><td className="py-1 font-medium">Networks Scanned</td><td>{networks.length}</td></tr>
              <tr><td className="py-1 font-medium">Suspicious Networks</td><td>{networks.filter(n => n.status !== 'Normal').length}</td></tr>
              <tr><td className="py-1 font-medium">Interface</td><td>{status.interfaceName}</td></tr>
              <tr><td className="py-1 font-medium">Packets/sec</td><td>{status.packetsPerSecond}</td></tr>
            </tbody>
          </table>

          {alerts.length > 0 && (
            <>
              <h2 className="text-lg font-semibold mt-6 mb-2 border-b pb-1">Alerts ({alerts.length})</h2>
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-1 pr-2">Time</th>
                    <th className="text-left py-1 pr-2">Severity</th>
                    <th className="text-left py-1">Title</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 50).map((a, i) => (
                    <tr key={i} className="border-b border-gray-200">
                      <td className="py-1 pr-2 font-mono">{a.time}</td>
                      <td className="py-1 pr-2">{a.severity}</td>
                      <td className="py-1">{a.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {networks.length > 0 && (
            <>
              <h2 className="text-lg font-semibold mt-6 mb-2 border-b pb-1">Scanned Networks ({networks.length})</h2>
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-1 pr-2">SSID</th>
                    <th className="text-left py-1 pr-2">BSSID</th>
                    <th className="text-left py-1 pr-2">Ch</th>
                    <th className="text-left py-1 pr-2">RSSI</th>
                    <th className="text-left py-1">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {networks.map((n, i) => (
                    <tr key={i} className="border-b border-gray-200">
                      <td className="py-1 pr-2">{n.ssid}</td>
                      <td className="py-1 pr-2 font-mono">{n.bssid}</td>
                      <td className="py-1 pr-2">{n.channel}</td>
                      <td className="py-1 pr-2">{n.rssi} dBm</td>
                      <td className="py-1">{n.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <p className="text-xs text-gray-400 mt-8 border-t pt-4">
            WIDPS - Wireless Intrusion Detection & Prevention System | Generated by AI-powered detection engine
          </p>
        </div>
      </div>
    </div>
  );
}

function ReportAction({
  icon: Icon,
  label,
  desc,
  onClick,
  delay,
}: {
  icon: typeof FileText;
  label: string;
  desc: string;
  onClick: () => void;
  delay: number;
}) {
  return (
    <Card delay={delay} className="p-5">
      <button onClick={onClick} className="w-full text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)] rounded-lg">
        <div className="w-9 h-9 rounded-lg bg-[var(--color-accent-blue)]/10 flex items-center justify-center mb-3">
          <Icon size={17} className="text-[var(--color-accent-blue)]" />
        </div>
        <p className="text-sm font-semibold">{label}</p>
        <p className="text-xs text-[var(--color-text-muted)] mt-1">{desc}</p>
      </button>
    </Card>
  );
}
