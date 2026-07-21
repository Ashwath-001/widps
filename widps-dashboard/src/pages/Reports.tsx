import { FileText, FileJson, FileSpreadsheet, CalendarClock, ShieldAlert } from 'lucide-react';
import Card from '../components/common/Card';
import { useLiveAlerts, useScannedNetworks, useSystemStatus } from '../hooks/useMockLiveData';

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
    download(`widps_report_${dateStr}.json`, JSON.stringify(payload, null, 2), 'application/json');
  };

  const exportCsv = () => {
    const headers = ['Time', 'Severity', 'Attack', 'Detail'];
    const rows = alerts.map((a) => [a.time, a.severity, a.title, a.detail.replace(/,/g, ';')]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    download(`widps_alerts_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
  };

  const exportNetworksCsv = () => {
    const headers = ['SSID', 'BSSID', 'Channel', 'RSSI', 'Vendor', 'Encryption', 'Status', 'First Seen', 'Last Seen'];
    const rows = networks.map((n) => [n.ssid, n.bssid, n.channel, n.rssi, n.vendor, n.encryption, n.status, n.firstSeen, n.lastSeen]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    download(`widps_networks_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
  };

  const exportPdf = () => {
    window.print();
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
          <p>Print uses the browser's native print dialog — use "Save as PDF" for PDF output.</p>
        </div>
      </Card>
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
