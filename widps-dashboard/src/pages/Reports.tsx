import { FileText, FileJson, FileSpreadsheet, Printer } from 'lucide-react';
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

  const criticalCount = alerts.filter((a) => a.severity === 'Critical').length;
  const suspiciousNets = networks.filter((n) => n.status !== 'Normal');

  const exportJson = () => {
    const payload = {
      report_metadata: {
        title: "WIDPS Incident Report",
        generated_at: new Date().toISOString(),
        report_id: `WIDPS-IR-${dateStr.replace(/-/g, '')}-${Date.now().toString(36).toUpperCase()}`,
        classification: "INTERNAL USE ONLY",
      },
      executive_summary: {
        total_alerts: alerts.length,
        critical_alerts: criticalCount,
        networks_monitored: networks.length,
        suspicious_networks: suspiciousNets.length,
        monitoring_interface: status.interfaceName,
      },
      system_status: status,
      detected_networks: networks,
      security_alerts: alerts,
    };
    download(`WIDPS_Incident_Report_${dateStr}.json`, JSON.stringify(payload, null, 2), 'application/json');
    toast.show('Incident report exported (JSON)', 'success');
  };

  const exportAlertsCsv = () => {
    const headers = ['Timestamp', 'Severity', 'Title', 'Detail'];
    const rows = alerts.map((a) => [a.time, a.severity, a.title, `"${(a.detail || '').replace(/"/g, '""')}"`]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    download(`WIDPS_Alerts_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
    toast.show(`Exported ${alerts.length} alerts`, 'success');
  };

  const exportNetworksCsv = () => {
    const headers = ['SSID', 'BSSID', 'Channel', 'RSSI', 'Vendor', 'Encryption', 'Status'];
    const rows = networks.map((n) => [n.ssid, n.bssid, n.channel, n.rssi, n.vendor, n.encryption, n.status]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    download(`WIDPS_Networks_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
    toast.show(`Exported ${networks.length} networks`, 'success');
  };

  const openReport = () => {
    // Backend generates the full HTML report - open in new tab
    window.open('/api/report', '_blank');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Reports</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Generate incident reports and export evidence data.
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-4 text-center" delay={0.02}>
          <p className="text-2xl font-bold data-mono">{alerts.length}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Total Alerts</p>
        </Card>
        <Card className="p-4 text-center" delay={0.04}>
          <p className="text-2xl font-bold data-mono text-[var(--color-accent-danger)]">{criticalCount}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Critical</p>
        </Card>
        <Card className="p-4 text-center" delay={0.06}>
          <p className="text-2xl font-bold data-mono">{networks.length}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Networks</p>
        </Card>
        <Card className="p-4 text-center" delay={0.08}>
          <p className="text-2xl font-bold data-mono text-[var(--color-accent-warning)]">{suspiciousNets.length}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Flagged</p>
        </Card>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <ExportCard icon={Printer} label="Incident Report" desc="Backend-generated HTML" onClick={openReport} delay={0.10} />
        <ExportCard icon={FileJson} label="Full Export (JSON)" desc="All data + metadata" onClick={exportJson} delay={0.12} />
        <ExportCard icon={FileSpreadsheet} label="Alerts (CSV)" desc={`${alerts.length} records`} onClick={exportAlertsCsv} delay={0.14} />
        <ExportCard icon={FileSpreadsheet} label="Networks (CSV)" desc={`${networks.length} APs`} onClick={exportNetworksCsv} delay={0.16} />
      </div>
    </div>
  );
}

function ExportCard({ icon: Icon, label, desc, onClick, delay }: {
  icon: typeof FileText;
  label: string;
  desc: string;
  onClick: () => void;
  delay: number;
}) {
  return (
    <Card delay={delay} className="p-5">
      <button onClick={onClick} className="w-full text-left">
        <div className="w-9 h-9 rounded-lg bg-[var(--color-accent-blue)]/10 flex items-center justify-center mb-3">
          <Icon size={17} className="text-[var(--color-accent-blue)]" />
        </div>
        <p className="text-sm font-semibold">{label}</p>
        <p className="text-xs text-[var(--color-text-muted)] mt-1">{desc}</p>
      </button>
    </Card>
  );
}
