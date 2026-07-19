import { FileText, FileJson, FileSpreadsheet, CalendarClock, ShieldAlert } from 'lucide-react';
import Card from '../components/common/Card';
import { eventLog, systemStatus } from '../data/mockData';

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
  const dateStr = new Date().toISOString().slice(0, 10);

  const exportJson = () => {
    download(`widps_report_${dateStr}.json`, JSON.stringify({ systemStatus, events: eventLog }, null, 2), 'application/json');
  };

  const exportCsv = () => {
    const headers = ['Time', 'Attack', 'Severity', 'Prediction', 'Confidence', 'Action Taken', 'Status'];
    const rows = eventLog.map((e) => [e.time, e.attack, e.severity, e.prediction, `${e.confidencePct}%`, e.actionTaken, e.status]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    download(`widps_report_${dateStr}.csv`, csv, 'text/csv;charset=utf-8;');
  };

  const exportPdfNote = () => {
    // PDF generation typically happens backend-side (Rust) for reliable
    // layout — this is the client-side trigger that would invoke a Tauri
    // command such as `invoke('generate_pdf_report')`.
    alert('This calls the Rust backend command generate_pdf_report() once wired via Tauri invoke().');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Reports</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Generate and export incident documentation for this monitoring session.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <ReportAction icon={FileText} label="Export PDF" desc="Formatted incident summary" onClick={exportPdfNote} delay={0.03} />
        <ReportAction icon={FileSpreadsheet} label="Export CSV" desc="Raw event log rows" onClick={exportCsv} delay={0.06} />
        <ReportAction icon={FileJson} label="Export JSON" desc="Full structured payload" onClick={exportJson} delay={0.09} />
        <ReportAction icon={CalendarClock} label="Daily Report" desc="24h rollup summary" onClick={exportPdfNote} delay={0.12} />
      </div>

      <Card className="p-5" delay={0.15}>
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert size={16} className="text-[var(--color-accent-blue)]" />
          <h3 className="text-sm font-semibold">Generate Incident Report</h3>
        </div>
        <p className="text-sm text-[var(--color-text-secondary)] mb-4">
          Bundles the selected threat event, its AI classification detail, and surrounding traffic context into a
          single exportable file — useful for submitting to faculty/judges as supporting evidence.
        </p>
        <button
          onClick={exportPdfNote}
          className="px-4 py-2.5 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium hover:bg-[var(--color-accent-blue-soft)] transition-colors"
        >
          Generate Incident Report
        </button>
      </Card>

      <Card className="p-5" delay={0.18}>
        <h3 className="text-sm font-semibold mb-3">Recent Exports</h3>
        <p className="text-sm text-[var(--color-text-muted)]">No reports generated yet this session.</p>
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
