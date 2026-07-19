import { BrainCircuit, Clock, ShieldCheck, Cpu, Layers } from 'lucide-react';
import Card from '../components/common/Card';

export default function AIDetection() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold">AI Detection Engine</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
              Upcoming Feature (MVP Roadmap)
            </span>
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Planned on-device RF classifier for intelligent wireless anomaly detection.
          </p>
        </div>
      </div>

      <Card className="p-8 text-center" delay={0.03}>
        <div className="w-14 h-14 rounded-2xl bg-[var(--color-accent-blue)]/10 text-[var(--color-accent-blue)] flex items-center justify-center mx-auto mb-4 border border-[var(--color-accent-blue)]/20">
          <BrainCircuit size={28} />
        </div>
        <h2 className="text-lg font-semibold text-[var(--color-text)]">On-Device Machine Learning Engine</h2>
        <p className="text-xs text-[var(--color-text-muted)] max-w-lg mx-auto mt-2 leading-relaxed">
          The AI classifier module is scheduled for Phase 2 integration. Current MVP operations rely on deterministic heuristic detectors (Deauth flood, Rogue AP / Evil Twin, Karma AP) in the Rust backend core.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto mt-8 text-left">
          <div className="p-4 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <Cpu size={18} className="text-[var(--color-accent-blue)] mb-2" />
            <h3 className="text-xs font-semibold text-[var(--color-text)]">Model Architecture</h3>
            <p className="text-[11px] text-[var(--color-text-muted)] mt-1">Lightweight Random Forest / XGBoost model trained on 802.11 frame feature vectors.</p>
          </div>

          <div className="p-4 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <Layers size={18} className="text-[var(--color-accent-green)] mb-2" />
            <h3 className="text-xs font-semibold text-[var(--color-text)]">Targeted Attacks</h3>
            <p className="text-[11px] text-[var(--color-text-muted)] mt-1">Automated classification of Deauth floods, Beacon floods, Karma APs, & Probe anomalies.</p>
          </div>

          <div className="p-4 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <Clock size={18} className="text-[var(--color-accent-warning)] mb-2" />
            <h3 className="text-xs font-semibold text-[var(--color-text)]">Inference Speed</h3>
            <p className="text-[11px] text-[var(--color-text-muted)] mt-1">Sub-5ms per-packet inference latency optimized for Raspberry Pi embedded devices.</p>
          </div>
        </div>
      </Card>

      <Card className="p-5" delay={0.06}>
        <div className="flex items-center gap-2 mb-3">
          <ShieldCheck size={16} className="text-[var(--color-accent-green)]" />
          <h3 className="text-sm font-semibold">Active Heuristic Detectors (Current MVP)</h3>
        </div>
        <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <dt className="font-semibold text-[var(--color-text)]">Deauth Flood Detector</dt>
            <dd className="text-[var(--color-text-muted)] mt-1">Tracks burst rates of disassociation/deauth frames per BSSID/station.</dd>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <dt className="font-semibold text-[var(--color-text)]">Rogue AP / Evil Twin</dt>
            <dd className="text-[var(--color-text-muted)] mt-1">Cross-references beacon SSIDs against known whitelist BSSID & OUI databases.</dd>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <dt className="font-semibold text-[var(--color-text)]">Karma Attack Detector</dt>
            <dd className="text-[var(--color-text-muted)] mt-1">Detects AP probe response anomalies answering for unbroadcast SSIDs.</dd>
          </div>
        </dl>
      </Card>
    </div>
  );
}
