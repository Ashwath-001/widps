import { useState, useEffect } from 'react';
import { BrainCircuit, Clock, ShieldCheck, Cpu, Layers, Activity, TrendingUp } from 'lucide-react';
import Card from '../components/common/Card';
import { useSystemStatus } from '../hooks/useMockLiveData';

interface AiPrediction {
  label: string;
  confidence: number;
  threat_score: number;
  inference_ms: number;
  frame_count: number;
}

interface ThreatProfile {
  bssid: string;
  ssid: string | null;
  score: number;
  evidence: { source: string; weight: number; description: string; timestamp: string }[];
  verdict: string;
  alert_count: number;
}

async function fetchAi<T>(endpoint: string): Promise<T | null> {
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}${endpoint}`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return null;
}

export default function AIDetection() {
  const status = useSystemStatus();
  const [prediction, setPrediction] = useState<AiPrediction | null>(null);
  const [threats, setThreats] = useState<ThreatProfile[]>([]);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const pred = await fetchAi<AiPrediction>('/api/ai/predict');
      const thr = await fetchAi<ThreatProfile[]>('/api/threats');
      if (!cancelled) {
        if (pred) setPrediction(pred);
        if (thr) setThreats(thr);
      }
      if (!cancelled) setTimeout(poll, 2000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  const modelOnline = prediction !== null && prediction.frame_count > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">AI Detection Engine</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Real-time ONNX ML classifier + composite threat scoring.
          </p>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-medium border ${
          modelOnline
            ? 'bg-green-500/10 text-green-400 border-green-500/20'
            : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
        }`}>
          {modelOnline ? 'Model Online' : 'Model Offline'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4" delay={0.02}>
          <div className="flex items-center gap-2 mb-2">
            <BrainCircuit size={14} className="text-[var(--color-accent-blue)]" />
            <p className="text-xs text-[var(--color-text-muted)] uppercase">Current Prediction</p>
          </div>
          <p className={`text-lg font-bold ${prediction?.label === 'Normal' ? 'text-[var(--color-accent-green)]' : 'text-[var(--color-accent-danger)]'}`}>
            {prediction?.label || 'Waiting...'}
          </p>
        </Card>
        <Card className="p-4" delay={0.04}>
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp size={14} className="text-[var(--color-accent-green)]" />
            <p className="text-xs text-[var(--color-text-muted)] uppercase">Confidence</p>
          </div>
          <p className="text-lg font-bold data-mono">
            {prediction ? `${(prediction.confidence * 100).toFixed(1)}%` : '—'}
          </p>
        </Card>
        <Card className="p-4" delay={0.06}>
          <div className="flex items-center gap-2 mb-2">
            <Clock size={14} className="text-[var(--color-accent-warning)]" />
            <p className="text-xs text-[var(--color-text-muted)] uppercase">Inference Time</p>
          </div>
          <p className="text-lg font-bold data-mono">
            {prediction ? `${prediction.inference_ms.toFixed(3)} ms` : '—'}
          </p>
        </Card>
        <Card className="p-4" delay={0.08}>
          <div className="flex items-center gap-2 mb-2">
            <Activity size={14} className="text-[var(--color-accent-blue)]" />
            <p className="text-xs text-[var(--color-text-muted)] uppercase">Frames/Window</p>
          </div>
          <p className="text-lg font-bold data-mono">{prediction?.frame_count || 0}</p>
        </Card>
      </div>

      {threats.length > 0 && (
        <Card className="p-5" delay={0.10}>
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck size={16} className="text-[var(--color-accent-danger)]" />
            <h3 className="text-sm font-semibold">Active Threat Profiles ({threats.length})</h3>
          </div>
          <div className="space-y-3">
            {threats.map((t) => (
              <div key={t.bssid} className="p-4 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="text-sm font-medium">{t.ssid || '<Unknown SSID>'}</p>
                    <p className="text-xs data-mono text-[var(--color-accent-blue)]">{t.bssid}</p>
                  </div>
                  <div className="text-right">
                    <p className={`text-lg font-bold data-mono ${
                      t.score >= 85 ? 'text-[var(--color-accent-danger)]' :
                      t.score >= 60 ? 'text-[var(--color-accent-warning)]' :
                      'text-[var(--color-text-secondary)]'
                    }`}>{t.score.toFixed(0)}/100</p>
                    <p className="text-[10px] text-[var(--color-text-muted)]">{t.verdict}</p>
                  </div>
                </div>
                <div className="w-full h-2 rounded-full bg-[var(--color-border)] overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      t.score >= 85 ? 'bg-[var(--color-accent-danger)]' :
                      t.score >= 60 ? 'bg-[var(--color-accent-warning)]' :
                      'bg-[var(--color-accent-blue)]'
                    }`}
                    style={{ width: `${Math.min(t.score, 100)}%` }}
                  />
                </div>
                {t.evidence.length > 0 && (
                  <div className="mt-3 space-y-1">
                    {t.evidence.slice(-3).map((e, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px] text-[var(--color-text-muted)]">
                        <span className="px-1.5 py-0.5 rounded bg-[var(--color-card)] text-[10px] font-medium">{e.source}</span>
                        <span className="truncate">{e.description}</span>
                        <span className="ml-auto shrink-0 data-mono text-[var(--color-accent-warning)]">+{e.weight.toFixed(0)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="p-5" delay={0.14}>
        <div className="flex items-center gap-2 mb-3">
          <Cpu size={16} className="text-[var(--color-accent-blue)]" />
          <h3 className="text-sm font-semibold">Model Information</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Architecture</p>
            <p className="text-[var(--color-text-muted)] mt-1">Random Forest (30 trees, depth 10) exported to ONNX. NLP-inspired TF-IDF n-gram tokenization.</p>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Classes (6)</p>
            <p className="text-[var(--color-text-muted)] mt-1">Normal, Deauth_Flood, Auth_Flood, Evil_Twin, Krack, Kr00k</p>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Performance</p>
            <p className="text-[var(--color-text-muted)] mt-1">99.55% accuracy, 0.001ms inference (ONNX), 120 features (20 stats + 100 TF-IDF)</p>
          </div>
        </div>
      </Card>

      <Card className="p-5" delay={0.16}>
        <div className="flex items-center gap-2 mb-3">
          <Layers size={16} className="text-[var(--color-accent-green)]" />
          <h3 className="text-sm font-semibold">Detection Layers (3-tier fusion)</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Layer 1: Rule-Based</p>
            <p className="text-[var(--color-text-muted)] mt-1">7 detectors (Deauth flood, Rogue AP, Karma, Seq anomaly, Probe flood, Beacon flood, Auth flood)</p>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Layer 2: ML Classification</p>
            <p className="text-[var(--color-text-muted)] mt-1">ONNX Random Forest with NLP frame tokenization. 1-second inference windows.</p>
          </div>
          <div className="p-3 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-text)]">Layer 3: Composite Scoring</p>
            <p className="text-[var(--color-text-muted)] mt-1">Per-BSSID evidence accumulation with time-decay. Fuses all layers into 0-100 threat score.</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
