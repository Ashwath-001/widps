import { useState, useEffect } from 'react';
import { BrainCircuit, Layers, ArrowUp, ArrowDown, Info } from 'lucide-react';
import Card from '../components/common/Card';

interface ShapFeature {
  feature: string;
  shap_value: number;
  feature_value: number;
  contribution_pct: number;
  direction: 'attack' | 'normal';
}

interface ShapRecord {
  timestamp: string;
  prediction_label: string;
  confidence: number;
  top_features: string; // JSON string
  shap_values: string;  // JSON string
}

interface ParsedShap {
  timestamp: string;
  label: string;
  confidence: number;
  features: ShapFeature[];
}

async function fetchShap(): Promise<ParsedShap[]> {
  const tryParse = (raw: ShapRecord[]): ParsedShap[] => raw.map(r => ({
    timestamp: r.timestamp,
    label: r.prediction_label,
    confidence: r.confidence,
    features: (() => { try { return JSON.parse(r.top_features); } catch { return []; } })(),
  }));

  try {
    const res = await fetch('/api/ai/shap');
    if (res.ok) return tryParse(await res.json());
  } catch { /* fallback */ }

  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/ai/shap`);
      if (res.ok) return tryParse(await res.json());
    } catch { /* next */ }
  }
  return [];
}

function FeatureBar({ feature }: { feature: ShapFeature }) {
  const maxWidth = 80;
  const width = Math.min(feature.contribution_pct, 100) * (maxWidth / 100);
  const isAttack = feature.direction === 'attack';

  return (
    <div className="flex items-center gap-2 py-1.5 flex-wrap sm:flex-nowrap">
      <div className="w-full sm:w-[180px] shrink-0 sm:text-right">
        <span className="text-[11px] font-mono text-[var(--color-text-secondary)] truncate block">
          {feature.feature}
        </span>
      </div>
      <div className="flex-1 flex items-center gap-2 w-full min-w-0">
        <div className="flex-1 h-5 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)] relative overflow-hidden">
          <div
            className={`h-full rounded transition-all duration-500 ${
              isAttack ? 'bg-red-500/60' : 'bg-green-500/60'
            }`}
            style={{ width: `${width}%` }}
          />
          <span className="absolute inset-0 flex items-center px-2 text-[10px] font-mono">
            {feature.shap_value > 0 ? '+' : ''}{feature.shap_value.toFixed(4)}
          </span>
        </div>
        <span className="text-[10px] w-12 text-right shrink-0 data-mono text-[var(--color-text-muted)]">
          {feature.contribution_pct.toFixed(1)}%
        </span>
        {isAttack ? (
          <ArrowUp size={12} className="text-red-400 shrink-0" />
        ) : (
          <ArrowDown size={12} className="text-green-400 shrink-0" />
        )}
      </div>
    </div>
  );
}

export default function ShapExplainability() {
  const [explanations, setExplanations] = useState<ParsedShap[]>([]);
  const [selected, setSelected] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const data = await fetchShap();
      if (!cancelled && data.length > 0) setExplanations(data);
      if (!cancelled) setTimeout(poll, 5000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  const current = explanations[selected] || null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Layers size={20} className="text-[var(--color-accent-blue)]" />
          SHAP Explainability
        </h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Understand <em>why</em> the AI classified each prediction. SHAP values show feature contributions.
        </p>
      </div>

      {/* Info banner */}
      <Card className="p-4 flex items-start gap-3" delay={0.02}>
        <Info size={16} className="text-[var(--color-accent-blue)] mt-0.5 shrink-0" />
        <div className="text-xs text-[var(--color-text-secondary)]">
          <p className="font-medium text-[var(--color-text)]">What are SHAP values?</p>
          <p className="mt-1">
            SHAP (SHapley Additive exPlanations) assigns each feature a value showing how much it pushed
            the prediction toward "attack" (red, positive) or "normal" (green, negative).
            Higher absolute value = more influence on the decision.
          </p>
        </div>
      </Card>

      {explanations.length > 0 ? (
        <>
          {/* Prediction selector */}
          <Card className="p-4" delay={0.04}>
            <div className="flex items-center gap-3 flex-wrap">
              <p className="text-xs text-[var(--color-text-muted)]">Recent Predictions:</p>
              <div className="flex gap-2 flex-wrap">
                {explanations.slice(0, 10).map((ex, i) => (
                  <button
                    key={i}
                    onClick={() => setSelected(i)}
                    className={`px-3 py-1.5 rounded text-xs font-medium border transition-all ${
                      selected === i
                        ? 'bg-[var(--color-accent-blue)] text-white border-[var(--color-accent-blue)]'
                        : 'bg-[var(--color-card)] text-[var(--color-text-secondary)] border-[var(--color-border)] hover:border-[var(--color-accent-blue)]'
                    }`}
                  >
                    {ex.label} ({(ex.confidence * 100).toFixed(0)}%)
                  </button>
                ))}
              </div>
            </div>
          </Card>

          {/* Selected explanation */}
          {current && (
            <Card className="p-5" delay={0.06}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <BrainCircuit size={14} className="text-[var(--color-accent-warning)]" />
                    Prediction: <span className="text-[var(--color-accent-danger)]">{current.label}</span>
                  </h3>
                  <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                    Confidence: {(current.confidence * 100).toFixed(1)}% • Time: {current.timestamp}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-[var(--color-text-muted)]">Features shown</p>
                  <p className="text-lg font-bold data-mono">{current.features.length}</p>
                </div>
              </div>

              {/* Feature importance bars */}
              <div className="space-y-0.5">
                <div className="hidden sm:flex items-center gap-2 py-1 mb-2 border-b border-[var(--color-border-soft)]">
                  <div className="w-[180px] shrink-0 text-right text-[10px] font-medium text-[var(--color-text-muted)] uppercase">
                    Feature Name
                  </div>
                  <div className="flex-1 text-[10px] font-medium text-[var(--color-text-muted)] uppercase">
                    SHAP Contribution
                  </div>
                  <span className="text-[10px] w-12 text-right shrink-0 font-medium text-[var(--color-text-muted)] uppercase">%</span>
                  <span className="w-3 shrink-0" />
                </div>
                {current.features.map((feat, i) => (
                  <FeatureBar key={i} feature={feat} />
                ))}
              </div>

              {/* Legend */}
              <div className="mt-4 flex items-center gap-6 text-[10px] text-[var(--color-text-muted)]">
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-red-500/60" /> Pushes toward attack classification
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-green-500/60" /> Pushes toward normal classification
                </span>
              </div>
            </Card>
          )}
        </>
      ) : (
        <Card className="p-8 text-center" delay={0.04}>
          <BrainCircuit size={40} className="mx-auto text-[var(--color-text-muted)] mb-3" />
          <p className="text-sm text-[var(--color-text-secondary)]">No SHAP explanations yet</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            Explanations are generated when the ML model detects an attack with confidence &gt; 50%.
          </p>
        </Card>
      )}
    </div>
  );
}
