import { motion } from 'framer-motion';
import { BrainCircuit, Zap, Target, Layers } from 'lucide-react';
import Card from '../components/common/Card';
import CircularProgress from '../components/common/CircularProgress';
import AnimatedNumber from '../components/common/AnimatedNumber';
import { aiPrediction } from '../data/mockData';

function severityColor(pct: number) {
  if (pct >= 70) return 'var(--color-accent-danger)';
  if (pct >= 30) return 'var(--color-accent-warning)';
  return 'var(--color-accent-green)';
}

export default function AIDetection() {
  const p = aiPrediction;
  const ringColor = severityColor(p.confidencePct);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">AI Detection</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Real-time classifier output from the on-device inference engine.
        </p>
      </div>

      <Card className="p-6 lg:p-8" delay={0.03}>
        <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-8 items-center">
          <div className="flex justify-center">
            <CircularProgress value={p.confidencePct} color={ringColor} label="AI Confidence" size={190} />
          </div>

          <div>
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide mb-1">Current Prediction</p>
            <motion.h2
              key={p.label}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-2xl font-bold mb-4"
              style={{ color: ringColor }}
            >
              {p.label}
            </motion.h2>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <MetricTile icon={Target} label="Threat Score" value={p.threatScore} suffix="/100" />
              <MetricTile icon={Zap} label="Inference Time" value={p.inferenceTimeMs} decimals={1} suffix=" ms" />
              <MetricTile icon={BrainCircuit} label="Model" valueLabel={p.modelName} />
              <MetricTile icon={Layers} label="Features" value={p.featureCount} />
            </div>
          </div>
        </div>
      </Card>

      <Card className="p-6" delay={0.06}>
        <h3 className="text-sm font-semibold mb-5">Class Probabilities</h3>
        <div className="space-y-4">
          {p.probabilities.map((prob, i) => {
            const color = severityColor(prob.pct);
            return (
              <div key={prob.label}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm">{prob.label}</span>
                  <span className="data-mono text-sm font-medium" style={{ color }}>
                    <AnimatedNumber value={prob.pct} suffix="%" />
                  </span>
                </div>
                <div className="h-2 rounded-full bg-[var(--color-border)] overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${prob.pct}%` }}
                    transition={{ duration: 0.8, delay: 0.1 + i * 0.05, ease: 'easeOut' }}
                    className="h-full rounded-full"
                    style={{ backgroundColor: color }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card className="p-5" delay={0.09}>
        <h3 className="text-sm font-semibold mb-3">Model Info</h3>
        <dl className="grid grid-cols-2 sm:grid-cols-4 gap-y-3 text-sm">
          <dt className="text-[var(--color-text-secondary)]">Model name</dt>
          <dd className="data-mono text-right sm:text-left">{p.modelName}</dd>
          <dt className="text-[var(--color-text-secondary)]">Version</dt>
          <dd className="data-mono text-right sm:text-left">{p.modelVersion}</dd>
          <dt className="text-[var(--color-text-secondary)]">Feature count</dt>
          <dd className="data-mono text-right sm:text-left">{p.featureCount}</dd>
          <dt className="text-[var(--color-text-secondary)]">Inference time</dt>
          <dd className="data-mono text-right sm:text-left">{p.inferenceTimeMs} ms</dd>
        </dl>
      </Card>
    </div>
  );
}

interface MetricTileProps {
  icon: typeof Target;
  label: string;
  value?: number;
  decimals?: number;
  suffix?: string;
  valueLabel?: string;
}

function MetricTile({ icon: Icon, label, value, decimals = 0, suffix = '', valueLabel }: MetricTileProps) {
  return (
    <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
      <Icon size={14} className="text-[var(--color-accent-blue)] mb-2" />
      <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wide">{label}</p>
      <p className="data-mono text-sm font-semibold mt-0.5">
        {valueLabel ?? <AnimatedNumber value={value ?? 0} decimals={decimals} suffix={suffix} />}
      </p>
    </div>
  );
}
