import {
  Activity,
  Wifi,
  Users,
  Gauge,
  BrainCircuit,
  Cpu,
  MemoryStick,
  Thermometer,
  ShieldCheck,
  Radio,
} from 'lucide-react';
import StatCard from '../components/common/StatCard';
import Card from '../components/common/Card';
import { useSystemStatus } from '../hooks/useMockLiveData';

export default function Overview() {
  const status = useSystemStatus();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">System Overview</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Live status of the monitoring interface, detection engine, and host device.
        </p>
      </div>

      {/* Monitoring status banner */}
      <Card className="p-4 flex items-center justify-between flex-wrap gap-3" delay={0.02}>
        <div className="flex items-center gap-3">
          <span className="relative flex items-center justify-center w-3 h-3">
            <span className="absolute inline-flex w-full h-full rounded-full bg-[var(--color-accent-green)] pulse-ring" />
            <span className="relative inline-flex w-2.5 h-2.5 rounded-full bg-[var(--color-accent-green)]" />
          </span>
          <div>
            <p className="text-sm font-medium">
              Monitoring {status.monitoringActive ? 'Active' : 'Stopped'} on{' '}
              <span className="data-mono text-[var(--color-accent-blue)]">{status.interfaceName}</span>
            </p>
            <p className="text-xs text-[var(--color-text-muted)]">
              Channel hopper cycling 1–11 · Detection engine: {status.detectionEngineStatus}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
          <Radio size={14} className="text-[var(--color-accent-blue)]" />
          Current channel
          <span className="data-mono text-[var(--color-text)] font-semibold text-base">{status.currentChannel}</span>
        </div>
      </Card>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        <StatCard icon={Wifi} label="Nearby Access Points" value={status.nearbyApCount} tone="blue" delay={0.03} />
        <StatCard icon={Users} label="Connected Stations" value={status.connectedStationCount} tone="green" delay={0.06} />
        <StatCard icon={Activity} label="Packets / sec" value={status.packetsPerSecond} tone="default" delay={0.09} />
        <StatCard
          icon={BrainCircuit}
          label="AI Model Status"
          value={status.aiModelStatus === 'Online' ? 1 : 0}
          decimals={0}
          suffix=""
          tone={status.aiModelStatus === 'Online' ? 'green' : 'danger'}
          subtext={status.aiModelStatus}
          delay={0.12}
        />
        <StatCard icon={Cpu} label="CPU Usage" value={status.cpuUsagePct} suffix="%" tone="blue" delay={0.15} />
        <StatCard icon={MemoryStick} label="Memory Usage" value={status.memoryUsagePct} suffix="%" tone="blue" delay={0.18} />
        <StatCard
          icon={Thermometer}
          label="Pi Temperature"
          value={status.piTemperatureC}
          suffix="°C"
          tone={status.piTemperatureC > 75 ? 'danger' : status.piTemperatureC > 65 ? 'warning' : 'default'}
          delay={0.21}
        />
        <StatCard
          icon={ShieldCheck}
          label="Detection Engine"
          value={status.detectionEngineStatus === 'Running' ? 1 : 0}
          subtext={status.detectionEngineStatus}
          tone={status.detectionEngineStatus === 'Running' ? 'green' : 'warning'}
          delay={0.24}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.27}>
          <div className="flex items-center gap-2 mb-3">
            <Gauge size={16} className="text-[var(--color-accent-blue)]" />
            <h3 className="text-sm font-semibold">Interface Snapshot</h3>
          </div>
          <dl className="grid grid-cols-2 gap-y-3 text-sm">
            <dt className="text-[var(--color-text-secondary)]">Interface</dt>
            <dd className="data-mono text-right">{status.interfaceName}</dd>
            <dt className="text-[var(--color-text-secondary)]">Mode</dt>
            <dd className="data-mono text-right">Monitor</dd>
            <dt className="text-[var(--color-text-secondary)]">Current channel</dt>
            <dd className="data-mono text-right">{status.currentChannel}</dd>
            <dt className="text-[var(--color-text-secondary)]">Hop interval</dt>
            <dd className="data-mono text-right">300 ms</dd>
          </dl>
        </Card>

        <Card className="p-5" delay={0.3}>
          <div className="flex items-center gap-2 mb-3">
            <BrainCircuit size={16} className="text-[var(--color-accent-blue)]" />
            <h3 className="text-sm font-semibold">AI Engine Snapshot</h3>
          </div>
          <dl className="grid grid-cols-2 gap-y-3 text-sm">
            <dt className="text-[var(--color-text-secondary)]">Model</dt>
            <dd className="data-mono text-right">widps-rf-v2</dd>
            <dt className="text-[var(--color-text-secondary)]">Version</dt>
            <dd className="data-mono text-right">2.1.0</dd>
            <dt className="text-[var(--color-text-secondary)]">Status</dt>
            <dd className="text-right text-[var(--color-accent-green)] font-medium">{status.aiModelStatus}</dd>
            <dt className="text-[var(--color-text-secondary)]">Avg. inference time</dt>
            <dd className="data-mono text-right">4.2 ms</dd>
          </dl>
        </Card>
      </div>
    </div>
  );
}
