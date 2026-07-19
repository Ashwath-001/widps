import type {
  AccessPoint,
  AiPrediction,
  AlertItem,
  AttackDistribution,
  ChannelUtilization,
  FrameTypeRadarPoint,
  LiveFeedItem,
  LogEntry,
  SignalBucket,
  SystemStatus,
  ThreatEvent,
  ThreatsOverTimePoint,
  TopChannelStat,
  TopologyLink,
  TopologyNode,
  TrafficPoint,
} from '../types';

export const systemStatus: SystemStatus = {
  monitoringActive: true,
  interfaceName: 'wlan1mon',
  currentChannel: 1,
  nearbyApCount: 0,
  connectedStationCount: 0,
  packetsPerSecond: 0,
  aiModelStatus: 'Offline (MVP Roadmap)',
  cpuUsagePct: 15,
  memoryUsagePct: 32,
  piTemperatureC: 45,
  detectionEngineStatus: 'Running',
};

export const accessPoints: AccessPoint[] = [];

export function generateTrafficHistory(points = 30): TrafficPoint[] {
  const now = Date.now();
  return Array.from({ length: points }, (_, i) => {
    const t = new Date(now - (points - i) * 1000);
    return {
      t: t.toLocaleTimeString('en-GB'),
      beacon: 0,
      probeRequest: 0,
      auth: 0,
      assoc: 0,
      disassoc: 0,
      deauth: 0,
      packetRate: 0,
    };
  });
}

export const channelUtilization: ChannelUtilization[] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((ch) => ({
  channel: ch,
  utilizationPct: 0,
}));

export const signalDistribution: SignalBucket[] = [
  { range: '-30 to -40 dBm', count: 0 },
  { range: '-41 to -50 dBm', count: 0 },
  { range: '-51 to -60 dBm', count: 0 },
  { range: '-61 to -70 dBm', count: 0 },
  { range: '-71 to -80 dBm', count: 0 },
  { range: '-81 to -90 dBm', count: 0 },
];

export const aiPrediction: AiPrediction = {
  label: 'Normal Traffic',
  confidencePct: 100,
  threatScore: 0,
  inferenceTimeMs: 0,
  modelName: 'widps-rf-v2 (MVP Roadmap)',
  modelVersion: '2.1.0',
  featureCount: 27,
  probabilities: [
    { label: 'Normal', pct: 100 },
    { label: 'Beacon Flood', pct: 0 },
    { label: 'Probe Flood', pct: 0 },
    { label: 'Authentication Flood', pct: 0 },
    { label: 'Deauthentication Attack', pct: 0 },
  ],
};

export const threatEvents: ThreatEvent[] = [];

export const eventLog: LogEntry[] = [];

export const alerts: AlertItem[] = [];

export const liveFeed: LiveFeedItem[] = [];

export const attackDistribution: AttackDistribution[] = [];

export function generateThreatsOverTime(points = 24): ThreatsOverTimePoint[] {
  return Array.from({ length: points }, (_, i) => ({
    t: `${String(i).padStart(2, '0')}:00`,
    count: 0,
  }));
}

export const topChannels: TopChannelStat[] = [];

export const frameTypeRadar: FrameTypeRadarPoint[] = [];

export const topologyNodes: TopologyNode[] = [];

export const topologyLinks: TopologyLink[] = [];
