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
    const spike = i > points - 6; // deauth spike near the end for visual interest
    return {
      t: t.toLocaleTimeString('en-GB'),
      beacon: 60 + Math.round(Math.sin(i / 3) * 8 + Math.random() * 6),
      probeRequest: 20 + Math.round(Math.random() * 10),
      auth: 4 + Math.round(Math.random() * 3),
      assoc: 3 + Math.round(Math.random() * 3),
      disassoc: spike ? 8 + Math.round(Math.random() * 6) : Math.round(Math.random() * 2),
      deauth: spike ? 25 + Math.round(Math.random() * 40) : Math.round(Math.random() * 2),
      packetRate: 700 + Math.round(Math.sin(i / 4) * 120 + Math.random() * 80) + (spike ? 300 : 0),
    };
  });
}

export const channelUtilization: ChannelUtilization[] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((ch) => ({
  channel: ch,
  utilizationPct: ch === 6 ? 78 : ch === 11 ? 52 : Math.round(10 + Math.random() * 35),
}));

export const signalDistribution: SignalBucket[] = [
  { range: '-30 to -40', count: 3 },
  { range: '-40 to -50', count: 5 },
  { range: '-50 to -60', count: 6 },
  { range: '-60 to -70', count: 4 },
  { range: '-70 to -80', count: 2 },
  { range: '-80 to -90', count: 1 },
];

export const aiPrediction: AiPrediction = {
  label: 'Deauthentication Attack',
  confidencePct: 90,
  threatScore: 93,
  inferenceTimeMs: 4.2,
  modelName: 'widps-rf-v2',
  modelVersion: '2.1.0',
  featureCount: 27,
  probabilities: [
    { label: 'Normal', pct: 4 },
    { label: 'Beacon Flood', pct: 2 },
    { label: 'Probe Flood', pct: 1 },
    { label: 'Authentication Flood', pct: 3 },
    { label: 'Deauthentication Attack', pct: 90 },
  ],
};

export const threatEvents: ThreatEvent[] = [
  { id: 'th-1', attackName: 'Deauthentication Flood', severity: 'Critical', targetMac: 'D8:BB:2C:11:22:33', attackerMac: '24:0A:C4:11:9B:3D', ssid: 'CollegeWiFi', channel: 6, detectedAt: '12:41:07', aiConfidencePct: 96, status: 'Active' },
  { id: 'th-2', attackName: 'Rogue AP / Evil Twin', severity: 'High', targetMac: '—', attackerMac: '24:0A:C4:11:9B:3D', ssid: 'CollegeWiFi', channel: 6, detectedAt: '12:38:44', aiConfidencePct: 88, status: 'Investigating' },
  { id: 'th-3', attackName: 'Karma Attack', severity: 'Medium', targetMac: '9E:12:88:AA:BB:01', attackerMac: '3C:71:BF:44:21:98', ssid: 'FreeCollegeWiFi', channel: 6, detectedAt: '11:58:19', aiConfidencePct: 74, status: 'Mitigated' },
  { id: 'th-4', attackName: 'Beacon Flood', severity: 'Low', targetMac: '—', attackerMac: '18:FE:34:AA:11:02', ssid: '(multiple)', channel: 11, detectedAt: '10:22:51', aiConfidencePct: 61, status: 'Ignored' },
];

export const eventLog: LogEntry[] = [];

export const alerts: AlertItem[] = [];

export const liveFeed: LiveFeedItem[] = [];

export const attackDistribution: AttackDistribution[] = [
  { name: 'Deauth Flood', value: 42, color: '#EF4444' },
  { name: 'Evil Twin', value: 21, color: '#FACC15' },
  { name: 'Karma Attack', value: 14, color: '#3B82F6' },
  { name: 'Beacon Flood', value: 13, color: '#22C55E' },
  { name: 'Probe Flood', value: 10, color: '#94A3B8' },
];

export function generateThreatsOverTime(points = 24): ThreatsOverTimePoint[] {
  return Array.from({ length: points }, (_, i) => ({
    t: `${String(i).padStart(2, '0')}:00`,
    count: Math.round(2 + Math.random() * 6 + (i > 18 ? 6 : 0)),
  }));
}

export const topChannels: TopChannelStat[] = [
  { channel: 6, attackCount: 18 },
  { channel: 11, attackCount: 9 },
  { channel: 1, attackCount: 5 },
  { channel: 44, attackCount: 3 },
  { channel: 9, attackCount: 2 },
];

export const frameTypeRadar: FrameTypeRadarPoint[] = [
  { frameType: 'Beacon', value: 82, fullMark: 100 },
  { frameType: 'Probe Req', value: 54, fullMark: 100 },
  { frameType: 'Auth', value: 30, fullMark: 100 },
  { frameType: 'Assoc', value: 25, fullMark: 100 },
  { frameType: 'Disassoc', value: 40, fullMark: 100 },
  { frameType: 'Deauth', value: 88, fullMark: 100 },
];

export const topologyNodes: TopologyNode[] = [
  { id: 'ap-main', label: 'CollegeWiFi (AP)', kind: 'ap', mac: 'AA:BB:CC:DD:EE:FF', x: 400, y: 60 },
  { id: 'client-1', label: 'Client — Laptop', kind: 'client', mac: 'D8:BB:2C:11:22:33', x: 220, y: 200 },
  { id: 'client-2', label: 'Client — Phone', kind: 'client', mac: 'F4:5E:AB:90:10:22', x: 400, y: 220 },
  { id: 'client-3', label: 'Client — Tablet', kind: 'client', mac: '9E:12:88:AA:BB:01', x: 580, y: 200 },
  { id: 'suspicious-1', label: 'Suspicious Probe Source', kind: 'suspicious', mac: '3C:71:BF:44:21:98', x: 580, y: 340 },
  { id: 'attacker-1', label: 'Evil Twin AP', kind: 'attacker', mac: '24:0A:C4:11:9B:3D', x: 220, y: 360 },
];

export const topologyLinks: TopologyLink[] = [
  { source: 'ap-main', target: 'client-1' },
  { source: 'ap-main', target: 'client-2' },
  { source: 'ap-main', target: 'client-3' },
  { source: 'client-3', target: 'suspicious-1', suspicious: true },
  { source: 'client-1', target: 'attacker-1', suspicious: true },
];
