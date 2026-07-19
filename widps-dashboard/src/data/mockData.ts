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
  currentChannel: 6,
  nearbyApCount: 14,
  connectedStationCount: 37,
  packetsPerSecond: 842,
  aiModelStatus: 'Online',
  cpuUsagePct: 46,
  memoryUsagePct: 61,
  piTemperatureC: 58,
  detectionEngineStatus: 'Running',
};

export const accessPoints: AccessPoint[] = [
  { id: 'ap-1', ssid: 'CollegeWiFi', bssid: 'AA:BB:CC:DD:EE:FF', channel: 6, rssi: -31, vendor: 'Cisco Systems', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 22, status: 'Normal', firstSeen: '08:02:11', lastSeen: '12:41:02' },
  { id: 'ap-2', ssid: 'CollegeWiFi', bssid: '24:0A:C4:11:9B:3D', channel: 6, rssi: -84, vendor: 'Espressif Inc.', encryption: 'Open', beaconIntervalMs: 100, clientCount: 0, status: 'Malicious', firstSeen: '12:38:44', lastSeen: '12:41:09' },
  { id: 'ap-3', ssid: 'CollegeWiFi-5G', bssid: 'AA:BB:CC:DD:EE:00', channel: 44, rssi: -42, vendor: 'Cisco Systems', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 15, status: 'Normal', firstSeen: '08:02:12', lastSeen: '12:41:05' },
  { id: 'ap-4', ssid: 'Hostel_Block_C', bssid: '5C:F9:38:22:AB:10', channel: 11, rssi: -55, vendor: 'TP-Link', encryption: 'WPA2-PSK', beaconIntervalMs: 100, clientCount: 9, status: 'Normal', firstSeen: '08:00:00', lastSeen: '12:40:58' },
  { id: 'ap-5', ssid: 'eduroam', bssid: '00:1A:2B:3C:4D:5E', channel: 1, rssi: -47, vendor: 'Aruba Networks', encryption: 'WPA2-Enterprise', beaconIntervalMs: 100, clientCount: 18, status: 'Normal', firstSeen: '08:00:03', lastSeen: '12:41:00' },
  { id: 'ap-6', ssid: 'DIRECT-4F-HPPrinter', bssid: '9C:8E:99:AA:12:34', channel: 3, rssi: -70, vendor: 'HP Inc.', encryption: 'WPA2-PSK', beaconIntervalMs: 100, clientCount: 0, status: 'Normal', firstSeen: '09:14:21', lastSeen: '12:35:40' },
  { id: 'ap-7', ssid: 'FreeCollegeWiFi', bssid: '3C:71:BF:44:21:98', channel: 6, rssi: -38, vendor: 'Espressif Inc.', encryption: 'Open', beaconIntervalMs: 100, clientCount: 3, status: 'Suspicious', firstSeen: '11:58:02', lastSeen: '12:41:01' },
  { id: 'ap-8', ssid: 'Lab304_IoT', bssid: 'B8:27:EB:77:2C:19', channel: 9, rssi: -60, vendor: 'Raspberry Pi Foundation', encryption: 'WPA2-PSK', beaconIntervalMs: 100, clientCount: 4, status: 'Normal', firstSeen: '08:05:55', lastSeen: '12:39:12' },
];

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

export const eventLog: LogEntry[] = [
  { id: 'log-1', time: '12:41:07', attack: 'Deauthentication Flood', severity: 'Critical', prediction: 'Deauthentication Attack', confidencePct: 96, actionTaken: 'Alert raised', status: 'Active' },
  { id: 'log-2', time: '12:38:44', attack: 'Rogue AP / Evil Twin', severity: 'High', prediction: 'Evil Twin', confidencePct: 88, actionTaken: 'Flagged for review', status: 'Investigating' },
  { id: 'log-3', time: '11:58:19', attack: 'Karma Attack', severity: 'Medium', prediction: 'Karma AP', confidencePct: 74, actionTaken: 'Client warned', status: 'Mitigated' },
  { id: 'log-4', time: '10:22:51', attack: 'Beacon Flood', severity: 'Low', prediction: 'Beacon Flood', confidencePct: 61, actionTaken: 'Logged only', status: 'Ignored' },
  { id: 'log-5', time: '09:47:03', attack: 'Probe Flood', severity: 'Low', prediction: 'Probe Flood', confidencePct: 55, actionTaken: 'Logged only', status: 'Mitigated' },
  { id: 'log-6', time: '08:31:40', attack: 'Deauthentication Flood', severity: 'High', prediction: 'Deauthentication Attack', confidencePct: 91, actionTaken: 'Alert raised', status: 'Mitigated' },
];

export const alerts: AlertItem[] = [
  { id: 'al-1', severity: 'Critical', title: 'Deauthentication Flood', detail: '40+ deauth frames/sec targeting CollegeWiFi clients', time: '12:41:07', read: false },
  { id: 'al-2', severity: 'High', title: 'Evil Twin Detected', detail: 'BSSID 24:0A:C4:11:9B:3D impersonating CollegeWiFi on channel 6', time: '12:38:44', read: false },
  { id: 'al-3', severity: 'Medium', title: 'Karma Attack Suspected', detail: 'FreeCollegeWiFi answering probes for unregistered SSIDs', time: '11:58:19', read: true },
  { id: 'al-4', severity: 'Low', title: 'Beacon Flood', detail: 'Elevated beacon rate observed on channel 11', time: '10:22:51', read: true },
];

export const liveFeed: LiveFeedItem[] = [
  { id: 'lf-1', time: '12:31:04', message: 'Mitigation started', tone: 'success' },
  { id: 'lf-2', time: '12:31:01', message: 'Deauthentication Attack detected', tone: 'danger' },
  { id: 'lf-3', time: '12:30:15', message: 'Threat level raised to HIGH', tone: 'warning' },
  { id: 'lf-4', time: '12:30:07', message: 'AI confidence 98%', tone: 'info' },
  { id: 'lf-5', time: '12:30:02', message: 'Beacon flood detected on channel 11', tone: 'warning' },
];

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
