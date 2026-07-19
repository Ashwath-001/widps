// ---------------------------------------------------------------------------
// Core domain types for the WIDPS dashboard.
// These mirror what the Rust backend will eventually emit over Tauri events
// / a WebSocket bridge. Keep this file in sync with the Rust-side structs
// (serde-derived) so the payloads deserialize into these shapes untouched.
// ---------------------------------------------------------------------------

export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ApStatus = 'Normal' | 'Suspicious' | 'Malicious';

export type Severity = 'Low' | 'Medium' | 'High' | 'Critical';

export type AttackStatus = 'Active' | 'Investigating' | 'Mitigated' | 'Ignored';

export interface SystemStatus {
  monitoringActive: boolean;
  interfaceName: string;
  currentChannel: number;
  nearbyApCount: number;
  connectedStationCount: number;
  packetsPerSecond: number;
  aiModelStatus: 'Online' | 'Loading' | 'Offline';
  cpuUsagePct: number;
  memoryUsagePct: number;
  piTemperatureC: number;
  detectionEngineStatus: 'Running' | 'Paused' | 'Error';
}

export interface AccessPoint {
  id: string;
  ssid: string;
  bssid: string;
  channel: number;
  rssi: number;
  vendor: string;
  encryption: string;
  beaconIntervalMs: number;
  clientCount: number;
  status: ApStatus;
  firstSeen: string;
  lastSeen: string;
}

export interface TrafficPoint {
  t: string; // HH:MM:SS
  beacon: number;
  probeRequest: number;
  auth: number;
  assoc: number;
  disassoc: number;
  deauth: number;
  packetRate: number;
}

export interface ChannelUtilization {
  channel: number;
  utilizationPct: number;
}

export interface SignalBucket {
  range: string; // e.g. "-30 to -40"
  count: number;
}

export interface AiPrediction {
  label: string;
  confidencePct: number;
  threatScore: number; // 0-100
  inferenceTimeMs: number;
  modelName: string;
  modelVersion: string;
  featureCount: number;
  probabilities: { label: string; pct: number }[];
}

export interface ThreatEvent {
  id: string;
  attackName: string;
  severity: Severity;
  targetMac: string;
  attackerMac: string;
  ssid: string;
  channel: number;
  detectedAt: string;
  aiConfidencePct: number;
  status: AttackStatus;
}

export interface LogEntry {
  id: string;
  time: string;
  attack: string;
  severity: Severity;
  prediction: string;
  confidencePct: number;
  actionTaken: string;
  status: AttackStatus;
}

export interface AlertItem {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  time: string;
  read: boolean;
}

export interface LiveFeedItem {
  id: string;
  time: string;
  message: string;
  tone: 'info' | 'warning' | 'danger' | 'success';
}

export interface AttackDistribution {
  name: string;
  value: number;
  color: string;
}

export interface ThreatsOverTimePoint {
  t: string;
  count: number;
}

export interface TopChannelStat {
  channel: number;
  attackCount: number;
}

export interface FrameTypeRadarPoint {
  frameType: string;
  value: number;
  fullMark: number;
}

export type NodeKind = 'ap' | 'client' | 'suspicious' | 'attacker';

export interface TopologyNode {
  id: string;
  label: string;
  kind: NodeKind;
  mac: string;
  x: number;
  y: number;
}

export interface TopologyLink {
  source: string;
  target: string;
  suspicious?: boolean;
}
