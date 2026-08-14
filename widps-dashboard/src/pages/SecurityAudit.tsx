import { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Lock, FileCheck, RefreshCw, Server } from 'lucide-react';
import Card from '../components/common/Card';

interface AuditResult {
  total_signed_alerts: number;
  valid: number;
  tampered: number;
  integrity_status: 'CLEAN' | 'TAMPERED';
}

interface SiemStatus {
  enabled: boolean;
  target_host: string;
  target_port: string;
  format: string;
  protocol: string;
}

async function fetchAudit(): Promise<AuditResult | null> {
  try {
    const res = await fetch('/api/audit/integrity');
    if (res.ok) return res.json();
  } catch { /* fallback */ }
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/audit/integrity`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return null;
}

async function fetchSiem(): Promise<SiemStatus | null> {
  try {
    const res = await fetch('/api/siem/status');
    if (res.ok) return res.json();
  } catch { /* fallback */ }
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/siem/status`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return null;
}

export default function SecurityAudit() {
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [siem, setSiem] = useState<SiemStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastCheck, setLastCheck] = useState<string>('');

  const runAudit = async () => {
    setLoading(true);
    const [a, s] = await Promise.all([fetchAudit(), fetchSiem()]);
    if (a) setAudit(a);
    if (s) setSiem(s);
    setLastCheck(new Date().toLocaleTimeString('en-GB'));
    setLoading(false);
  };

  useEffect(() => { runAudit(); }, []);

  const isClean = audit?.integrity_status === 'CLEAN';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Lock size={20} className="text-[var(--color-accent-green)]" />
            Security & Audit
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Alert integrity verification, SIEM forwarding status, and system security.
          </p>
        </div>
        <button
          onClick={runAudit}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-[var(--color-accent-blue)] text-white text-xs font-medium flex items-center gap-2 hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          {loading ? 'Checking...' : 'Run Audit'}
        </button>
      </div>

      {/* Integrity Status */}
      <Card className={`p-6 border-2 ${isClean ? 'border-green-500/30' : 'border-red-500/30'}`} delay={0.02}>
        <div className="flex items-center gap-4">
          {isClean ? (
            <ShieldCheck size={48} className="text-green-400" />
          ) : (
            <ShieldAlert size={48} className="text-red-400" />
          )}
          <div>
            <h2 className={`text-xl font-bold ${isClean ? 'text-green-400' : 'text-red-400'}`}>
              {audit ? (isClean ? 'INTEGRITY VERIFIED' : '⚠ TAMPERING DETECTED') : 'Awaiting Audit'}
            </h2>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">
              {audit
                ? `${audit.total_signed_alerts} signed alerts verified. ${audit.valid} valid, ${audit.tampered} tampered.`
                : 'Click "Run Audit" to verify all stored alert signatures.'
              }
            </p>
            {lastCheck && (
              <p className="text-xs text-[var(--color-text-muted)] mt-1">Last checked: {lastCheck}</p>
            )}
          </div>
        </div>
      </Card>

      {/* Audit Stats */}
      {audit && (
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <Card className="p-4 text-center" delay={0.04}>
            <FileCheck size={20} className="mx-auto text-[var(--color-accent-blue)] mb-2" />
            <p className="text-2xl font-bold data-mono">{audit.total_signed_alerts}</p>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Total Signed</p>
          </Card>
          <Card className="p-4 text-center" delay={0.06}>
            <ShieldCheck size={20} className="mx-auto text-green-400 mb-2" />
            <p className="text-2xl font-bold data-mono text-green-400">{audit.valid}</p>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Valid (Untampered)</p>
          </Card>
          <Card className="p-4 text-center" delay={0.08}>
            <ShieldAlert size={20} className="mx-auto text-red-400 mb-2" />
            <p className="text-2xl font-bold data-mono text-red-400">{audit.tampered}</p>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Tampered</p>
          </Card>
          <Card className="p-4 text-center" delay={0.10}>
            <Lock size={20} className="mx-auto text-[var(--color-accent-warning)] mb-2" />
            <p className="text-2xl font-bold data-mono">HMAC-SHA256</p>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Signing Algorithm</p>
          </Card>
        </div>
      )}

      {/* HMAC Explanation */}
      <Card className="p-5" delay={0.12}>
        <h3 className="text-sm font-semibold mb-3">How Alert Signing Works</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-blue)]">1. Sign on Create</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              Every alert is signed with HMAC-SHA256(time | severity | title | detail) using a server-side secret key before storage.
            </p>
          </div>
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-green)]">2. Store Signature</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              The 64-character hex signature is stored alongside the alert in SQLite and the JSONL backup file.
            </p>
          </div>
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-warning)]">3. Verify on Audit</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              Recomputes HMAC for each stored alert and compares. If the alert text was modified, the signature won't match → tampered.
            </p>
          </div>
        </div>
      </Card>

      {/* SIEM Status */}
      <Card className="p-5" delay={0.14}>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Server size={14} className="text-[var(--color-accent-blue)]" />
          SIEM Integration (Wazuh)
        </h3>
        {siem ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Status</p>
              <p className={`text-sm font-bold mt-1 ${siem.enabled ? 'text-green-400' : 'text-[var(--color-text-muted)]'}`}>
                {siem.enabled ? 'ACTIVE' : 'DISABLED'}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Target</p>
              <p className="text-sm font-mono mt-1">{siem.target_host}:{siem.target_port}</p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Protocol</p>
              <p className="text-sm font-bold mt-1">{siem.protocol}</p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Format</p>
              <p className="text-sm font-bold mt-1 uppercase">{siem.format}</p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Enable</p>
              <p className="text-[10px] text-[var(--color-text-muted)] mt-1 font-mono">WIDPS_SIEM_ENABLED=1</p>
            </div>
          </div>
        ) : (
          <p className="text-xs text-[var(--color-text-muted)]">Unable to reach backend for SIEM status.</p>
        )}
      </Card>
    </div>
  );
}
