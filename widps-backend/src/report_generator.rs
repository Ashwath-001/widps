use crate::db::Database;
use std::sync::{Arc, Mutex};

pub fn generate_incident_report(db: &Database, system_info: &SystemInfo) -> String {
    let alerts = db.get_recent_alerts(500);
    let now = chrono::Local::now();
    let date_str = now.format("%Y-%m-%d").to_string();
    let time_str = now.format("%H:%M:%S").to_string();
    let report_id = format!("WIDPS-IR-{}-{:04X}", now.format("%Y%m%d"), now.timestamp() as u32 & 0xFFFF);

    let critical_count = alerts.iter().filter(|a| a.severity == "Critical").count();
    let high_count = alerts.iter().filter(|a| a.severity == "High").count();
    let medium_count = alerts.iter().filter(|a| a.severity == "Medium").count();
    let total_alerts = alerts.len();

    let risk_level = if critical_count > 0 { "CRITICAL" }
        else if high_count > 0 { "HIGH" }
        else if medium_count > 0 { "MEDIUM" }
        else { "LOW" };

    let risk_color = match risk_level {
        "CRITICAL" => "#dc2626",
        "HIGH" => "#ea580c",
        "MEDIUM" => "#ca8a04",
        _ => "#16a34a",
    };

    // Build alert rows
    let alert_rows: String = alerts.iter().take(60).enumerate().map(|(i, a)| {
        let row_bg = if i % 2 == 0 { "#ffffff" } else { "#f9fafb" };
        let sev_color = match a.severity.as_str() {
            "Critical" => "#dc2626",
            "High" => "#ea580c",
            _ => "#6b7280",
        };
        format!(
            r#"<tr style="background:{}"><td style="padding:6px 8px;border:1px solid #e5e7eb;font-family:monospace;font-size:9pt">{}</td><td style="padding:6px 8px;border:1px solid #e5e7eb;font-weight:600;color:{}">{}</td><td style="padding:6px 8px;border:1px solid #e5e7eb">{}</td></tr>"#,
            row_bg, a.timestamp, sev_color, a.severity, a.title
        )
    }).collect();

    let truncation_note = if total_alerts > 60 {
        format!(r#"<p style="font-size:9pt;color:#6b7280;margin-top:4px;font-style:italic">Displaying 60 of {} total alerts. Full dataset available via /api/alerts endpoint.</p>"#, total_alerts)
    } else {
        String::new()
    };

    // Severity breakdown for the chart-like display
    let severity_breakdown = format!(
        r#"<table style="width:100%;border-collapse:collapse;margin-top:12px">
        <tr><td style="padding:8px;background:#fef2f2;border:1px solid #e5e7eb;width:25%;text-align:center"><span style="font-size:20pt;font-weight:700;color:#dc2626">{}</span><br><span style="font-size:8pt;color:#6b7280">CRITICAL</span></td>
        <td style="padding:8px;background:#fff7ed;border:1px solid #e5e7eb;width:25%;text-align:center"><span style="font-size:20pt;font-weight:700;color:#ea580c">{}</span><br><span style="font-size:8pt;color:#6b7280">HIGH</span></td>
        <td style="padding:8px;background:#fefce8;border:1px solid #e5e7eb;width:25%;text-align:center"><span style="font-size:20pt;font-weight:700;color:#ca8a04">{}</span><br><span style="font-size:8pt;color:#6b7280">MEDIUM</span></td>
        <td style="padding:8px;background:#f0fdf4;border:1px solid #e5e7eb;width:25%;text-align:center"><span style="font-size:20pt;font-weight:700;color:#16a34a">{}</span><br><span style="font-size:8pt;color:#6b7280">TOTAL</span></td></tr></table>"#,
        critical_count, high_count, medium_count, total_alerts
    );

    // Integrity check
    let (signed_total, valid, tampered) = db.audit_alert_integrity();
    let integrity_status = if tampered == 0 { "PASS — No tampering detected" } else { "FAIL — Alert records may have been modified" };
    let integrity_color = if tampered == 0 { "#16a34a" } else { "#dc2626" };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WIDPS Incident Report — {date_str}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 10pt; line-height: 1.5; color: #1f2937; background: #fff; }}
  .page {{ max-width: 210mm; margin: 0 auto; padding: 20mm; }}
  h1 {{ font-size: 16pt; font-weight: 700; letter-spacing: -0.02em; }}
  h2 {{ font-size: 12pt; font-weight: 600; margin-top: 24px; padding-bottom: 6px; border-bottom: 2px solid #1f2937; margin-bottom: 12px; }}
  h3 {{ font-size: 10pt; font-weight: 600; margin-top: 16px; margin-bottom: 8px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 9pt; }}
  th {{ background: #f3f4f6; padding: 6px 8px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1f2937; padding-bottom: 16px; margin-bottom: 24px; }}
  .header-right {{ text-align: right; font-size: 9pt; color: #6b7280; }}
  .classification {{ display: inline-block; padding: 2px 8px; background: #fef2f2; border: 1px solid #fca5a5; color: #dc2626; font-size: 8pt; font-weight: 700; letter-spacing: 0.05em; }}
  .risk-box {{ padding: 12px 16px; border: 2px solid {risk_color}; background: {risk_color}11; margin: 12px 0; }}
  .risk-level {{ font-size: 14pt; font-weight: 700; color: {risk_color}; }}
  .footer {{ margin-top: 32px; padding-top: 12px; border-top: 2px solid #1f2937; font-size: 8pt; color: #6b7280; display: flex; justify-content: space-between; }}
  .meta-table td {{ padding: 6px 12px; border: 1px solid #e5e7eb; }}
  .meta-table td:first-child {{ background: #f9fafb; font-weight: 600; width: 180px; }}
  @media print {{ body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }} .page {{ padding: 15mm; }} }}
</style>
</head>
<body>
<div class="page">

<!-- HEADER -->
<div class="header">
  <div>
    <h1>WIRELESS INTRUSION DETECTION REPORT</h1>
    <p style="font-size:9pt;color:#6b7280;margin-top:4px">WIDPS — Security Monitoring &amp; Threat Analysis</p>
  </div>
  <div class="header-right">
    <span class="classification">INTERNAL USE ONLY</span>
    <p style="margin-top:8px">Report: <strong>{report_id}</strong></p>
    <p>Date: {date_str} {time_str}</p>
    <p>Sensor: {hostname}</p>
  </div>
</div>

<!-- 1. EXECUTIVE SUMMARY -->
<h2>1. Executive Summary</h2>
<p style="margin-bottom:12px">
  This report documents wireless security events recorded by the WIDPS monitoring sensor
  on interface <strong>{interface}</strong>. The sensor operates in passive 802.11 monitor mode,
  capturing and analyzing management frames across channels 1–11 without transmitting any data.
  Detection is performed using a three-layer architecture: rule-based heuristics, machine learning
  classification (Random Forest, 99.55% accuracy), and composite threat scoring with temporal evidence decay.
</p>

<table class="meta-table">
<tr><td>Sensor Interface</td><td style="font-family:monospace">{interface}</td></tr>
<tr><td>Active Channel</td><td>{channel}</td></tr>
<tr><td>Capture Rate</td><td>{pps} packets/second</td></tr>
<tr><td>Detection Engine</td><td>{engine_status}</td></tr>
<tr><td>Report Period</td><td>{date_str} (ongoing monitoring)</td></tr>
<tr><td>Connected Stations</td><td>{stations}</td></tr>
</table>

<!-- 2. THREAT OVERVIEW -->
<h2>2. Threat Overview</h2>

<div class="risk-box">
  <span class="risk-level">Risk Level: {risk_level}</span>
  <p style="margin-top:4px;font-size:9pt;color:#374151">{risk_description}</p>
</div>

{severity_breakdown}

<!-- 3. ALERT LOG -->
<h2>3. Alert Log ({total_alerts} events)</h2>
<table>
<thead><tr><th style="width:130px">Timestamp</th><th style="width:70px">Severity</th><th>Description</th></tr></thead>
<tbody>
{alert_rows}
</tbody>
</table>
{truncation_note}

<!-- 4. DATA INTEGRITY -->
<h2>4. Data Integrity Verification</h2>
<table class="meta-table">
<tr><td>Signing Algorithm</td><td>HMAC-SHA256</td></tr>
<tr><td>Signed Records</td><td>{signed_total}</td></tr>
<tr><td>Valid Signatures</td><td style="color:#16a34a;font-weight:600">{valid}</td></tr>
<tr><td>Tampered Records</td><td style="color:{integrity_color};font-weight:600">{tampered}</td></tr>
<tr><td>Integrity Status</td><td style="color:{integrity_color};font-weight:600">{integrity_status}</td></tr>
</table>
<p style="font-size:8pt;color:#6b7280;margin-top:8px">
  Each alert is cryptographically signed at creation time. The integrity check recomputes
  signatures and compares against stored values to detect post-hoc modifications to evidence records.
</p>

<!-- 5. METHODOLOGY -->
<h2>5. Detection Methodology</h2>
<table class="meta-table">
<tr><td>Layer 1 — Rules</td><td>7 deterministic detectors (deauth flood, rogue AP, karma attack, sequence anomaly, probe flood, beacon flood, auth flood)</td></tr>
<tr><td>Layer 2 — ML</td><td>Random Forest classifier (30 trees), NLP-based TF-IDF frame tokenization, 6-class output, ONNX runtime</td></tr>
<tr><td>Layer 3 — Scoring</td><td>Per-BSSID evidence accumulation with source-weighted multipliers, temporal decay (0.5/sec), CVSS mapping</td></tr>
<tr><td>Layer 4 — Honeypot</td><td>Dynamic false-positive elimination via correlation with deception network connections</td></tr>
</table>

<!-- FOOTER -->
<div class="footer">
  <div>
    <p>WIDPS v1.0 — Wireless Intrusion Detection &amp; Prevention System</p>
    <p>This report was generated from live sensor data at the time indicated above.</p>
  </div>
  <div style="text-align:right">
    <p>{report_id}</p>
    <p>End of Report</p>
  </div>
</div>

</div>
</body>
</html>"#,
        date_str = date_str,
        time_str = time_str,
        report_id = report_id,
        hostname = system_info.hostname,
        interface = system_info.interface_name,
        channel = system_info.current_channel,
        pps = system_info.packets_per_second,
        engine_status = system_info.engine_status,
        stations = system_info.station_count,
        risk_level = risk_level,
        risk_color = risk_color,
        risk_description = match risk_level {
            "CRITICAL" => "Active wireless attacks have been detected requiring immediate investigation. One or more critical-severity events indicate a direct threat to network integrity.",
            "HIGH" => "High-severity events have been recorded. These warrant prompt review by the security operations team to determine if remediation is required.",
            "MEDIUM" => "Suspicious wireless activity has been observed. No confirmed active threat, but continued monitoring and periodic review are recommended.",
            _ => "No significant threats were detected during the reporting period. Wireless environment appears stable.",
        },
        severity_breakdown = severity_breakdown,
        total_alerts = total_alerts,
        alert_rows = alert_rows,
        truncation_note = truncation_note,
        signed_total = signed_total,
        valid = valid,
        tampered = tampered,
        integrity_status = integrity_status,
        integrity_color = integrity_color,
    )
}

pub struct SystemInfo {
    pub hostname: String,
    pub interface_name: String,
    pub current_channel: u8,
    pub packets_per_second: u32,
    pub engine_status: String,
    pub station_count: u32,
}
