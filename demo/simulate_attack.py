import argparse
import json
import subprocess
import sys
import time
import random

ATTACK_PROFILES = {
    "deauth": {
        "description": "Deauthentication Flood",
        "frames_per_sec": 200,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 12,
            "dst": "FF:FF:FF:FF:FF:FF",
            "src": "AA:BB:CC:DD:EE:FF",
            "rssi": random.randint(-45, -35),
            "frame_length": 86,
            "duration": random.choice([0, 320]),
            "protected": 0,
            "retry": 0,
            "reason_code": random.choice([1, 2, 3, 7]),
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.005,
            "timestamp": t,
        },
    },
    "beacon_flood": {
        "description": "Beacon Injection Flood",
        "frames_per_sec": 100,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 8,
            "dst": "FF:FF:FF:FF:FF:FF",
            "src": f"{random.randint(0,255):02X}:{random.randint(0,255):02X}:CC:DD:EE:FF",
            "rssi": random.randint(-60, -30),
            "frame_length": 342,
            "duration": 0,
            "protected": 0,
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.01,
            "timestamp": t,
        },
    },
    "auth_flood": {
        "description": "Authentication/Association Flood",
        "frames_per_sec": 50,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 11,
            "dst": "AA:BB:CC:DD:EE:FF",
            "src": f"{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:00:00:00",
            "rssi": random.randint(-70, -40),
            "frame_length": 120,
            "duration": random.randint(0, 500),
            "protected": 0,
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.02,
            "timestamp": t,
        },
    },
    "evil_twin": {
        "description": "Evil Twin / Rogue AP",
        "frames_per_sec": 10,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 8,
            "dst": "FF:FF:FF:FF:FF:FF",
            "src": "99:88:77:66:55:44",
            "rssi": random.randint(-50, -35),
            "frame_length": 340,
            "duration": 0,
            "protected": 0,
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.1,
            "timestamp": t,
        },
    },
    "karma": {
        "description": "Karma Attack (respond to all probes)",
        "frames_per_sec": 20,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 5,
            "dst": f"11:22:33:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}",
            "src": "DE:AD:BE:EF:CA:FE",
            "rssi": random.randint(-55, -30),
            "frame_length": 280,
            "duration": random.randint(0, 200),
            "protected": 0,
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.05,
            "timestamp": t,
        },
    },
    "probe_flood": {
        "description": "Probe Request Reconnaissance Scan",
        "frames_per_sec": 80,
        "pattern": lambda t: {
            "fc_type": 0,
            "fc_subtype": 4,
            "dst": "FF:FF:FF:FF:FF:FF",
            "src": "00:11:22:33:44:55",
            "rssi": random.randint(-65, -40),
            "frame_length": 150,
            "duration": 0,
            "protected": 0,
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.012,
            "timestamp": t,
        },
    },
    "normal": {
        "description": "Normal Traffic (beacons + data)",
        "frames_per_sec": 30,
        "pattern": lambda t: {
            "fc_type": random.choice([0, 0, 2]),
            "fc_subtype": random.choice([8, 8, 8, 4, 0]),
            "dst": random.choice(["FF:FF:FF:FF:FF:FF", "AA:BB:CC:DD:EE:FF"]),
            "src": "0C:9D:92:54:FE:34",
            "rssi": random.randint(-70, -40),
            "frame_length": random.randint(80, 400),
            "duration": 0,
            "protected": random.choice([0, 0, 1]),
            "retry": 0,
            "reason_code": 0,
            "seq_num": random.randint(0, 4095),
            "inter_frame_time": 0.033,
            "timestamp": t,
        },
    },
}


def run_simulation(attack_type, duration_sec, ml_process=None):
    if attack_type == "all":
        attacks = ["normal", "deauth", "beacon_flood", "auth_flood", "evil_twin", "karma", "probe_flood"]
        segment = duration_sec / len(attacks)
        for atk in attacks:
            print(f"\n--- Simulating: {ATTACK_PROFILES[atk]['description']} ({segment:.0f}s) ---")
            run_simulation(atk, segment, ml_process)
        return

    profile = ATTACK_PROFILES.get(attack_type)
    if not profile:
        print(f"Unknown attack: {attack_type}")
        print(f"Available: {', '.join(ATTACK_PROFILES.keys())}")
        return

    fps = profile["frames_per_sec"]
    delay = 1.0 / fps
    total_frames = int(duration_sec * fps)

    print(f"[Sim] Attack: {profile['description']}")
    print(f"[Sim] Rate: {fps} frames/sec for {duration_sec:.1f}s ({total_frames} frames)")
    print(f"[Sim] Sending to ML inference pipeline...")

    start = time.time()
    sent = 0

    for i in range(total_frames):
        t = time.time()
        frame = profile["pattern"](t)

        if ml_process:
            line = json.dumps(frame) + "\n"
            try:
                ml_process.stdin.write(line.encode())
                ml_process.stdin.flush()
            except BrokenPipeError:
                print("[Sim] ML process pipe broken")
                break
        else:
            print(json.dumps(frame))

        sent += 1
        elapsed = time.time() - start
        expected = (i + 1) * delay
        sleep_time = expected - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    elapsed = time.time() - start
    print(f"[Sim] Done: {sent} frames in {elapsed:.1f}s ({sent/elapsed:.0f} fps actual)")


def run_demo_presentation():
    """Generate realistic demo alerts and networks for dashboard presentation.
    
    Writes directly to widps_alerts.jsonl and widps_networks.json to populate
    the dashboard without requiring actual hardware or live capture.
    """
    import datetime
    from pathlib import Path

    print("=" * 60)
    print("WIDPS Demo Presentation Mode")
    print("=" * 60)
    print("\nGenerating realistic alerts and network data for dashboard...")
    print("This mode writes directly to widps_alerts.jsonl and widps_networks.json\n")

    alerts_path = Path("widps_alerts.jsonl")
    networks_path = Path("widps_networks.json")

    # Realistic campus AP inventory
    campus_aps = [
        {"ssid": "CampusNet-5G", "bssid": "0C:9D:92:54:FE:34", "channel": 36, "rssi": -42, "vendor": "Cisco Systems", "encryption": "WPA3-Enterprise"},
        {"ssid": "CampusNet-2G", "bssid": "0C:9D:92:54:FE:35", "channel": 6, "rssi": -55, "vendor": "Cisco Systems", "encryption": "WPA2-Enterprise"},
        {"ssid": "Library-WiFi", "bssid": "A4:CF:12:88:90:01", "channel": 1, "rssi": -48, "vendor": "TP-Link", "encryption": "WPA2-PSK"},
        {"ssid": "eduroam", "bssid": "00:1A:2B:3C:4D:5E", "channel": 11, "rssi": -60, "vendor": "Aruba Networks", "encryption": "WPA2-Enterprise"},
        {"ssid": "CS-Lab-IoT", "bssid": "B8:27:EB:A1:B2:C3", "channel": 6, "rssi": -53, "vendor": "Raspberry Pi", "encryption": "WPA2-PSK"},
        {"ssid": "Admin-Secured", "bssid": "3C:37:86:D4:E5:F6", "channel": 44, "rssi": -47, "vendor": "Cisco Systems", "encryption": "WPA3-Enterprise"},
        # Suspicious networks that appear during attack
        {"ssid": "CampusNet-5G", "bssid": "99:88:77:66:55:44", "channel": 36, "rssi": -38, "vendor": "Unknown", "encryption": "WPA2-PSK", "status": "Malicious"},
        {"ssid": "Free-Campus-WiFi", "bssid": "DE:AD:BE:EF:CA:FE", "channel": 6, "rssi": -35, "vendor": "Unknown", "encryption": "OPEN", "status": "Suspicious"},
    ]

    # Generate timeline of realistic alerts
    now = datetime.datetime.now()
    demo_alerts = []

    attack_scenarios = [
        # Scenario 1: Evil Twin appears (t=0)
        {"offset": 0, "severity": "High", "title": "Rogue AP Detected: SSID Collision",
         "detail": "SSID 'CampusNet-5G' seen on BSSID 99:88:77:66:55:44 (expected: 0C:9D:92:54:FE:34) | CH:36 | RSSI:-38 | Sec:WPA2-PSK vs WPA3-Enterprise | Vendor:Unknown"},
        {"offset": 2, "severity": "Critical", "title": "Evil Twin Confirmed: Certificate Mismatch",
         "detail": "BSSID 99:88:77:66:55:44 presenting invalid certificate for 'CampusNet-5G' | Fingerprint hash mismatch (0xA3F1 vs 0x7B2C)"},
        # Scenario 2: Deauth flood targeting legitimate AP (t=5)
        {"offset": 5, "severity": "Critical", "title": "Deauthentication Flood Detected",
         "detail": "47 deauth/disassoc frames from BSSID 99:88:77:66:55:44 within 5s (latest target: 0C:9D:92:54:FE:34)"},
        {"offset": 6, "severity": "High", "title": "Deauthentication Flood Detected",
         "detail": "23 deauth/disassoc frames from BSSID 99:88:77:66:55:44 within 5s (latest target: A4:CF:12:88:90:01)"},
        # Scenario 3: Karma attack (t=10)
        {"offset": 10, "severity": "Medium", "title": "Karma Attack Detected",
         "detail": "AP DE:AD:BE:EF:CA:FE responding to 8 distinct SSIDs in 30s (possible MANA/Karma)"},
        {"offset": 12, "severity": "High", "title": "Karma Attack Escalation",
         "detail": "AP DE:AD:BE:EF:CA:FE responding to 15 distinct SSIDs — active credential harvesting suspected"},
        # Scenario 4: Client migration attack (t=15)
        {"offset": 15, "severity": "High", "title": "Sequence Number Anomaly",
         "detail": "BSSID 99:88:77:66:55:44: 5 backwards sequence jumps in 5s (spoofing indicator) | Expected seq >2048, got 14"},
        # Scenario 5: Probe flood recon (t=18)
        {"offset": 18, "severity": "Medium", "title": "Probe Request Flood Detected",
         "detail": "62 probe requests from MAC 00:11:22:33:44:55 within 5s — active reconnaissance"},
        # Scenario 6: Beacon flood (t=22)
        {"offset": 22, "severity": "High", "title": "Beacon Injection Flood",
         "detail": "150+ beacons/sec from randomized BSSIDs on CH:6 — DoS via channel saturation"},
        # Scenario 7: Auth flood (t=25)
        {"offset": 25, "severity": "High", "title": "Authentication Flood Detected",
         "detail": "35 auth frames from randomized MACs targeting 0C:9D:92:54:FE:34 within 5s — DoS attack"},
        # Scenario 8: ML detection (t=28)
        {"offset": 28, "severity": "Critical", "title": "AI Model: Deauth_Flood (99.2% confidence)",
         "detail": "ML classifier detected Deauth_Flood pattern | Score:85 | Frames:247 | Window:1.0s | SHAP: inter_frame_time(-0.42), deauth_ratio(0.38)"},
        {"offset": 30, "severity": "Critical", "title": "AI Model: Evil_Twin (97.8% confidence)",
         "detail": "ML classifier detected Evil_Twin pattern | Score:90 | Frames:142 | Window:1.0s | SHAP: beacon_ratio(0.51), src_mac_count(-0.33)"},
        # Scenario 9: Honeypot engagement (t=32)
        {"offset": 32, "severity": "Critical", "title": "Honeypot Engaged: Attacker Connected",
         "detail": "MAC 99:88:77:66:55:44 connected to honeypot SSID 'IT-Department-Test' | IP:192.168.100.5 | DNS queries logged"},
        {"offset": 35, "severity": "Critical", "title": "Composite Threat Score: 94/100",
         "detail": "BSSID 99:88:77:66:55:44 | Evidence: rogue_ap(+15), deauth(+25), fingerprint(+30), ML-ONNX(+18), honeypot(+25) | Verdict: CONFIRMED ATTACKER"},
    ]

    # Write alerts
    with open(alerts_path, "w") as f:
        for alert in demo_alerts:
            pass  # Clear existing

    written = 0
    for scenario in attack_scenarios:
        alert_time = now - datetime.timedelta(seconds=60 - scenario["offset"])
        alert_obj = {
            "timestamp": alert_time.strftime("%H:%M:%S"),
            "severity": scenario["severity"],
            "title": scenario["title"],
            "detail": scenario["detail"],
        }
        with open(alerts_path, "a") as f:
            f.write(json.dumps(alert_obj) + "\n")
        written += 1
        print(f"  [{alert_obj['timestamp']}] {scenario['severity']:>8} | {scenario['title']}")

    # Write networks JSON
    network_entries = []
    for ap in campus_aps:
        now_str = now.strftime("%H:%M:%S")
        first_seen = (now - datetime.timedelta(minutes=random.randint(5, 60))).strftime("%H:%M:%S")
        rssi_base = ap["rssi"]
        rssi_history = [rssi_base + random.randint(-5, 5) for _ in range(20)]

        network_entries.append({
            "id": f"ap-{ap['bssid'].replace(':', '')}",
            "ssid": ap["ssid"],
            "bssid": ap["bssid"],
            "channel": ap["channel"],
            "rssi": rssi_base,
            "vendor": ap["vendor"],
            "encryption": ap["encryption"],
            "beaconIntervalMs": 100,
            "clientCount": random.randint(0, 12),
            "status": ap.get("status", "Normal"),
            "firstSeen": first_seen,
            "lastSeen": now_str,
            "rssiHistory": rssi_history,
        })

    with open(networks_path, "w") as f:
        json.dump(network_entries, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Demo data generated:")
    print(f"  Alerts:   {written} → {alerts_path}")
    print(f"  Networks: {len(network_entries)} → {networks_path}")
    print(f"\nStart the backend (or just the dashboard) to see the data live.")
    print(f"  cd widps-backend && cargo run --release")
    print(f"  cd widps-dashboard && npm run dev")
    print(f"{'='*60}")


def run_demo_live():
    """Live presentation mode — generates alerts with real-time delays.
    
    Run this WHILE the backend is running. Alerts appear progressively
    on the dashboard, telling a coherent attack story over 60 seconds.
    
    Story: Normal campus → Recon detected → Evil Twin appears → 
           Deauth flood → ML classifies → Honeypot confirms → Verdict
    """
    import datetime
    from pathlib import Path

    alerts_path = Path("widps_alerts.jsonl")
    networks_path = Path("widps_networks.json")

    print("=" * 60)
    print(" WIDPS Live Demo — Attack Story Simulation")
    print("=" * 60)
    print()
    print(" This generates alerts in REAL-TIME with pauses.")
    print(" Keep the dashboard open to watch alerts appear live.")
    print(" Total duration: ~60 seconds")
    print()
    print(" Story: Normal → Recon → Evil Twin → Deauth Flood")
    print("        → ML Detection → Honeypot Trap → CONFIRMED")
    print()
    input(" Press ENTER to begin the demo...")
    print()

    # Phase 0: Write campus network baseline
    now = datetime.datetime.now()
    campus_aps = [
        {"ssid": "CampusNet-5G", "bssid": "0C:9D:92:54:FE:34", "channel": 36, "rssi": -42, "vendor": "Cisco Systems", "encryption": "WPA3-Enterprise"},
        {"ssid": "CampusNet-2G", "bssid": "0C:9D:92:54:FE:35", "channel": 6, "rssi": -55, "vendor": "Cisco Systems", "encryption": "WPA2-Enterprise"},
        {"ssid": "Library-WiFi", "bssid": "A4:CF:12:88:90:01", "channel": 1, "rssi": -48, "vendor": "TP-Link", "encryption": "WPA2-PSK"},
        {"ssid": "eduroam", "bssid": "00:1A:2B:3C:4D:5E", "channel": 11, "rssi": -60, "vendor": "Aruba Networks", "encryption": "WPA2-Enterprise"},
        {"ssid": "CS-Lab-IoT", "bssid": "B8:27:EB:A1:B2:C3", "channel": 6, "rssi": -53, "vendor": "Raspberry Pi", "encryption": "WPA2-PSK"},
        {"ssid": "Admin-Secured", "bssid": "3C:37:86:D4:E5:F6", "channel": 44, "rssi": -47, "vendor": "Cisco Systems", "encryption": "WPA3-Enterprise"},
    ]

    network_entries = []
    for ap in campus_aps:
        rssi_history = [ap["rssi"] + random.randint(-3, 3) for _ in range(20)]
        network_entries.append({
            "id": f"ap-{ap['bssid'].replace(':', '')}",
            "ssid": ap["ssid"], "bssid": ap["bssid"], "channel": ap["channel"],
            "rssi": ap["rssi"], "vendor": ap["vendor"], "encryption": ap["encryption"],
            "beaconIntervalMs": 100, "clientCount": random.randint(2, 8),
            "status": "Normal", "firstSeen": (now - datetime.timedelta(hours=2)).strftime("%H:%M:%S"),
            "lastSeen": now.strftime("%H:%M:%S"), "rssiHistory": rssi_history,
        })

    with open(networks_path, "w") as f:
        json.dump(network_entries, f, indent=2)
    with open(alerts_path, "w") as f:
        pass  # Clear alerts

    print("  ✓ Campus baseline loaded (6 legitimate APs)")
    print()

    # Attack story timeline
    story = [
        # Phase 1: Reconnaissance (t=5s)
        (5, "Medium", "Probe Request Flood Detected",
         "62 probe requests from MAC 00:11:22:33:44:55 within 5s — active reconnaissance",
         "  📡 Phase 1: RECONNAISSANCE — Someone is scanning the network..."),

        # Phase 2: Evil Twin appears (t=12s)
        (7, "High", "Rogue AP Detected: SSID Collision",
         "SSID 'CampusNet-5G' seen on BSSID 99:88:77:66:55:44 (expected: 0C:9D:92:54:FE:34) | CH:36 | RSSI:-38 | Sec:WPA2-PSK vs WPA3-Enterprise | Vendor:Unknown",
         "  🚨 Phase 2: EVIL TWIN DEPLOYED — Attacker cloned CampusNet-5G!"),

        (3, "Critical", "Evil Twin Confirmed: Fingerprint Mismatch",
         "BSSID 99:88:77:66:55:44 fingerprint hash mismatch (0xA3F1 → 0x7B2C) — hardware differs from legitimate AP",
         None),

        # Phase 3: Deauth flood to force clients (t=20s)
        (5, "Critical", "Deauthentication Flood Detected",
         "47 deauth/disassoc frames from BSSID 99:88:77:66:55:44 within 5s (latest target: 0C:9D:92:54:FE:34)",
         "  ⚡ Phase 3: DEAUTH FLOOD — Forcing clients off legitimate AP..."),

        (3, "High", "Deauthentication Flood Detected",
         "23 deauth/disassoc frames from BSSID 99:88:77:66:55:44 within 5s (latest target: A4:CF:12:88:90:01)",
         None),

        # Phase 4: ML kicks in (t=28s)
        (5, "Critical", "AI Model: Deauth_Flood (99.2% confidence)",
         "ML classifier detected Deauth_Flood pattern | Score:85 | Frames:247 | Window:1.0s | SHAP: inter_frame_time(-0.42), deauth_ratio(0.38)",
         "  🧠 Phase 4: ML DETECTION — AI confirms attack with 99.2% confidence"),

        (3, "Critical", "AI Model: Evil_Twin (97.8% confidence)",
         "ML classifier detected Evil_Twin pattern | Score:90 | Frames:142 | Window:1.0s | SHAP: beacon_ratio(0.51), unique_src_macs(-0.33)",
         None),

        # Phase 5: Sequence anomaly (t=36s)
        (5, "High", "Sequence Number Anomaly (MAC Spoofing Indicator)",
         "BSSID 99:88:77:66:55:44: 5 backwards sequence jumps in 5s | Expected seq >2048, got 14 — confirms spoofed source",
         "  🔍 Phase 5: FORENSICS — Sequence numbers confirm MAC spoofing"),

        # Phase 6: Honeypot engagement (t=44s)
        (8, "Critical", "Honeypot Engaged: Attacker Connected",
         "MAC 99:88:77:66:55:44 connected to honeypot SSID 'IT-Department-Test' | IP:192.168.100.5 | DNS queries: evil.com, c2server.net",
         "  🍯 Phase 6: HONEYPOT TRAP — Attacker took the bait!"),

        # Phase 7: Final verdict (t=50s)
        (6, "Critical", "Composite Threat Score: 94/100 — CONFIRMED ATTACKER",
         "BSSID 99:88:77:66:55:44 | Evidence: rogue_ap(+15), deauth(+25), fingerprint(+30), ML-ONNX(+18), honeypot(+25) | Correlation bonus: 1.5x | Verdict: CONFIRMED ATTACKER",
         "  ✅ Phase 7: VERDICT — Threat score 94/100, CONFIRMED ATTACKER"),
    ]

    # Add the rogue AP to networks when it "appears"
    rogue_added = False

    for delay, severity, title, detail, phase_msg in story:
        time.sleep(delay)

        if phase_msg:
            print(phase_msg)

        # Add rogue AP to network list when Evil Twin appears
        if "Rogue AP" in title and not rogue_added:
            rogue_added = True
            network_entries.append({
                "id": "ap-998877665544", "ssid": "CampusNet-5G", "bssid": "99:88:77:66:55:44",
                "channel": 36, "rssi": -38, "vendor": "Unknown", "encryption": "WPA2-PSK",
                "beaconIntervalMs": 100, "clientCount": 0, "status": "Malicious",
                "firstSeen": datetime.datetime.now().strftime("%H:%M:%S"),
                "lastSeen": datetime.datetime.now().strftime("%H:%M:%S"),
                "rssiHistory": [-38 + random.randint(-2, 2) for _ in range(20)],
            })
            with open(networks_path, "w") as f:
                json.dump(network_entries, f, indent=2)

        # Write alert
        alert_obj = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "severity": severity,
            "title": title,
            "detail": detail,
        }
        with open(alerts_path, "a") as f:
            f.write(json.dumps(alert_obj) + "\n")

        severity_color = {"Medium": "⚠️ ", "High": "🟠", "Critical": "🔴"}
        print(f"    {severity_color.get(severity, '  ')} [{alert_obj['timestamp']}] {severity:>8} | {title}")

    print()
    print("  " + "=" * 56)
    print("  ✅ DEMO COMPLETE — All 7 phases executed successfully")
    print("  " + "=" * 56)
    print()
    print("  The dashboard now shows the full attack timeline.")
    print("  Walk evaluator through: Network → AI Detection → Threat Scoring → Reports")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="WIDPS Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo/simulate_attack.py --attack deauth --duration 10
  python demo/simulate_attack.py --attack evil_twin --duration 15
  python demo/simulate_attack.py --attack all --duration 30
  python demo/simulate_attack.py --attack all --duration 30 --pipe-to-ml

Available attacks:
  deauth        Deauthentication flood (200 frames/sec)
  beacon_flood  Fake beacon injection (100 frames/sec)
  auth_flood    Authentication/association flood (50 frames/sec)
  evil_twin     Rogue AP impersonating legitimate network (10 frames/sec)
  karma         Karma AP responding to all probes (20 frames/sec)
  probe_flood   Probe request reconnaissance scan (80 frames/sec)
  normal        Legitimate traffic baseline (30 frames/sec)
  all           Cycles through all attack types sequentially

Real hardware attacks (own test AP only):
  Prerequisites:
    sudo airmon-ng start wlan1
    sudo ip link set wlan1mon up

  Deauth Flood:
    sudo aireplay-ng --deauth 100 -a <YOUR_TEST_AP_BSSID> wlan1mon

  Targeted Deauth (specific client):
    sudo aireplay-ng --deauth 50 -a <AP_BSSID> -c <CLIENT_MAC> wlan1mon

  Beacon Flood (requires mdk4):
    sudo mdk4 wlan1mon b -c 6 -s 100

  Authentication Flood (requires mdk4):
    sudo mdk4 wlan1mon a -a <YOUR_TEST_AP_BSSID> -m

  Probe Flood (requires mdk4):
    sudo mdk4 wlan1mon p -c 6 -t <YOUR_TEST_AP_BSSID>

  Evil Twin (requires hostapd-mana):
    sudo hostapd-mana demo/evil_twin.conf

  Karma Attack (requires hostapd-mana):
    sudo hostapd-mana demo/karma.conf

Virtual interface (no adapter needed):
  sudo modprobe mac80211_hwsim radios=2
  sudo ip link set hwsim0 up
  sudo iw dev hwsim0 set type monitor
  sudo tcpreplay --intf1=hwsim0 --multiplier=0.5 demo/deauth_attack.pcap

Generating demo pcap files:
  sudo tcpdump -i wlan1mon -w demo/normal_traffic.pcap -c 10000
  sudo tcpdump -i wlan1mon -w demo/deauth_attack.pcap &
  sudo aireplay-ng --deauth 50 -a <BSSID> wlan1mon
  sleep 10 && kill %1

Expected detector responses:
  Attack                          Detector         Severity    Time to Detect
  Deauth flood (10+ frames/5s)    deauth_flood     Critical    <5s
  Beacon flood (50+ beacons/s)    beacon_flood     High        <1s
  Auth flood (20+ frames/5s)      auth_flood       High        <5s
  Evil Twin (same SSID diff BSSID) rogue_ap        High/Crit   First beacon
  Karma (responds to unknown SSID) karma           Medium      First probe resp
  Probe scan (30+ probes/5s)      probe_flood      Medium      <5s
  MAC spoofing (seq anomaly)      sequence_anomaly High        ~10 frames
  Any attack pattern              ML (ONNX)        Varies      1s window
        """,
    )
    parser.add_argument("--attack", default="deauth",
                        choices=["deauth", "beacon_flood", "auth_flood", "evil_twin", "karma", "probe_flood", "normal", "all"],
                        help="Attack type to simulate (default: deauth)")
    parser.add_argument("--duration", type=float, default=10,
                        help="Duration in seconds (default: 10)")
    parser.add_argument("--pipe-to-ml", action="store_true",
                        help="Pipe frames directly to ml/inference.py --stdin for real-time ML classification")
    parser.add_argument("--stdout-only", action="store_true",
                        help="Print frames to stdout (for manual piping)")
    parser.add_argument("--demo-presentation", action="store_true",
                        help="Generate realistic demo alerts for dashboard presentation (no hardware required)")
    parser.add_argument("--demo-live", action="store_true",
                        help="Live storytelling demo — alerts appear progressively over 60s (run alongside backend)")

    args = parser.parse_args()

    if args.demo_presentation:
        run_demo_presentation()
        return

    if args.demo_live:
        run_demo_live()
        return

    print("=" * 50)
    print("WIDPS Attack Simulator")
    print("=" * 50)

    ml_process = None
    if args.pipe_to_ml:
        print("[Sim] Starting ML inference process...")
        try:
            ml_process = subprocess.Popen(
                ["ml/.venv/bin/python", "ml/inference.py", "--stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)

            import threading
            def read_predictions():
                for line in ml_process.stdout:
                    text = line.decode().strip()
                    if not text or not text.startswith("{"):
                        continue
                    try:
                        pred = json.loads(text)
                        if pred.get("label") != "Normal":
                            print(f"  [ML PREDICTION] {pred['label']} "
                                  f"(conf: {pred['confidence']:.0%}, "
                                  f"score: {pred['threat_score']}, "
                                  f"frames: {pred['frame_count']})")
                    except json.JSONDecodeError:
                        pass

            t = threading.Thread(target=read_predictions, daemon=True)
            t.start()

        except FileNotFoundError:
            print("[Sim] ML venv not found. Run: python3 -m venv ml/.venv && ml/.venv/bin/pip install -r ml/requirements.txt")
            return

    run_simulation(args.attack, args.duration, ml_process)

    if ml_process:
        time.sleep(2)
        ml_process.terminate()

    print("\n[Sim] Simulation complete.")


if __name__ == "__main__":
    main()
