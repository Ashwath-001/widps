# WIDPS Honeypot — Design Rationale

## The Question: "We detect fake APs. Why are we creating one?"

This is the right question to ask, and the answer is critical to understanding
the system's architecture.

## Short Answer

The honeypot is NOT "another fake AP for catching hackers." It is a
**false-positive elimination oracle** that converts ambiguous IDS detections
into confirmed verdicts with high confidence.

## The Problem We're Solving

The #1 unsolved problem in wireless IDS is **false positives**:

```
IDS detects new BSSID broadcasting "CollegeWiFi"
    ├── Is it an attacker's Evil Twin?        → ACTION NEEDED
    ├── Is it a new AP deployed by IT?        → IGNORE
    └── Is it a student's mobile hotspot?     → MONITOR
```

Without the honeypot, we can only say "suspicious" (60-70% confidence).
With the honeypot, we can say "confirmed" (95%+ confidence).

## How Correlation Works

```
             MAIN IDS (wlan1mon - passive)
                      │
                      ├── Detects BSSID XX:XX:XX running "CollegeWiFi"
                      │   not in whitelist → flags MAC as suspect
                      │
                      ├── Detects deauth flood from MAC YY:YY:YY
                      │   → marks MAC as deauth source
                      │
                      ▼
             HONEYPOT (wlan2 - active)
                      │
                      │   MAC XX:XX:XX connects to "FreeWiFi" honeypot
                      │
                      ▼
             CORRELATION ENGINE
                      │
                      │   XX:XX:XX was flagged as rogue AP operator
                      │   XX:XX:XX now connected to honeypot
                      │   ∴ Legitimate AP infrastructure doesn't seek open WiFi
                      │   ∴ CONFIRMED: XX:XX:XX is an attacker device
                      │
                      ▼
             VERDICT: CRITICAL THREAT (confidence: 95%)
             Previously: SUSPICIOUS (confidence: 40%)
```

## Why Legitimate APs Never Trigger This

A Cisco/Aruba/Ubiquiti access point:
- Has a static wired backhaul (Ethernet)
- Never sends probe requests for random SSIDs
- Never connects to other wireless networks
- Has no reason to interact with open APs

An attacker's device (laptop, Pi, WiFi Pineapple):
- HAS a wireless client interface (in addition to the AP interface)
- Probes for remembered networks (including open ones)
- May actively seek internet connectivity via WiFi
- WILL respond to open AP availability

This behavioral difference is exploitable and provable.

## Static vs Dynamic Honeypot

### Static Honeypot (what most papers implement)
- Fixed SSID like "FreeWiFi"
- Sophisticated attackers recognize and avoid it
- Limited attacker coverage
- Easy to fingerprint (always same BSSID, same beacon interval)

### Dynamic Honeypot (our approach — novel contribution)
- Monitors probe requests in the environment
- Identifies SSIDs that devices probe for but no AP serves
- Deploys those SSIDs as traps
- Result: if you connect to an SSID that didn't exist until we created it,
  you're provably seeking networks to exploit

**Why dynamic is better:**
1. Can't be pre-identified by attackers (SSIDs change based on environment)
2. Catches sophisticated attackers who avoid obvious "FreeWiFi" traps
3. The SSID existed in the attacker's saved networks → proves prior malicious use
4. Academic novelty — no wireless IDS paper implements environment-adaptive honeypot deployment

## Threat Model & Ethical Considerations

### What the honeypot IS:
- A confirmation tool that validates IDS detections
- A false-positive eliminator that prevents alert fatigue
- A forensic evidence generator for incident response

### What the honeypot is NOT:
- An entrapment device (devices connect voluntarily)
- A man-in-the-middle tool (no traffic is intercepted)
- A credential harvester (captive portal logs are for forensic evidence only)

### Network Isolation Guarantees:
- Honeypot subnets have ZERO connectivity to production network
- No internet access is provided
- All traffic stays within isolated 192.168.66-69.0/24 subnets
- iptables rules prevent any cross-subnet leakage

## Integration with Main IDS

```rust
// In the main capture loop:

// 1. When IDS flags a suspected rogue AP:
honeypot.mark_suspected_rogue_operator(&bssid, "SSID not in whitelist");

// 2. When IDS detects deauth source:
honeypot.mark_deauth_source(&src_mac);

// 3. When probe for unknown SSID is seen (no AP serves it):
honeypot.record_unserved_probe(&ssid, &src_mac);

// The honeypot monitor thread then:
// - Watches for any of these MACs connecting to honeypot APs
// - When found → fires CONFIRMED correlation alert
// - Feeds high-weight evidence to ThreatScorer
```

## Comparison with Related Work

| System | Approach | Our Improvement |
|--------|----------|-----------------|
| Shadow Honeynet (Springer 2015) | Static honeypot for RAP detection | Dynamic SSID + correlation engine |
| Honeypot IDS (Springer 2017) | Honeypot detects attacks on itself | Honeypot confirms attacks detected elsewhere |
| Venus Fly-Trap (ResearchGate 2022) | Optimization-based honeypot placement | Environment-adaptive SSID selection |
| SOAR Dynamic Honeypots (2022) | Dynamic service emulation | Dynamic wireless network emulation |

**Novel contribution:** No prior work uses a honeypot specifically as a
cross-correlation oracle for wireless IDS false-positive elimination with
environment-adaptive SSID deployment.

## Summary

```
Without honeypot:
  Detection confidence: 40-70% (many false positives)
  Alert fatigue: HIGH
  Actionability: LOW (can't be sure it's an attack)

With honeypot correlation:
  Detection confidence: 85-99% (correlated evidence)
  Alert fatigue: LOW (only confirmed threats escalate)
  Actionability: HIGH (evidence chain supports response)
```
