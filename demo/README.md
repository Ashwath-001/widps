# WIDPS Demo & Attack Simulation Guide

## Quick Demo Options

### Option A: No Hardware (Simulation Mode)
Just run the backend without wlan1mon available:
```bash
cd widps-backend
cargo run --release
```
It auto-detects missing interface and starts simulating attacks every 10s.
Dashboard at http://localhost:5173 shows live alerts cycling through all attack types.

---

### Option B: Replay a .pcap File (Reproducible Demo)
Use tcpreplay to inject a pre-recorded attack capture into a virtual interface:

```bash
# Create a virtual monitor interface
sudo modprobe mac80211_hwsim radios=2
sudo ip link set hwsim0 up
sudo iw dev hwsim0 set type monitor

# Replay a deauth attack pcap (slowed to 0.5x speed)
sudo tcpreplay --intf1=hwsim0 --multiplier=0.5 demo/deauth_attack.pcap

# In another terminal, run WIDPS pointing to hwsim0
# (edit IFACE in main.rs to "hwsim0" or pass as env var)
sudo ./target/release/widps
```

---

### Option C: Real Hardware Attack (Own test AP ONLY)

**Legal warning: Only use these on YOUR OWN test network. Never on networks you don't own.**

#### Prerequisites
```bash
sudo airmon-ng start wlan1          # put adapter in monitor mode
sudo ip link set wlan1mon up
```

#### 1. Deauth Flood (triggers deauth_flood + sequence_anomaly detectors)
```bash
# Flood deauth against your test AP
sudo aireplay-ng --deauth 100 -a <YOUR_TEST_AP_BSSID> wlan1mon

# Targeted deauth (specific client)
sudo aireplay-ng --deauth 50 -a <AP_BSSID> -c <CLIENT_MAC> wlan1mon
```

#### 2. Beacon Flood (triggers beacon_flood detector)
```bash
# Requires mdk4
sudo mdk4 wlan1mon b -c 6 -s 100
# -c 6 = channel 6, -s 100 = 100 beacons/sec (threshold is 50)
```

#### 3. Authentication Flood (triggers auth_flood detector)
```bash
sudo mdk4 wlan1mon a -a <YOUR_TEST_AP_BSSID> -m
# Floods auth frames against the target AP
```

#### 4. Probe Flood / Reconnaissance (triggers probe_flood detector)
```bash
sudo mdk4 wlan1mon p -c 6 -t <YOUR_TEST_AP_BSSID>
# Or with scapy for more control
```

#### 5. Evil Twin / Rogue AP (triggers rogue_ap detector)
```bash
# Create a fake AP with same SSID as your test network
sudo hostapd-mana demo/evil_twin.conf
# See demo/evil_twin.conf for config
```

#### 6. Karma Attack (triggers karma detector)
```bash
# hostapd-mana with karma mode
sudo hostapd-mana demo/karma.conf
# Responds to all probe requests regardless of SSID
```

---

### Option D: Python Attack Simulator (No extra tools needed)

Generates fake frames directly into the WIDPS pipeline via the ML bridge stdin:

```bash
cd widps
python3 demo/simulate_attack.py --attack deauth --duration 10
```

---

## Generating Demo pcap Files

If you need pcap files for replay:

```bash
# Capture 30s of normal traffic
sudo tcpdump -i wlan1mon -w demo/normal_traffic.pcap -c 10000

# Capture while running a deauth attack (in another terminal)
sudo tcpdump -i wlan1mon -w demo/deauth_attack.pcap &
sudo aireplay-ng --deauth 50 -a <BSSID> wlan1mon
sleep 10 && kill %1
```

## Expected Detector Responses

| Attack | Detector | Alert Severity | Time to Detect |
|--------|----------|---------------|----------------|
| Deauth flood (10+ frames/5s) | deauth_flood | Critical | <5s |
| Beacon flood (50+ beacons/s) | beacon_flood | High | <1s |
| Auth flood (20+ frames/5s) | auth_flood | High | <5s |
| Evil Twin (same SSID, different BSSID) | rogue_ap | High/Critical | First beacon |
| Karma (responds to unknown SSID) | karma | Medium | First probe response |
| Probe scan (30+ probes/5s) | probe_flood | Medium | <5s |
| MAC spoofing (seq anomaly) | sequence_anomaly | High | ~10 frames |
| Any attack pattern | ML (ONNX) | Varies | 1s window |
