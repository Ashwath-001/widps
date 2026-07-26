"""
Usage:
    python demo/simulate_attack.py --attack deauth --duration 10
    python demo/simulate_attack.py --attack evil_twin --duration 15
    python demo/simulate_attack.py --attack all --duration 30
"""

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


def main():
    parser = argparse.ArgumentParser(description="WIDPS Attack Simulator")
    parser.add_argument("--attack", default="deauth",
                        help="Attack type: deauth, beacon_flood, auth_flood, evil_twin, karma, probe_flood, normal, all")
    parser.add_argument("--duration", type=float, default=10,
                        help="Duration in seconds (default: 10)")
    parser.add_argument("--pipe-to-ml", action="store_true",
                        help="Pipe frames directly to ml/inference.py --stdin")
    parser.add_argument("--stdout-only", action="store_true",
                        help="Print frames to stdout (for manual piping)")

    args = parser.parse_args()

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
