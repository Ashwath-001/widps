import argparse
import json
import time
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from collections import deque, Counter
import joblib

OUTPUT_DIR = Path("ml/output")
MODEL_PATH = OUTPUT_DIR / "model_rf.joblib"
TFIDF_PATH = OUTPUT_DIR / "tfidf_vectorizer.joblib"
LABEL_ENCODER_PATH = OUTPUT_DIR / "label_encoder.joblib"
FEATURE_NAMES_PATH = OUTPUT_DIR / "feature_names.txt"

WINDOW_SIZE_SEC = 1.0
ALERT_THRESHOLD = 0.70

BACKEND_ALERTS_FILE = "widps_alerts.jsonl"
BACKEND_NETWORKS_FILE = "widps_networks.json"


class WIDPSClassifier:

    def __init__(self):
        sys.stderr.write("[Model] Loading trained artifacts...\n")
        self.model = joblib.load(MODEL_PATH)
        self.tfidf = joblib.load(TFIDF_PATH)
        self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
        self.feature_names = FEATURE_NAMES_PATH.read_text().strip().split("\n")
        self.classes = self.label_encoder.classes_
        sys.stderr.write(f"[Model] Loaded RF with {self.model.n_estimators} trees\n")
        sys.stderr.write(f"[Model] Classes: {self.classes.tolist()}\n")
        sys.stderr.write(f"[Model] Features: {len(self.feature_names)} "
              f"(20 statistical + {len(self.feature_names) - 20} TF-IDF)\n")

        self.frame_buffer = deque(maxlen=5000)
        self.window_start_time = None

    def frame_to_token(self, frame: dict) -> str:
        fc_type = frame.get("fc_type", 0)
        fc_subtype = frame.get("fc_subtype", 0)
        is_broadcast = 1 if frame.get("dst", "").lower() == "ff:ff:ff:ff:ff:ff" else 0
        has_reason = 1 if frame.get("reason_code", 0) > 0 else 0
        protected = frame.get("protected", 0)
        retry = frame.get("retry", 0)

        duration = frame.get("duration", 0)
        if duration == 0:
            dur_bin = "0"
        elif duration < 100:
            dur_bin = "L"
        elif duration < 500:
            dur_bin = "M"
        else:
            dur_bin = "H"

        return f"T{fc_type}S{fc_subtype}_B{is_broadcast}_R{has_reason}_P{protected}_RT{retry}_D{dur_bin}"

    def extract_window_stats(self, frames: list) -> np.ndarray:
        n = len(frames)
        if n == 0:
            return np.zeros(20)

        rssi_vals = [f.get("rssi", -90) for f in frames]
        ift_vals = [f.get("inter_frame_time", 0.0) for f in frames]
        flen_vals = [f.get("frame_length", 0) for f in frames]
        subtypes = [f.get("fc_subtype", 0) for f in frames]
        durations = [f.get("duration", 0) for f in frames]
        seq_nums = [f.get("seq_num", 0) for f in frames]

        rssi_arr = np.array(rssi_vals, dtype=np.float64)
        ift_arr = np.array(ift_vals, dtype=np.float64)
        flen_arr = np.array(flen_vals, dtype=np.float64)

        src_macs = set(f.get("src", "") for f in frames if f.get("src"))
        dst_macs = set(f.get("dst", "") for f in frames if f.get("dst"))
        bcast_count = sum(1 for f in frames if f.get("dst", "").lower() == "ff:ff:ff:ff:ff:ff")

        subtype_counter = Counter(subtypes)
        deauth_ratio = (subtype_counter.get(12, 0) + subtype_counter.get(10, 0)) / n
        beacon_ratio = subtype_counter.get(8, 0) / n
        probe_req_ratio = subtype_counter.get(4, 0) / n
        probe_resp_ratio = subtype_counter.get(5, 0) / n

        seq_diffs = np.diff(seq_nums) if len(seq_nums) > 1 else np.array([0])
        seq_backwards = int(np.sum(seq_diffs < 0))
        seq_large_jumps = int(np.sum(seq_diffs > 500))

        protected_count = sum(f.get("protected", 0) for f in frames)

        features = [
            n,
            float(np.mean(rssi_arr)),
            float(np.std(rssi_arr)),
            float(np.mean(ift_arr)),
            float(np.min(ift_arr)) if len(ift_arr) > 0 else 0.0,
            float(np.std(ift_arr)),
            float(np.mean(flen_arr)),
            float(np.std(flen_arr)),
            len(set(subtypes)),
            deauth_ratio,
            beacon_ratio,
            probe_req_ratio,
            probe_resp_ratio,
            bcast_count / n,
            len(src_macs),
            len(dst_macs),
            protected_count / n,
            seq_backwards / max(len(seq_diffs), 1),
            seq_large_jumps / max(len(seq_diffs), 1),
            float(np.mean(durations)),
        ]

        return np.array(features, dtype=np.float64)

    def predict_window(self, frames: list) -> dict:
        if not frames:
            return {"label": "Normal", "confidence": 1.0, "threat_score": 0}

        t0 = time.perf_counter()

        tokens = [self.frame_to_token(f) for f in frames]
        sentence = " ".join(tokens)

        tfidf_vec = self.tfidf.transform([sentence]).toarray()
        stat_vec = self.extract_window_stats(frames).reshape(1, -1)
        combined = np.hstack([stat_vec, tfidf_vec])

        prediction = self.model.predict(combined)[0]
        probabilities = self.model.predict_proba(combined)[0]

        inference_ms = (time.perf_counter() - t0) * 1000

        label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(probabilities[prediction])

        prob_map = {}
        for i, cls in enumerate(self.classes):
            prob_map[cls] = round(float(probabilities[i]), 4)

        severity_weights = {
            "Normal": 0,
            "Auth_Flood": 60,
            "Deauth_Flood": 85,
            "Evil_Twin": 90,
            "Krack": 95,
            "Kr00k": 80,
        }
        base_score = severity_weights.get(label, 50)
        threat_score = int(base_score * confidence)

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "probabilities": prob_map,
            "threat_score": threat_score,
            "inference_ms": round(inference_ms, 3),
            "frame_count": len(frames),
            "window_duration_sec": WINDOW_SIZE_SEC,
        }

    def process_frame(self, frame: dict) -> dict | None:
        now = frame.get("timestamp", time.time())

        if self.window_start_time is None:
            self.window_start_time = now

        self.frame_buffer.append(frame)

        if now - self.window_start_time >= WINDOW_SIZE_SEC:
            window_frames = list(self.frame_buffer)
            self.frame_buffer.clear()
            self.window_start_time = now
            result = self.predict_window(window_frames)
            return result

        return None


def simulate_inference():
    print("\n" + "=" * 70)
    print("SIMULATION MODE - Replaying test data as live frames")
    print("=" * 70 + "\n")

    classifier = WIDPSClassifier()

    test_df = pd.read_csv(OUTPUT_DIR / "features_test.csv")

    print(f"[Sim] Replaying {len(test_df)} pre-extracted windows...\n")
    print(f"{'#':>4} {'True Label':>15} {'Predicted':>15} {'Conf':>6} {'Score':>6} {'Time':>8} {'Status'}")
    print("-" * 80)

    correct = 0
    total = 0
    alerts_fired = 0

    feature_cols = [c for c in test_df.columns if c not in ("label", "label_name")]

    for idx, row in test_df.iterrows():
        features = row[feature_cols].values.reshape(1, -1)

        t0 = time.perf_counter()
        pred = classifier.model.predict(features)[0]
        proba = classifier.model.predict_proba(features)[0]
        inference_ms = (time.perf_counter() - t0) * 1000

        pred_label = classifier.label_encoder.inverse_transform([pred])[0]
        true_label = row["label_name"]
        confidence = float(proba[pred])

        severity_weights = {
            "Normal": 0, "Auth_Flood": 60,
            "Deauth_Flood": 85, "Evil_Twin": 90,
            "Krack": 95, "Kr00k": 80,
        }
        threat_score = int(severity_weights.get(pred_label, 50) * confidence)

        is_correct = pred_label == true_label
        correct += int(is_correct)
        total += 1

        is_alert = pred_label != "Normal" and confidence >= ALERT_THRESHOLD
        is_error = not is_correct

        if is_alert or is_error:
            status = "OK" if is_correct else "WRONG"
            if is_alert:
                alerts_fired += 1
                status = f"ALERT {'OK' if is_correct else 'WRONG'}"
            print(f"{total:>4} {true_label:>15} {pred_label:>15} {confidence:>5.1%} "
                  f"{threat_score:>5} {inference_ms:>6.2f}ms  {status}")

    print("-" * 80)
    print(f"\n[Results]")
    print(f"  Total windows:   {total}")
    print(f"  Correct:         {correct} ({correct/total*100:.1f}%)")
    print(f"  Errors:          {total - correct}")
    print(f"  Alerts fired:    {alerts_fired}")


def live_inference():
    print("\n" + "=" * 70)
    print("LIVE MODE - Monitoring Rust backend output")
    print("=" * 70 + "\n")

    classifier = WIDPSClassifier()

    alerts_path = Path(BACKEND_ALERTS_FILE)
    networks_path = Path(BACKEND_NETWORKS_FILE)

    if not alerts_path.exists() and not networks_path.exists():
        print(f"[Live] Neither {alerts_path} nor {networks_path} found.")
        print("[Live] Start the Rust backend first: sudo ./target/release/widps")
        print("[Live] Falling back to simulation mode...\n")
        simulate_inference()
        return

    print(f"[Live] Watching: {alerts_path}")
    print(f"[Live] Window size: {WINDOW_SIZE_SEC}s")
    print(f"[Live] Alert threshold: {ALERT_THRESHOLD:.0%}")
    print(f"[Live] Press Ctrl+C to stop\n")

    last_pos = 0
    window_frames = []
    window_start = time.time()

    try:
        while True:
            if alerts_path.exists():
                with open(alerts_path, "r") as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        frame = alert_to_frame_dict(alert)
                        window_frames.append(frame)
                    except json.JSONDecodeError:
                        continue

            if networks_path.exists():
                try:
                    with open(networks_path, "r") as f:
                        networks = json.loads(f.read())
                    for net in networks[:5]:
                        frame = network_to_frame_dict(net)
                        window_frames.append(frame)
                except (json.JSONDecodeError, FileNotFoundError):
                    pass

            now = time.time()
            if now - window_start >= WINDOW_SIZE_SEC and window_frames:
                result = classifier.predict_window(window_frames)

                if result["label"] != "Normal" and result["confidence"] >= ALERT_THRESHOLD:
                    print(f"[{time.strftime('%H:%M:%S')}] ALERT {result['label']:15s} "
                          f"conf={result['confidence']:.1%} "
                          f"score={result['threat_score']} "
                          f"frames={result['frame_count']} "
                          f"({result['inference_ms']:.1f}ms)")
                else:
                    sys.stdout.write(".")
                    sys.stdout.flush()

                window_frames = []
                window_start = now

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n\n[Live] Stopped.")


def alert_to_frame_dict(alert: dict) -> dict:
    title = alert.get("title", "").lower()

    if "deauth" in title:
        fc_type, fc_subtype = 0, 12
    elif "disassoc" in title:
        fc_type, fc_subtype = 0, 10
    elif "rogue" in title or "evil twin" in title:
        fc_type, fc_subtype = 0, 8
    elif "karma" in title:
        fc_type, fc_subtype = 0, 5
    elif "probe" in title:
        fc_type, fc_subtype = 0, 4
    elif "sequence" in title or "spoof" in title:
        fc_type, fc_subtype = 0, 8
    else:
        fc_type, fc_subtype = 0, 0

    return {
        "fc_type": fc_type,
        "fc_subtype": fc_subtype,
        "dst": "ff:ff:ff:ff:ff:ff",
        "src": "00:00:00:00:00:00",
        "rssi": -60,
        "frame_length": 86,
        "duration": 0,
        "protected": 0,
        "retry": 0,
        "reason_code": 7 if fc_subtype in (10, 12) else 0,
        "seq_num": 0,
        "inter_frame_time": 0.001,
        "timestamp": time.time(),
    }


def network_to_frame_dict(network: dict) -> dict:
    return {
        "fc_type": 0,
        "fc_subtype": 8,
        "dst": "ff:ff:ff:ff:ff:ff",
        "src": network.get("bssid", "00:00:00:00:00:00"),
        "rssi": network.get("rssi", -70),
        "frame_length": 342,
        "duration": 0,
        "protected": 0,
        "retry": 0,
        "reason_code": 0,
        "seq_num": 0,
        "inter_frame_time": 0.1,
        "timestamp": time.time(),
    }


def export_onnx():
    print("\n" + "=" * 70)
    print("ONNX EXPORT - For Rust Backend Integration")
    print("=" * 70 + "\n")

    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        print("[ERROR] skl2onnx not installed. Install: pip install skl2onnx")
        print("\n  Alternative Rust integration options:")
        print("  1. tract crate (ONNX runtime for Rust)")
        print("  2. smartcore crate (native Rust ML)")
        print("  3. linfa crate (Rust ML framework)")
        print("  4. Python subprocess pipe (simplest for MVP)")
        return

    model = joblib.load(MODEL_PATH)
    n_features = len(FEATURE_NAMES_PATH.read_text().strip().split("\n"))

    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type)

    onnx_path = OUTPUT_DIR / "widps_model.onnx"
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"[Saved] {onnx_path}")
    print(f"[Info]  Input shape: (batch, {n_features})")
    print(f"[Info]  Output: class label + probabilities")


def stdin_mode():
    classifier = WIDPSClassifier()
    sys.stderr.write("[stdin] Ready. Send frame JSON per line.\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            continue

        result = classifier.process_frame(frame)

        if result is not None:
            output = json.dumps(result)
            sys.stdout.write(output + "\n")
            sys.stdout.flush()


def benchmark():
    print("\n" + "=" * 70)
    print("BENCHMARK MODE")
    print("=" * 70 + "\n")

    classifier = WIDPSClassifier()

    n_windows = 100
    print(f"[Bench] Generating {n_windows} synthetic windows...")

    windows = []
    for _ in range(n_windows):
        n_frames = np.random.randint(50, 200)
        frames = []
        for i in range(n_frames):
            frames.append({
                "fc_type": np.random.choice([0, 1, 2]),
                "fc_subtype": np.random.choice([0, 4, 5, 8, 10, 12]),
                "dst": np.random.choice(["ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff"]),
                "src": f"{np.random.randint(0,255):02x}:00:00:00:00:00",
                "rssi": np.random.randint(-90, -30),
                "frame_length": np.random.randint(50, 500),
                "duration": np.random.randint(0, 1000),
                "protected": np.random.choice([0, 1]),
                "retry": np.random.choice([0, 1]),
                "reason_code": np.random.choice([0, 0, 0, 7]),
                "seq_num": np.random.randint(0, 4096),
                "inter_frame_time": np.random.exponential(0.001),
                "timestamp": time.time() + i * 0.001,
            })
        windows.append(frames)

    print(f"[Bench] Running inference on {n_windows} windows...")
    t0 = time.perf_counter()

    for window in windows:
        classifier.predict_window(window)

    total_time = time.perf_counter() - t0
    avg_ms = (total_time / n_windows) * 1000

    print(f"\n[Results]")
    print(f"  Total time:      {total_time:.2f}s")
    print(f"  Avg per window:  {avg_ms:.2f} ms")
    print(f"  Throughput:      {n_windows / total_time:.0f} windows/sec")
    print(f"  Frame rate:      {sum(len(w) for w in windows) / total_time:.0f} frames/sec")


def main():
    parser = argparse.ArgumentParser(description="WIDPS ML Inference Engine")
    parser.add_argument("--simulate", action="store_true", help="Simulate inference on test data")
    parser.add_argument("--live", action="store_true", help="Live inference from backend output files")
    parser.add_argument("--stdin", action="store_true", help="Read frames from stdin (Rust pipe integration)")
    parser.add_argument("--export-onnx", action="store_true", help="Export model to ONNX format")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark inference throughput")

    args = parser.parse_args()

    if not MODEL_PATH.exists():
        print(f"[ERROR] Model not found at {MODEL_PATH}")
        print("        Run first: python ml/train_model.py")
        sys.exit(1)

    if args.stdin:
        stdin_mode()
    elif args.export_onnx:
        export_onnx()
    elif args.benchmark:
        benchmark()
    elif args.live:
        live_inference()
    else:
        simulate_inference()


if __name__ == "__main__":
    main()
