import os
import csv
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import warnings

warnings.filterwarnings("ignore")

DATASET_BASE = Path("dataset/archive/CSV")
OUTPUT_DIR = Path("ml/output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FOLDER_LABEL_MAP = {
    "1.Deauth": "Deauth_Flood",
    "2.Disas": "Deauth_Flood",
    "3.(Re)Assoc": "Auth_Flood",
    "4.Rogue_AP": "Evil_Twin",
    "12.Evil_Twin": "Evil_Twin",
    "5.Krack": "Krack",
    "6.Kr00k": "Kr00k",
}

WINDOW_SIZE_SEC = 1.0
TFIDF_MAX_FEATURES = 100
TFIDF_NGRAM_RANGE = (1, 3)
MAX_NORMAL_ROWS_PER_FOLDER = 60000
MAX_ATTACK_ROWS_PER_FOLDER = 60000
SEED = 42


def safe_float(val, default=0.0):
    if not val or val.strip() == "":
        return default
    try:
        return float(val.split("-")[0] if val.startswith("-") else val.split("-")[0])
    except (ValueError, IndexError):
        return default


def parse_rssi(val, default=-90.0):
    if not val or val.strip() == "":
        return default
    val = val.strip()

    parts = []
    current = ""
    for i, ch in enumerate(val):
        if ch == '-' and i > 0 and current:
            parts.append(current)
            current = ch
        else:
            current += ch
    if current:
        parts.append(current)

    for p in parts:
        try:
            v = float(p)
            if -100 <= v <= 0:
                return v
        except ValueError:
            continue

    return default


def safe_int(val, default=0):
    if not val or val.strip() == "":
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def freq_to_channel(freq_mhz):
    freq = safe_int(str(freq_mhz), 0)
    if freq == 0:
        return 0
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    elif 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    return 0


def frame_to_token(row, col_idx):
    fc_type = safe_int(row[col_idx["wlan.fc.type"]], -1)
    fc_subtype = safe_int(row[col_idx["wlan.fc.subtype"]], -1)

    da = row[col_idx["wlan.da"]].strip().lower() if col_idx["wlan.da"] < len(row) else ""
    is_broadcast = 1 if da == "ff:ff:ff:ff:ff:ff" else 0

    reason_raw = row[col_idx["wlan.fixed.reason_code"]].strip() if col_idx["wlan.fixed.reason_code"] < len(row) else ""
    has_reason = 1 if reason_raw and reason_raw != "" else 0

    protected = safe_int(row[col_idx["wlan.fc.protected"]], 0)
    retry = safe_int(row[col_idx["wlan.fc.retry"]], 0)

    duration = safe_int(row[col_idx["wlan.duration"]], 0)
    if duration == 0:
        dur_bin = "0"
    elif duration < 100:
        dur_bin = "L"
    elif duration < 500:
        dur_bin = "M"
    else:
        dur_bin = "H"

    return f"T{fc_type}S{fc_subtype}_B{is_broadcast}_R{has_reason}_P{protected}_RT{retry}_D{dur_bin}"


def create_windows(rows, col_idx, window_sec=WINDOW_SIZE_SEC):
    if not rows:
        return []

    windows = []
    current_tokens = []
    current_rows = []
    window_start = safe_float(rows[0][col_idx["frame.time_relative"]])

    for row in rows:
        t = safe_float(row[col_idx["frame.time_relative"]])

        if t - window_start > window_sec and current_tokens:
            label = _label_window(current_rows, col_idx)
            windows.append((current_tokens, current_rows, label))
            current_tokens = []
            current_rows = []
            window_start = t

        token = frame_to_token(row, col_idx)
        current_tokens.append(token)
        current_rows.append(row)

    if current_tokens:
        label = _label_window(current_rows, col_idx)
        windows.append((current_tokens, current_rows, label))

    return windows


def _label_window(rows, col_idx):
    label_col = col_idx["Label"]
    labels = [r[label_col].strip() for r in rows if label_col < len(r)]
    attack_labels = [l for l in labels if l and l != "Normal"]

    if len(attack_labels) / max(len(labels), 1) > 0.05:
        counter = Counter(attack_labels)
        return counter.most_common(1)[0][0]
    return "Normal"


def extract_window_stats(rows, col_idx):
    n = len(rows)
    if n == 0:
        return np.zeros(20)

    rssi_vals = []
    ift_vals = []
    flen_vals = []
    subtypes = []
    durations = []
    seq_nums = []

    for row in rows:
        rssi_vals.append(parse_rssi(row[col_idx["radiotap.dbm_antsignal"]]))
        ift_vals.append(safe_float(row[col_idx["frame.time_delta"]]))
        flen_vals.append(safe_int(row[col_idx["frame.len"]]))
        subtypes.append(safe_int(row[col_idx["wlan.fc.subtype"]]))
        durations.append(safe_int(row[col_idx["wlan.duration"]]))
        seq_nums.append(safe_int(row[col_idx["wlan.seq"]]))

    rssi_arr = np.array(rssi_vals)
    ift_arr = np.array(ift_vals)
    flen_arr = np.array(flen_vals)

    src_macs = set(r[col_idx["wlan.sa"]].strip() for r in rows if r[col_idx["wlan.sa"]].strip())
    dst_macs = set(r[col_idx["wlan.da"]].strip() for r in rows if r[col_idx["wlan.da"]].strip())

    bcast_count = sum(1 for r in rows if r[col_idx["wlan.da"]].strip().lower() == "ff:ff:ff:ff:ff:ff")

    subtype_counter = Counter(subtypes)
    deauth_ratio = (subtype_counter.get(12, 0) + subtype_counter.get(10, 0)) / n
    beacon_ratio = subtype_counter.get(8, 0) / n
    probe_req_ratio = subtype_counter.get(4, 0) / n
    probe_resp_ratio = subtype_counter.get(5, 0) / n

    seq_diffs = np.diff(seq_nums) if len(seq_nums) > 1 else np.array([0])
    seq_backwards = np.sum(seq_diffs < 0)
    seq_large_jumps = np.sum(seq_diffs > 500)

    protected_count = sum(safe_int(r[col_idx["wlan.fc.protected"]]) for r in rows)

    features = [
        n,
        np.mean(rssi_arr),
        np.std(rssi_arr),
        np.mean(ift_arr),
        np.min(ift_arr) if len(ift_arr) > 0 else 0,
        np.std(ift_arr),
        np.mean(flen_arr),
        np.std(flen_arr),
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
        np.mean(durations),
    ]

    return np.array(features, dtype=np.float64)


STAT_FEATURE_NAMES = [
    "frame_count",
    "rssi_mean",
    "rssi_std",
    "inter_frame_time_mean",
    "inter_frame_time_min",
    "inter_frame_time_std",
    "frame_length_mean",
    "frame_length_std",
    "unique_subtypes",
    "deauth_disassoc_ratio",
    "beacon_ratio",
    "probe_request_ratio",
    "probe_response_ratio",
    "broadcast_ratio",
    "unique_src_macs",
    "unique_dst_macs",
    "protected_frame_ratio",
    "seq_anomaly_backward_ratio",
    "seq_anomaly_jump_ratio",
    "duration_mean",
]


def get_col_indices(header):
    required = [
        "wlan.fc.type", "wlan.fc.subtype", "wlan.da", "wlan.sa",
        "wlan.fixed.reason_code", "wlan.fc.protected", "wlan.fc.retry",
        "wlan.duration", "frame.time_relative", "frame.time_delta",
        "frame.len", "radiotap.dbm_antsignal", "radiotap.channel.freq",
        "radiotap.datarate", "wlan.seq", "wlan.ssid", "wlan.bssid",
        "Label",
    ]
    col_idx = {}
    for col_name in required:
        if col_name in header:
            col_idx[col_name] = header.index(col_name)
        else:
            col_idx[col_name] = 9999
            print(f"  [WARN] Column '{col_name}' not found in header")
    return col_idx


def load_folder_data(folder_name, unified_label):
    folder_path = DATASET_BASE / folder_name
    if not folder_path.exists():
        print(f"  [SKIP] Folder not found: {folder_path}")
        return [], []

    csv_files = sorted(folder_path.glob("*.csv"))
    print(f"  Scanning {len(csv_files)} files in {folder_name}...")

    all_normal_rows = []
    all_attack_rows = []
    header = None
    col_idx = None

    for fpath in csv_files:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            file_header = next(reader)

            if header is None:
                header = file_header
                col_idx = get_col_indices(header)

            label_col = col_idx["Label"]

            for row in reader:
                if len(row) <= label_col:
                    continue
                label = row[label_col].strip()

                if label == "Normal":
                    if len(all_normal_rows) < MAX_NORMAL_ROWS_PER_FOLDER:
                        all_normal_rows.append(row)
                elif label != "":
                    if len(all_attack_rows) < MAX_ATTACK_ROWS_PER_FOLDER:
                        all_attack_rows.append(row)

        if (len(all_normal_rows) >= MAX_NORMAL_ROWS_PER_FOLDER and
                len(all_attack_rows) >= MAX_ATTACK_ROWS_PER_FOLDER):
            break

    print(f"    Loaded {len(all_normal_rows):,} Normal + {len(all_attack_rows):,} Attack rows")
    return header, col_idx, all_normal_rows, all_attack_rows


def process_folder(folder_name, unified_label):
    result = load_folder_data(folder_name, unified_label)
    if not result or len(result) < 4:
        return [], [], []

    header, col_idx, normal_rows, attack_rows = result

    if col_idx is None:
        return [], [], []

    all_rows = []
    for r in normal_rows:
        all_rows.append((r, "Normal"))
    for r in attack_rows:
        all_rows.append((r, unified_label))

    time_col = col_idx["frame.time_relative"]
    all_rows.sort(key=lambda x: safe_float(x[0][time_col]))

    just_rows = [r[0] for r in all_rows]
    windows = create_windows(just_rows, col_idx)

    print(f"    Created {len(windows)} time windows ({WINDOW_SIZE_SEC}s each)")

    stat_features = []
    token_sentences = []
    window_labels = []

    for tokens, w_rows, label in windows:
        stats = extract_window_stats(w_rows, col_idx)
        stat_features.append(stats)

        sentence = " ".join(tokens)
        token_sentences.append(sentence)

        if label == "Normal":
            window_labels.append("Normal")
        else:
            window_labels.append(unified_label)

    return stat_features, token_sentences, window_labels


def main():
    print("=" * 70)
    print("WIDPS - NLP-Inspired Feature Extraction Pipeline")
    print("=" * 70)
    print()

    all_stat_features = []
    all_token_sentences = []
    all_labels = []

    for folder_name, unified_label in FOLDER_LABEL_MAP.items():
        print(f"\n[Processing] {folder_name} -> class '{unified_label}'")
        stats, sentences, labels = process_folder(folder_name, unified_label)

        if stats:
            all_stat_features.extend(stats)
            all_token_sentences.extend(sentences)
            all_labels.extend(labels)

    print(f"\n{'=' * 70}")
    print(f"Total windows extracted: {len(all_labels):,}")
    label_dist = Counter(all_labels)
    print("Label distribution:")
    for label, count in sorted(label_dist.items(), key=lambda x: -x[1]):
        print(f"  {label:20s}: {count:,}")

    if len(all_labels) == 0:
        print("\n[ERROR] No data extracted. Check dataset path.")
        return

    print(f"\n[TF-IDF] Fitting vectorizer (max_features={TFIDF_MAX_FEATURES}, "
          f"ngrams={TFIDF_NGRAM_RANGE})...")

    tfidf = TfidfVectorizer(
        ngram_range=TFIDF_NGRAM_RANGE,
        max_features=TFIDF_MAX_FEATURES,
        analyzer="word",
        sublinear_tf=True,
        dtype=np.float32,
    )

    tfidf_matrix = tfidf.fit_transform(all_token_sentences)
    print(f"  TF-IDF shape: {tfidf_matrix.shape}")
    print(f"  Top 10 features: {tfidf.get_feature_names_out()[:10].tolist()}")

    stat_array = np.array(all_stat_features, dtype=np.float64)
    tfidf_array = tfidf_matrix.toarray()

    stat_array = np.nan_to_num(stat_array, nan=0.0, posinf=0.0, neginf=0.0)

    combined_features = np.hstack([stat_array, tfidf_array])
    print(f"\n[Combined] Final feature matrix shape: {combined_features.shape}")

    le = LabelEncoder()
    encoded_labels = le.fit_transform(all_labels)
    print(f"[Labels] Classes: {le.classes_.tolist()}")

    X_train, X_test, y_train, y_test = train_test_split(
        combined_features, encoded_labels,
        test_size=0.3,
        random_state=SEED,
        stratify=encoded_labels,
    )

    print(f"\n[Split] Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")

    tfidf_feature_names = [f"tfidf_{name}" for name in tfidf.get_feature_names_out()]
    all_feature_names = STAT_FEATURE_NAMES + tfidf_feature_names

    train_df = pd.DataFrame(X_train, columns=all_feature_names)
    train_df["label"] = y_train
    train_df["label_name"] = le.inverse_transform(y_train)

    test_df = pd.DataFrame(X_test, columns=all_feature_names)
    test_df["label"] = y_test
    test_df["label_name"] = le.inverse_transform(y_test)

    train_path = OUTPUT_DIR / "features_train.csv"
    test_path = OUTPUT_DIR / "features_test.csv"
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"\n[Saved] {train_path} ({train_df.shape})")
    print(f"[Saved] {test_path} ({test_df.shape})")

    joblib.dump(tfidf, OUTPUT_DIR / "tfidf_vectorizer.joblib")
    joblib.dump(le, OUTPUT_DIR / "label_encoder.joblib")
    print(f"[Saved] tfidf_vectorizer.joblib")
    print(f"[Saved] label_encoder.joblib")

    with open(OUTPUT_DIR / "feature_names.txt", "w") as f:
        for name in all_feature_names:
            f.write(name + "\n")

    print(f"\n{'=' * 70}")
    print("Feature extraction complete!")
    print(f"Total features per window: {len(all_feature_names)} "
          f"(20 statistical + {TFIDF_MAX_FEATURES} TF-IDF)")
    print(f"Ready for model training: python ml/train_model.py")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
