"""Management-frame feature extraction with a split by capture file."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

DATASET_BASE = Path("ml/dataset/archive/CSV")
OUTPUT_DIR = Path("ml/output_mgmt")

FOLDER_LABEL_MAP = {
    "1.Deauth": "Deauth_Flood",
    "2.Disas": "Deauth_Flood",
    "3.(Re)Assoc": "Auth_Flood",
    "4.Rogue_AP": "Evil_Twin",
    "12.Evil_Twin": "Evil_Twin",
    "5.Krack": "Krack",
    "6.Kr00k": "Kr00k",
}

WINDOW_SEC = 1.0
ATTACK_FRACTION = 0.05      # same labelling rule as the original pipeline
MIN_FRAMES_PER_WINDOW = 1
TFIDF_MAX_FEATURES = 100
TFIDF_NGRAM_RANGE = (1, 3)
TEST_FILE_FRACTION = 0.30
SEED = 42

USECOLS = [
    "frame.len", "frame.time_relative", "radiotap.dbm_antsignal",
    "wlan.duration", "wlan.da", "wlan.sa", "wlan.fc.type", "wlan.fc.subtype",
    "wlan.fc.protected", "wlan.fc.retry", "wlan.seq", "wlan.fixed.reason_code",
    "Label",
]

STAT_FEATURE_NAMES = [
    "frame_count", "rssi_mean", "rssi_std", "inter_frame_time_mean",
    "inter_frame_time_min", "inter_frame_time_std", "frame_length_mean",
    "frame_length_std", "unique_subtypes", "deauth_disassoc_ratio",
    "beacon_ratio", "probe_request_ratio", "probe_response_ratio",
    "broadcast_ratio", "unique_src_macs", "unique_dst_macs",
    "protected_frame_ratio", "seq_anomaly_backward_ratio",
    "seq_anomaly_jump_ratio", "duration_mean",
]

_FIRST_NEGATIVE = re.compile(r"(-\d+(?:\.\d+)?)")


def num(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default)


def file_to_windows(path: Path):
    """Return (stats DataFrame, sentences list, labels list) for one capture file."""
    df = pd.read_csv(path, usecols=lambda c: c in USECOLS, dtype=str,
                     encoding_errors="replace", low_memory=False)
    if "Label" not in df.columns or "wlan.fc.type" not in df.columns:
        return None

    df = df[df["Label"].fillna("").str.strip() != ""]
    df = df[num(df["wlan.fc.type"], -1) == 0]           # management frames only
    if df.empty:
        return None

    df = df.assign(_t=num(df["frame.time_relative"])).sort_values("_t", kind="stable")
    df = df.reset_index(drop=True)

    t = df["_t"].to_numpy()
    ift = np.diff(t, prepend=t[0])
    ift[ift < 0] = 0.0

    subtype = num(df["wlan.fc.subtype"], -1).astype(int)
    da = df["wlan.da"].fillna("").str.strip().str.lower()
    sa = df["wlan.sa"].fillna("").str.strip()
    reason = df.get("wlan.fixed.reason_code", pd.Series("", index=df.index)).fillna("").str.strip()
    protected = num(df["wlan.fc.protected"]).astype(int)
    retry = num(df["wlan.fc.retry"]).astype(int)
    duration = num(df["wlan.duration"])
    seq = num(df["wlan.seq"])
    flen = num(df["frame.len"])
    rssi = (df["radiotap.dbm_antsignal"].fillna("").str.extract(_FIRST_NEGATIVE)[0]
            .astype(float).fillna(-90.0))
    rssi = rssi.where((rssi >= -100) & (rssi <= 0), -90.0)

    is_bcast = (da == "ff:ff:ff:ff:ff:ff").astype(int)
    has_reason = (reason != "").astype(int)
    dur_bin = np.select([duration == 0, duration < 100, duration < 500], ["0", "L", "M"], "H")
    token = ("T0S" + subtype.astype(str) + "_B" + is_bcast.astype(str) + "_R" + has_reason.astype(str)
             + "_P" + protected.astype(str) + "_RT" + retry.astype(str) + "_D" + pd.Series(dur_bin))

    win = np.floor((t - t[0]) / WINDOW_SEC).astype(int)
    is_attack = (df["Label"].str.strip() != "Normal").astype(int)

    work = pd.DataFrame({
        "win": win, "rssi": rssi, "ift": ift, "flen": flen, "subtype": subtype,
        "da": da, "sa": sa, "bcast": is_bcast, "protected": protected,
        "duration": duration, "seq": seq, "token": token, "attack": is_attack,
    })
    prev_same = work["win"].eq(work["win"].shift(1))
    d = work["seq"].diff()
    work["back"] = ((d < 0) & prev_same).astype(int)
    work["jump"] = ((d > 500) & prev_same).astype(int)
    work["is_deauth"] = work["subtype"].isin([10, 12]).astype(int)
    work["is_beacon"] = (work["subtype"] == 8).astype(int)
    work["is_preq"] = (work["subtype"] == 4).astype(int)
    work["is_presp"] = (work["subtype"] == 5).astype(int)

    g = work.groupby("win", sort=True)
    n = g.size()
    keep = n[n >= MIN_FRAMES_PER_WINDOW].index
    denom_diff = (n - 1).clip(lower=1)

    stats = pd.DataFrame({
        "frame_count": n,
        "rssi_mean": g["rssi"].mean(),
        "rssi_std": g["rssi"].std(ddof=0),
        "inter_frame_time_mean": g["ift"].mean(),
        "inter_frame_time_min": g["ift"].min(),
        "inter_frame_time_std": g["ift"].std(ddof=0),
        "frame_length_mean": g["flen"].mean(),
        "frame_length_std": g["flen"].std(ddof=0),
        "unique_subtypes": g["subtype"].nunique(),
        "deauth_disassoc_ratio": g["is_deauth"].sum() / n,
        "beacon_ratio": g["is_beacon"].sum() / n,
        "probe_request_ratio": g["is_preq"].sum() / n,
        "probe_response_ratio": g["is_presp"].sum() / n,
        "broadcast_ratio": g["bcast"].sum() / n,
        "unique_src_macs": g["sa"].apply(lambda s: len({x for x in s if x})),
        "unique_dst_macs": g["da"].apply(lambda s: len({x for x in s if x})),
        "protected_frame_ratio": g["protected"].sum() / n,
        "seq_anomaly_backward_ratio": g["back"].sum() / denom_diff,
        "seq_anomaly_jump_ratio": g["jump"].sum() / denom_diff,
        "duration_mean": g["duration"].mean(),
    }).loc[keep][STAT_FEATURE_NAMES]
    sentences = g["token"].apply(" ".join).loc[keep].tolist()
    attack_frac = (g["attack"].sum() / n).loc[keep].to_numpy()
    return stats, sentences, attack_frac


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-files-per-folder", type=int, default=0, help="0 = all files")
    args = ap.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)

    rows = []            # dicts: stats row + meta
    sentences = []
    meta = []            # dicts: label, file, folder, split
    per_file_log = []

    for folder, attack_label in FOLDER_LABEL_MAP.items():
        folder_path = DATASET_BASE / folder
        files = sorted(folder_path.glob("*.csv"))
        if args.max_files_per_folder:
            files = files[: args.max_files_per_folder]
        if not files:
            print(f"[skip] {folder}: no files")
            continue

        # Whole files go to train or test (ceil so every folder keeps a test file).
        order = rng.permutation(len(files))
        n_test = max(1, int(round(len(files) * TEST_FILE_FRACTION))) if len(files) > 1 else 0
        test_idx = set(order[:n_test].tolist())

        print(f"[{folder}] -> {attack_label}: {len(files)} files ({n_test} held out for test)")
        for i, f in enumerate(files):
            res = file_to_windows(f)
            if res is None:
                per_file_log.append({"file": str(f), "windows": 0})
                continue
            stats, sents, attack_frac = res
            split = "test" if i in test_idx else "train"
            labels = np.where(attack_frac > ATTACK_FRACTION, attack_label, "Normal")
            rows.append(stats.reset_index(drop=True))
            sentences.extend(sents)
            for lab in labels:
                meta.append({"label_name": lab, "file": f"{folder}/{f.name}", "folder": folder, "split": split})
            per_file_log.append({"file": str(f), "windows": int(len(stats)), "split": split,
                                 "attack_windows": int((labels != "Normal").sum())})

    if not rows:
        raise SystemExit("No data extracted. Check DATASET_BASE.")

    stats_df = pd.concat(rows, ignore_index=True)
    meta_df = pd.DataFrame(meta)
    stats_df = stats_df.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    print("\nWindows per class and split:")
    print(pd.crosstab(meta_df["label_name"], meta_df["split"]))

    train_mask = (meta_df["split"] == "train").to_numpy()
    tfidf = TfidfVectorizer(ngram_range=TFIDF_NGRAM_RANGE, max_features=TFIDF_MAX_FEATURES,
                            analyzer="word", sublinear_tf=True, dtype=np.float32)
    # Vocabulary comes from training files only.
    tfidf.fit([s for s, m in zip(sentences, train_mask) if m])
    tfidf_matrix = tfidf.transform(sentences).toarray()
    tfidf_names = [f"tfidf_{x}" for x in tfidf.get_feature_names_out()]

    feats = np.hstack([stats_df.to_numpy(dtype=np.float64), tfidf_matrix])
    names = STAT_FEATURE_NAMES + tfidf_names

    le = LabelEncoder().fit(meta_df["label_name"])
    out = pd.DataFrame(feats, columns=names)
    out["label"] = le.transform(meta_df["label_name"])
    out["label_name"] = meta_df["label_name"].to_numpy()
    out["file"] = meta_df["file"].to_numpy()
    out["folder"] = meta_df["folder"].to_numpy()

    out[train_mask].to_csv(OUTPUT_DIR / "features_train.csv", index=False)
    out[~train_mask].to_csv(OUTPUT_DIR / "features_test.csv", index=False)
    joblib.dump(tfidf, OUTPUT_DIR / "tfidf_vectorizer.joblib")
    joblib.dump(le, OUTPUT_DIR / "label_encoder.joblib")
    (OUTPUT_DIR / "feature_names.txt").write_text("\n".join(names) + "\n")
    (OUTPUT_DIR / "extraction_summary.json").write_text(json.dumps({
        "window_sec": WINDOW_SEC, "attack_fraction": ATTACK_FRACTION,
        "management_frames_only": True, "split": "by capture file",
        "test_file_fraction": TEST_FILE_FRACTION, "seed": SEED,
        "windows_total": int(len(out)),
        "class_counts": {k: int(v) for k, v in Counter(meta_df["label_name"]).items()},
        "files": per_file_log,
    }, indent=2))
    print(f"\nSaved to {OUTPUT_DIR}/  (train {int(train_mask.sum())} / test {int((~train_mask).sum())} windows)")


if __name__ == "__main__":
    main()
