"""
WIDPS Online Learning — Incremental Model Retraining
======================================================
When an admin confirms "this is an attack" via the dashboard, that labeled
sample is saved to the database. This script periodically checks for new
confirmed samples and retrains the model incorporating them.

The model improves over its deployment lifetime without manual intervention.

Usage:
  # One-shot retrain (checks for pending samples, retrains if threshold met)
  python ml/online_trainer.py --retrain

  # Daemon mode (checks every 60 seconds)
  python ml/online_trainer.py --daemon

  # Force retrain regardless of sample count
  python ml/online_trainer.py --force

How it works:
  1. Loads original training data (features_train.csv)
  2. Fetches new confirmed samples from SQLite
  3. Appends confirmed samples to training set
  4. Retrains Random Forest on combined data
  5. Evaluates on test set to ensure no accuracy regression
  6. If accuracy >= 99%, replaces the model
  7. Marks samples as used in DB
  8. Optionally retrains Isolation Forest too
"""

import sys
import time
import json
import sqlite3
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("[ERROR] scikit-learn required: pip install scikit-learn", file=sys.stderr)
    sys.exit(1)

OUTPUT_DIR = Path("ml/output")
MODEL_PATH = OUTPUT_DIR / "model_rf.joblib"
IF_MODEL_PATH = OUTPUT_DIR / "isolation_forest.joblib"
IF_SCALER_PATH = OUTPUT_DIR / "if_scaler.joblib"
TRAIN_DATA_PATH = OUTPUT_DIR / "features_train.csv"
TEST_DATA_PATH = OUTPUT_DIR / "features_test.csv"
LABEL_ENCODER_PATH = OUTPUT_DIR / "label_encoder.joblib"
FEATURE_NAMES_PATH = OUTPUT_DIR / "feature_names.txt"
DB_PATH = Path("widps-backend/data/widps.db")

# If running from project root, try alternate DB path
if not DB_PATH.exists():
    DB_PATH = Path("data/widps.db")

RETRAIN_THRESHOLD = 10  # Minimum confirmed samples before retraining
MIN_ACCURACY = 0.99     # Don't deploy if accuracy drops below this
BACKUP_SUFFIX = ".backup"


def get_pending_samples() -> list:
    """Fetch confirmed but not-yet-retrained samples from SQLite."""
    if not DB_PATH.exists():
        print(f"[WARN] Database not found at {DB_PATH}")
        return []

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "SELECT id, timestamp, label, features FROM confirmed_samples WHERE used_in_retrain = 0"
    )
    samples = []
    for row in cursor:
        samples.append({
            "id": row[0],
            "timestamp": row[1],
            "label": row[2],
            "features": row[3],
        })
    conn.close()
    return samples


def mark_samples_used(sample_ids: list):
    """Mark samples as used in retraining."""
    if not DB_PATH.exists():
        return
    conn = sqlite3.connect(str(DB_PATH))
    for sid in sample_ids:
        conn.execute("UPDATE confirmed_samples SET used_in_retrain = 1 WHERE id = ?", (sid,))
    conn.commit()
    conn.close()


def retrain(force: bool = False) -> bool:
    """
    Perform incremental retraining.
    Returns True if model was updated, False otherwise.
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking for pending samples...")

    # Get pending samples
    pending = get_pending_samples()
    print(f"  Pending confirmed samples: {len(pending)}")

    if not force and len(pending) < RETRAIN_THRESHOLD:
        print(f"  Below threshold ({RETRAIN_THRESHOLD}). Skipping retrain.")
        return False

    if len(pending) == 0 and not force:
        print("  No samples to retrain on.")
        return False

    # Load original training data
    if not TRAIN_DATA_PATH.exists():
        print(f"[ERROR] Training data not found: {TRAIN_DATA_PATH}")
        return False

    print("  Loading original training data...")
    train_df = pd.read_csv(TRAIN_DATA_PATH)
    test_df = pd.read_csv(TEST_DATA_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    feature_names = FEATURE_NAMES_PATH.read_text().strip().split("\n")
    feature_cols = [c for c in train_df.columns if c not in ("label", "label_name")]

    print(f"  Original training set: {len(train_df)} samples")
    print(f"  Test set: {len(test_df)} samples")

    # Parse and append confirmed samples
    new_rows = []
    valid_labels = set(label_encoder.classes_)

    for sample in pending:
        label = sample["label"]
        if label not in valid_labels:
            print(f"  [SKIP] Unknown label '{label}' (valid: {valid_labels})")
            continue

        try:
            features = json.loads(sample["features"])
            if isinstance(features, list) and len(features) == len(feature_cols):
                row = dict(zip(feature_cols, features))
                row["label"] = int(label_encoder.transform([label])[0])
                row["label_name"] = label
                new_rows.append(row)
            else:
                print(f"  [SKIP] Feature length mismatch: got {len(features)}, expected {len(feature_cols)}")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"  [SKIP] Failed to parse features: {e}")

    if not new_rows and not force:
        print("  No valid new samples after parsing.")
        return False

    print(f"  Valid new samples: {len(new_rows)}")

    # Combine original + new data
    if new_rows:
        new_df = pd.DataFrame(new_rows)
        combined_df = pd.concat([train_df, new_df], ignore_index=True)
    else:
        combined_df = train_df

    print(f"  Combined training set: {len(combined_df)} samples")

    # Train new model
    X_train = combined_df[feature_cols].values.astype(np.float64)
    y_train = combined_df["label"].values.astype(int)
    X_train = np.nan_to_num(X_train)

    X_test = test_df[feature_cols].values.astype(np.float64)
    y_test = test_df["label"].values.astype(int)
    X_test = np.nan_to_num(X_test)

    print("  Training new Random Forest...")
    t0 = time.perf_counter()

    new_model = RandomForestClassifier(
        n_estimators=30,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    new_model.fit(X_train, y_train)

    train_time = time.perf_counter() - t0
    print(f"  Training complete in {train_time:.2f}s")

    # Evaluate
    y_pred = new_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"  New model accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

    # Check for regression
    if accuracy < MIN_ACCURACY:
        print(f"  [ABORT] Accuracy {accuracy:.4f} < minimum {MIN_ACCURACY}")
        print("  Model NOT updated. New samples may contain noise.")
        return False

    # Backup old model
    if MODEL_PATH.exists():
        backup_path = MODEL_PATH.with_suffix(MODEL_PATH.suffix + BACKUP_SUFFIX)
        joblib.dump(joblib.load(MODEL_PATH), backup_path)
        print(f"  Backed up old model to {backup_path}")

    # Deploy new model
    joblib.dump(new_model, MODEL_PATH)
    print(f"  Deployed new model to {MODEL_PATH}")

    # Mark samples as used
    sample_ids = [s["id"] for s in pending]
    mark_samples_used(sample_ids)
    print(f"  Marked {len(sample_ids)} samples as retrained")

    # Also retrain Isolation Forest on the normal subset
    normal_mask = combined_df["label_name"] == "Normal"
    if normal_mask.sum() > 100:
        print("  Retraining Isolation Forest on updated normal data...")
        X_normal = combined_df[normal_mask][feature_cols].values.astype(np.float64)
        X_normal = np.nan_to_num(X_normal)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_normal)

        if_model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        )
        if_model.fit(X_scaled)

        joblib.dump(if_model, IF_MODEL_PATH)
        joblib.dump(scaler, IF_SCALER_PATH)
        print(f"  Isolation Forest updated")

    print(f"\n  Online learning complete. Model improved with {len(new_rows)} new samples.")
    return True


def daemon_mode():
    """Run as a background daemon, checking for new samples periodically."""
    print("=" * 60)
    print("WIDPS Online Learning — Daemon Mode")
    print("=" * 60)
    print(f"  Checking every 60s for new confirmed samples")
    print(f"  Retrain threshold: {RETRAIN_THRESHOLD} samples")
    print(f"  Min accuracy: {MIN_ACCURACY*100:.0f}%")
    print(f"  DB path: {DB_PATH}")
    print()

    while True:
        try:
            updated = retrain()
            if updated:
                print("  [!] Model updated. Restart ML inference for changes to take effect.")
        except Exception as e:
            print(f"  [ERROR] Retrain failed: {e}", file=sys.stderr)

        time.sleep(60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WIDPS Online Learning")
    parser.add_argument("--retrain", action="store_true", help="Check and retrain if threshold met")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--force", action="store_true", help="Force retrain regardless of sample count")
    args = parser.parse_args()

    if args.daemon:
        daemon_mode()
    elif args.force:
        retrain(force=True)
    else:
        retrain()
