"""
WIDPS Isolation Forest — Zero-Day Attack Detection
====================================================
Unsupervised anomaly detector that catches attacks the supervised model
was never trained on. Works alongside the Random Forest classifier:

  - Random Forest: "I've seen this pattern before, it's Deauth_Flood"
  - Isolation Forest: "I've never seen this pattern, it's ABNORMAL"

The RF catches known attack classes. The IF catches unknown (zero-day) attacks
by learning what "normal" looks like and flagging anything that deviates.

Training:
  python ml/isolation_forest.py --train
  (uses Normal-class windows from the feature extraction output)

Inference (integrated into inference.py):
  Called automatically on every prediction window.
  Returns anomaly_score (-1 = anomaly, 1 = normal) + raw score.

The anomaly score feeds into the Rust threat_scorer via the ML bridge
with source="isolation_forest" and appropriate weight.
"""

import sys
import json
import time
import numpy as np
import joblib
from pathlib import Path

try:
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("[ERROR] Required: pip install scikit-learn pandas", file=sys.stderr)
    sys.exit(1)

OUTPUT_DIR = Path("ml/output")
MODEL_PATH = OUTPUT_DIR / "isolation_forest.joblib"
SCALER_PATH = OUTPUT_DIR / "if_scaler.joblib"
FEATURE_NAMES_PATH = OUTPUT_DIR / "feature_names.txt"
TRAIN_DATA_PATH = OUTPUT_DIR / "features_train.csv"

# Hyperparameters
CONTAMINATION = 0.05  # Expected fraction of anomalies in training data
N_ESTIMATORS = 150     # Number of isolation trees
MAX_SAMPLES = 'auto'   # Samples per tree
RANDOM_STATE = 42


class IsolationForestDetector:
    """Zero-day anomaly detection using Isolation Forest."""

    def __init__(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Train first: python ml/isolation_forest.py --train"
            )

        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.feature_names = FEATURE_NAMES_PATH.read_text().strip().split("\n")
        sys.stderr.write(f"[IF] Loaded Isolation Forest ({N_ESTIMATORS} trees, contamination={CONTAMINATION})\n")

    def predict(self, features: np.ndarray) -> dict:
        """
        Score a feature vector for anomaly.

        Args:
            features: shape (1, n_features) or (n_features,)

        Returns:
            dict with:
              - is_anomaly: bool
              - anomaly_score: float (-1 to 0 for anomalies, 0 to 0.5 for normal)
              - raw_score: float (sklearn decision_function output)
              - confidence: float (0-1, how anomalous)
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Scale features (same scaler used during training)
        features_scaled = self.scaler.transform(features)

        # Predict: -1 = anomaly, 1 = normal
        prediction = self.model.predict(features_scaled)[0]

        # Decision function: negative = more anomalous
        raw_score = self.model.decision_function(features_scaled)[0]

        # Convert to 0-1 confidence (0 = definitely normal, 1 = definitely anomalous)
        # Raw scores typically range from -0.5 (very anomalous) to 0.5 (very normal)
        confidence = max(0.0, min(1.0, 0.5 - raw_score))

        return {
            "is_anomaly": prediction == -1,
            "anomaly_score": float(raw_score),
            "confidence": round(float(confidence), 4),
            "threshold": float(self.model.offset_),
        }


def train():
    """Train the Isolation Forest on Normal traffic only."""
    print("=" * 60)
    print("WIDPS Isolation Forest — Training")
    print("=" * 60)

    if not TRAIN_DATA_PATH.exists():
        print(f"[ERROR] Training data not found: {TRAIN_DATA_PATH}")
        print("        Run first: python ml/feature_extraction.py")
        sys.exit(1)

    # Load training data — ONLY normal traffic
    df = pd.read_csv(TRAIN_DATA_PATH)
    feature_cols = [c for c in df.columns if c not in ("label", "label_name")]

    normal_data = df[df["label_name"] == "Normal"][feature_cols]
    print(f"[Data] Total training samples: {len(df)}")
    print(f"[Data] Normal samples (used for IF): {len(normal_data)}")
    print(f"[Data] Features: {len(feature_cols)}")

    if len(normal_data) < 100:
        print("[ERROR] Too few normal samples for training.")
        sys.exit(1)

    X = normal_data.values.astype(np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    print(f"\n[Training] n_estimators={N_ESTIMATORS}, contamination={CONTAMINATION}")
    t0 = time.perf_counter()

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        max_samples=MAX_SAMPLES,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    train_time = time.perf_counter() - t0
    print(f"[Training] Complete in {train_time:.2f}s")

    # Evaluate on training data
    scores = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)
    n_anomalies = (predictions == -1).sum()

    print(f"\n[Evaluation on Normal data]")
    print(f"  Flagged as anomaly: {n_anomalies}/{len(X_scaled)} ({n_anomalies/len(X_scaled)*100:.1f}%)")
    print(f"  Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"  Score mean: {scores.mean():.4f}, std: {scores.std():.4f}")
    print(f"  Threshold (offset): {model.offset_:.4f}")

    # Test on attack data
    attack_data = df[df["label_name"] != "Normal"][feature_cols]
    if len(attack_data) > 0:
        X_attack = np.nan_to_num(attack_data.values.astype(np.float64))
        X_attack_scaled = scaler.transform(X_attack)
        attack_preds = model.predict(X_attack_scaled)
        attack_detected = (attack_preds == -1).sum()
        print(f"\n[Evaluation on Attack data]")
        print(f"  Total attack samples: {len(attack_data)}")
        print(f"  Detected as anomaly: {attack_detected}/{len(attack_data)} ({attack_detected/len(attack_data)*100:.1f}%)")

        # Per-class breakdown
        for class_name in df[df["label_name"] != "Normal"]["label_name"].unique():
            class_data = df[df["label_name"] == class_name][feature_cols]
            X_cls = np.nan_to_num(class_data.values.astype(np.float64))
            X_cls_scaled = scaler.transform(X_cls)
            cls_preds = model.predict(X_cls_scaled)
            cls_detected = (cls_preds == -1).sum()
            print(f"    {class_name:20s}: {cls_detected}/{len(cls_preds)} detected ({cls_detected/len(cls_preds)*100:.1f}%)")

    # Save
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\n[Saved] {MODEL_PATH}")
    print(f"[Saved] {SCALER_PATH}")
    print(f"\n{'=' * 60}")
    print("Isolation Forest ready for zero-day detection.")
    print(f"{'=' * 60}")


def test():
    """Quick test of the trained model."""
    detector = IsolationForestDetector()

    # Generate a synthetic normal-looking sample
    n_features = len(detector.feature_names)
    normal_sample = np.zeros(n_features)
    normal_sample[0] = 50   # frame_count
    normal_sample[1] = -60  # rssi_mean
    normal_sample[9] = 0.0  # deauth_ratio = 0

    result = detector.predict(normal_sample)
    print(f"Normal-like sample: anomaly={result['is_anomaly']}, confidence={result['confidence']:.2f}")

    # Generate an anomalous sample
    anomaly_sample = np.zeros(n_features)
    anomaly_sample[0] = 500  # very high frame count
    anomaly_sample[9] = 0.9  # 90% deauth ratio
    anomaly_sample[1] = -30  # very strong signal

    result = detector.predict(anomaly_sample)
    print(f"Anomaly-like sample: anomaly={result['is_anomaly']}, confidence={result['confidence']:.2f}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WIDPS Isolation Forest")
    parser.add_argument("--train", action="store_true", help="Train on normal traffic")
    parser.add_argument("--test", action="store_true", help="Quick test")
    args = parser.parse_args()

    if args.train:
        train()
    elif args.test:
        test()
    else:
        train()
