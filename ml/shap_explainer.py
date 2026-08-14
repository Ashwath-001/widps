"""
WIDPS SHAP Explainability Module
---------------------------------
Generates SHAP (SHapley Additive exPlanations) values for every ML prediction.
Shows which features contributed most to the classification decision.

Usage:
  - Standalone: python ml/shap_explainer.py --test     (run on test set)
  - Integrated: imported by inference.py for live explanations
  - API mode:   python ml/shap_explainer.py --serve    (HTTP endpoint)
"""

import json
import sys
import time
import numpy as np
import joblib
from pathlib import Path

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("[WARN] shap not installed. Run: pip install shap", file=sys.stderr)

OUTPUT_DIR = Path("ml/output")
MODEL_PATH = OUTPUT_DIR / "model_rf.joblib"
TFIDF_PATH = OUTPUT_DIR / "tfidf_vectorizer.joblib"
LABEL_ENCODER_PATH = OUTPUT_DIR / "label_encoder.joblib"
FEATURE_NAMES_PATH = OUTPUT_DIR / "feature_names.txt"


class ShapExplainer:
    """Wraps SHAP TreeExplainer for the WIDPS Random Forest model."""

    def __init__(self):
        if not SHAP_AVAILABLE:
            raise ImportError("shap package required: pip install shap")

        self.model = joblib.load(MODEL_PATH)
        self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
        self.feature_names = FEATURE_NAMES_PATH.read_text().strip().split("\n")
        self.classes = self.label_encoder.classes_

        # TreeExplainer is fast for Random Forest (exact SHAP values)
        sys.stderr.write("[SHAP] Initializing TreeExplainer...\n")
        self.explainer = shap.TreeExplainer(self.model)
        sys.stderr.write(f"[SHAP] Ready. Features: {len(self.feature_names)}, Classes: {self.classes.tolist()}\n")

    def explain(self, features: np.ndarray, top_k: int = 10) -> dict:
        """
        Compute SHAP values for a single prediction.

        Args:
            features: shape (1, n_features) or (n_features,)
            top_k: number of top contributing features to return

        Returns:
            dict with explanation details
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        t0 = time.perf_counter()

        # Get prediction
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(probabilities[prediction])

        # Compute SHAP values
        shap_values = self.explainer.shap_values(features)

        explain_ms = (time.perf_counter() - t0) * 1000

        # shap_values is a list of arrays, one per class
        # Get SHAP values for the predicted class
        if isinstance(shap_values, list):
            class_shap = shap_values[prediction][0]
        else:
            class_shap = shap_values[0]

        # Get top-K features by absolute SHAP value
        abs_shap = np.abs(class_shap)
        top_indices = np.argsort(abs_shap)[::-1][:top_k]

        top_features = []
        for idx in top_indices:
            feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            shap_val = float(class_shap[idx])
            feature_val = float(features[0, idx])
            contribution_pct = float(abs_shap[idx] / abs_shap.sum() * 100) if abs_shap.sum() > 0 else 0.0

            top_features.append({
                "feature": feature_name,
                "shap_value": round(shap_val, 6),
                "feature_value": round(feature_val, 4),
                "contribution_pct": round(contribution_pct, 1),
                "direction": "attack" if shap_val > 0 else "normal",
            })

        # Build per-class probabilities with SHAP base values
        class_explanations = {}
        for i, cls in enumerate(self.classes):
            if isinstance(shap_values, list):
                cls_shap = shap_values[i][0]
            else:
                cls_shap = shap_values[0]

            class_explanations[cls] = {
                "probability": round(float(probabilities[i]), 4),
                "top_3_features": [],
            }
            cls_top = np.argsort(np.abs(cls_shap))[::-1][:3]
            for idx in cls_top:
                fname = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
                class_explanations[cls]["top_3_features"].append({
                    "feature": fname,
                    "shap_value": round(float(cls_shap[idx]), 6),
                })

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "explain_ms": round(explain_ms, 2),
            "top_features": top_features,
            "class_explanations": class_explanations,
            "base_value": float(self.explainer.expected_value[prediction]) if isinstance(self.explainer.expected_value, (list, np.ndarray)) else float(self.explainer.expected_value),
            "total_features": len(self.feature_names),
        }

    def explain_batch(self, features_batch: np.ndarray, top_k: int = 10) -> list:
        """Explain multiple predictions at once."""
        results = []
        for i in range(features_batch.shape[0]):
            results.append(self.explain(features_batch[i:i+1], top_k))
        return results


def test_on_dataset():
    """Run SHAP explanations on test dataset samples."""
    import pandas as pd

    print("\n" + "=" * 70)
    print("WIDPS SHAP Explainability — Test Mode")
    print("=" * 70 + "\n")

    explainer = ShapExplainer()

    test_path = OUTPUT_DIR / "features_test.csv"
    if not test_path.exists():
        print(f"[ERROR] Test data not found: {test_path}")
        print("        Run first: python ml/feature_extraction.py")
        return

    test_df = pd.read_csv(test_path)
    feature_cols = [c for c in test_df.columns if c not in ("label", "label_name")]

    # Sample 5 from each class for demonstration
    print(f"[Test] Loaded {len(test_df)} test samples")
    print(f"[Test] Explaining 5 samples per class...\n")

    for class_name in explainer.classes:
        class_samples = test_df[test_df["label_name"] == class_name]
        if class_samples.empty:
            continue

        sample = class_samples.sample(min(5, len(class_samples)), random_state=42)
        print(f"\n{'─' * 70}")
        print(f"  Class: {class_name} ({len(class_samples)} total test samples)")
        print(f"{'─' * 70}")

        for idx, (_, row) in enumerate(sample.iterrows()):
            features = row[feature_cols].values.astype(np.float64).reshape(1, -1)
            result = explainer.explain(features, top_k=5)

            print(f"\n  Sample {idx+1}: Predicted={result['label']} "
                  f"(conf={result['confidence']:.1%}, {result['explain_ms']:.1f}ms)")
            print(f"  {'Feature':<35} {'SHAP':>10} {'Value':>10} {'Contrib':>8} {'Dir':>8}")
            print(f"  {'─' * 73}")

            for feat in result["top_features"]:
                print(f"  {feat['feature']:<35} {feat['shap_value']:>10.4f} "
                      f"{feat['feature_value']:>10.2f} {feat['contribution_pct']:>6.1f}% "
                      f"{'↑ATK' if feat['direction'] == 'attack' else '↓NRM':>6}")

    print(f"\n\n{'=' * 70}")
    print("SHAP analysis complete.")
    print("These explanations show WHY the model made each classification decision.")
    print(f"{'=' * 70}\n")


def stdin_mode():
    """Read feature vectors from stdin, output SHAP explanations as JSON."""
    explainer = ShapExplainer()
    sys.stderr.write("[SHAP-stdin] Ready. Send feature arrays as JSON per line.\n")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            features = np.array(data["features"], dtype=np.float64)
            result = explainer.explain(features, top_k=data.get("top_k", 10))
            sys.stdout.write(json.dumps(result) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[SHAP-error] {e}\n")
            sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WIDPS SHAP Explainability")
    parser.add_argument("--test", action="store_true", help="Run on test dataset")
    parser.add_argument("--stdin", action="store_true", help="Read features from stdin (pipe mode)")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        print(f"[ERROR] Model not found at {MODEL_PATH}")
        print("        Run first: python ml/train_model.py")
        sys.exit(1)

    if not SHAP_AVAILABLE:
        print("[ERROR] shap package not installed.")
        print("        Install: pip install shap")
        sys.exit(1)

    if args.stdin:
        stdin_mode()
    else:
        test_on_dataset()
