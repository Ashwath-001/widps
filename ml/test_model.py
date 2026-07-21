import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
import joblib
import onnxruntime as ort
import time
import json

OUTPUT_DIR = Path("ml/output")


def load_test_data():
    test_path = OUTPUT_DIR / "features_test.csv"
    if not test_path.exists():
        print(f"[ERROR] {test_path} not found. Run feature_extraction.py first.")
        return None, None, None, None

    df = pd.read_csv(test_path)
    feature_cols = [c for c in df.columns if c not in ("label", "label_name")]

    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values
    label_names = sorted(df["label_name"].unique())
    y_names = df["label_name"].values

    return X, y, label_names, y_names


def test_sklearn_model(X, y, label_names):
    print("\n" + "=" * 60)
    print("TEST: sklearn Random Forest (model_rf.joblib)")
    print("=" * 60)

    model_path = OUTPUT_DIR / "model_rf.joblib"
    if not model_path.exists():
        print(f"[SKIP] {model_path} not found")
        return None

    model = joblib.load(model_path)

    t0 = time.perf_counter()
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)
    elapsed = time.perf_counter() - t0

    print_metrics(y, y_pred, y_proba, label_names, elapsed, len(X), "RF")
    return y_pred


def test_sklearn_fast_model(X, y, label_names):
    print("\n" + "=" * 60)
    print("TEST: sklearn Random Forest Fast (model_rf_fast.joblib)")
    print("=" * 60)

    model_path = OUTPUT_DIR / "model_rf_fast.joblib"
    if not model_path.exists():
        print(f"[SKIP] {model_path} not found")
        return None

    model = joblib.load(model_path)

    t0 = time.perf_counter()
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)
    elapsed = time.perf_counter() - t0

    print_metrics(y, y_pred, y_proba, label_names, elapsed, len(X), "RF_Fast")
    return y_pred


def test_xgboost_model(X, y, label_names):
    print("\n" + "=" * 60)
    print("TEST: XGBoost (model_xgb.joblib)")
    print("=" * 60)

    model_path = OUTPUT_DIR / "model_xgb.joblib"
    if not model_path.exists():
        print(f"[SKIP] {model_path} not found")
        return None

    model = joblib.load(model_path)

    t0 = time.perf_counter()
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)
    elapsed = time.perf_counter() - t0

    print_metrics(y, y_pred, y_proba, label_names, elapsed, len(X), "XGB")
    return y_pred


def test_onnx_model(X, y, label_names):
    print("\n" + "=" * 60)
    print("TEST: ONNX Runtime (widps_model_fast.onnx)")
    print("=" * 60)

    onnx_path = OUTPUT_DIR / "widps_model_fast.onnx"
    if not onnx_path.exists():
        onnx_path = OUTPUT_DIR / "widps_model.onnx"
    if not onnx_path.exists():
        print(f"[SKIP] No ONNX model found")
        return None

    session = ort.InferenceSession(str(onnx_path))
    input_name = session.get_inputs()[0].name

    for _ in range(5):
        session.run(None, {input_name: X[:1]})

    t0 = time.perf_counter()
    results = session.run(None, {input_name: X})
    elapsed = time.perf_counter() - t0

    y_pred = results[0]
    y_proba = results[1]

    print_metrics(y, y_pred, y_proba, label_names, elapsed, len(X), "ONNX")
    return y_pred


def print_metrics(y_true, y_pred, y_proba, label_names, elapsed, n_samples, model_tag):
    acc = accuracy_score(y_true, y_pred)
    f1_macro = f1_score(y_true, y_pred, average="macro")
    f1_weighted = f1_score(y_true, y_pred, average="weighted")
    precision_macro = precision_score(y_true, y_pred, average="macro")
    recall_macro = recall_score(y_true, y_pred, average="macro")

    avg_ms = (elapsed / n_samples) * 1000
    total_ms = elapsed * 1000

    print(f"\n  Samples tested:     {n_samples}")
    print(f"  Total time:         {total_ms:.1f} ms")
    print(f"  Avg per sample:     {avg_ms:.4f} ms")
    print(f"  Throughput:         {n_samples/elapsed:.0f} samples/sec")
    print(f"\n  Accuracy:           {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision (macro):  {precision_macro:.4f}")
    print(f"  Recall (macro):     {recall_macro:.4f}")
    print(f"  F1 Score (macro):   {f1_macro:.4f}")
    print(f"  F1 Score (weighted):{f1_weighted:.4f}")

    try:
        if y_proba is not None and len(y_proba.shape) == 2:
            auc = roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro")
            print(f"  ROC-AUC (macro):    {auc:.4f}")
    except Exception:
        pass

    print(f"\n  Per-class report:")
    print(classification_report(y_true, y_pred, target_names=label_names, digits=4))

    cm = confusion_matrix(y_true, y_pred)
    print(f"  Confusion Matrix:")
    header = "  {:>12s}".format("") + "".join(f"{n[:8]:>9s}" for n in label_names)
    print(header)
    for i, row in enumerate(cm):
        row_str = "  {:>12s}".format(label_names[i][:12]) + "".join(f"{v:>9d}" for v in row)
        print(row_str)

    results = {
        "model": model_tag,
        "accuracy": round(acc, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "precision_macro": round(precision_macro, 4),
        "recall_macro": round(recall_macro, 4),
        "avg_inference_ms": round(avg_ms, 4),
        "samples_tested": n_samples,
    }
    results_path = OUTPUT_DIR / f"test_results_{model_tag.lower()}.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  [Saved] {results_path}")


def test_per_class_breakdown(X, y, y_names, label_names):
    print("\n" + "=" * 60)
    print("PER-CLASS SAMPLE DISTRIBUTION (Test Set)")
    print("=" * 60)

    from collections import Counter
    dist = Counter(y_names)
    total = sum(dist.values())
    print(f"\n  {'Class':<20s} {'Count':>8s} {'Percentage':>12s}")
    print(f"  {'-'*20} {'-'*8} {'-'*12}")
    for cls in sorted(dist.keys()):
        count = dist[cls]
        pct = count / total * 100
        print(f"  {cls:<20s} {count:>8d} {pct:>10.1f}%")
    print(f"  {'TOTAL':<20s} {total:>8d} {'100.0%':>12s}")


def main():
    print("=" * 60)
    print("WIDPS - Model Testing Suite (70/30 split)")
    print("=" * 60)

    result = load_test_data()
    if result[0] is None:
        return
    X, y, label_names, y_names = result

    print(f"\n[Data] Test set: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"[Data] Classes: {label_names}")

    test_per_class_breakdown(X, y, y_names, label_names)

    test_sklearn_model(X, y, label_names)
    test_sklearn_fast_model(X, y, label_names)
    test_xgboost_model(X, y, label_names)
    test_onnx_model(X, y, label_names)

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)

    result_files = list(OUTPUT_DIR.glob("test_results_*.json"))
    if result_files:
        print("\n  Model Comparison:")
        print(f"  {'Model':<12s} {'Accuracy':>10s} {'F1 Macro':>10s} {'Inference':>12s}")
        print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*12}")
        for rf in sorted(result_files):
            with open(rf) as f:
                r = json.load(f)
            print(f"  {r['model']:<12s} {r['accuracy']:>9.4f} {r['f1_macro']:>9.4f} {r['avg_inference_ms']:>9.4f} ms")


if __name__ == "__main__":
    main()
