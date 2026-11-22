import numpy as np
import joblib
from pathlib import Path
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as ort

OUTPUT_DIR = Path("ml/output")
MODEL_PATH = OUTPUT_DIR / "model_rf.joblib"
MODEL_FAST_PATH = OUTPUT_DIR / "model_rf_fast.joblib"
FEATURE_NAMES_PATH = OUTPUT_DIR / "feature_names.txt"
LABEL_ENCODER_PATH = OUTPUT_DIR / "label_encoder.joblib"


def export_model(model_path, onnx_filename):
    print(f"\n[Export] Loading {model_path}...")
    model = joblib.load(model_path)
    n_features = len(FEATURE_NAMES_PATH.read_text().strip().split("\n"))

    print(f"[Export] Model: {model.n_estimators} trees, max_depth={model.max_depth}")
    print(f"[Export] Input: {n_features} features (float32)")

    initial_type = [("features", FloatTensorType([None, n_features]))]

    print("[Export] Converting to ONNX...")
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=15,
        options={id(model): {"zipmap": False}},
    )

    onnx_path = OUTPUT_DIR / onnx_filename
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = onnx_path.stat().st_size / 1024
    print(f"[Export] Saved: {onnx_path} ({size_kb:.0f} KB)")
    return onnx_path


def validate_onnx(onnx_path, original_model_path):
    print(f"\n[Validate] Loading ONNX model...")
    session = ort.InferenceSession(str(onnx_path))

    input_name = session.get_inputs()[0].name
    print(f"[Validate] Input: name='{input_name}', shape={session.get_inputs()[0].shape}")
    for out in session.get_outputs():
        print(f"[Validate] Output: name='{out.name}', shape={out.shape}, type={out.type}")

    le = joblib.load(LABEL_ENCODER_PATH)
    original_model = joblib.load(original_model_path)

    n_features = len(FEATURE_NAMES_PATH.read_text().strip().split("\n"))
    np.random.seed(42)
    test_input = np.random.randn(10, n_features).astype(np.float32)

    original_preds = original_model.predict(test_input)
    original_proba = original_model.predict_proba(test_input)

    onnx_results = session.run(None, {input_name: test_input})
    onnx_preds = onnx_results[0]
    onnx_proba = onnx_results[1]

    match_count = np.sum(original_preds == onnx_preds)
    print(f"\n[Validate] Prediction match: {match_count}/10")

    max_proba_diff = np.max(np.abs(original_proba - onnx_proba))
    print(f"[Validate] Max probability difference: {max_proba_diff:.6f}")

    if match_count == 10 and max_proba_diff < 1e-5:
        print("[Validate] PASS - ONNX model matches sklearn exactly")
    elif match_count >= 9:
        print("[Validate] PASS - Minor floating point differences (acceptable)")
    else:
        print("[Validate] WARN - Significant differences detected")

    print(f"\n[Validate] Class labels: {le.classes_.tolist()}")


def benchmark_onnx(onnx_path):
    import time

    session = ort.InferenceSession(str(onnx_path))
    input_name = session.get_inputs()[0].name
    n_features = len(FEATURE_NAMES_PATH.read_text().strip().split("\n"))

    test_input = np.random.randn(1, n_features).astype(np.float32)

    for _ in range(10):
        session.run(None, {input_name: test_input})

    n_iters = 1000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        session.run(None, {input_name: test_input})
    elapsed = time.perf_counter() - t0

    avg_ms = (elapsed / n_iters) * 1000
    print(f"\n[Benchmark] ONNX inference: {avg_ms:.3f} ms/sample ({n_iters} iterations)")
    print(f"[Benchmark] Throughput: {n_iters/elapsed:.0f} predictions/sec")

    original_model = joblib.load(MODEL_FAST_PATH if MODEL_FAST_PATH.exists() else MODEL_PATH)
    t0 = time.perf_counter()
    for _ in range(n_iters):
        original_model.predict(test_input)
        original_model.predict_proba(test_input)
    elapsed_sk = time.perf_counter() - t0
    avg_ms_sk = (elapsed_sk / n_iters) * 1000

    print(f"[Benchmark] sklearn inference: {avg_ms_sk:.3f} ms/sample")
    speedup = avg_ms_sk / avg_ms
    print(f"[Benchmark] ONNX speedup: {speedup:.1f}x faster")


def main():
    print("=" * 60)
    print("WIDPS - ONNX Model Export")
    print("=" * 60)

    if MODEL_FAST_PATH.exists():
        onnx_path = export_model(MODEL_FAST_PATH, "widps_model_fast.onnx")
        validate_onnx(onnx_path, MODEL_FAST_PATH)
        benchmark_onnx(onnx_path)

    if MODEL_PATH.exists():
        onnx_path = export_model(MODEL_PATH, "widps_model.onnx")
        validate_onnx(onnx_path, MODEL_PATH)
        benchmark_onnx(onnx_path)

    print("\n" + "=" * 60)
    print("EXPORT COMPLETE")
    print("=" * 60)
    print(f"\nFiles:")
    for f in sorted(OUTPUT_DIR.glob("*.onnx")):
        print(f"  {f} ({f.stat().st_size/1024:.0f} KB)")
    print(f"\nRust integration (tract crate):")
    print(f"  use tract_onnx::prelude::*;")
    print(f"  let model = tract_onnx::onnx()")
    print(f'      .model_for_path("ml/output/widps_model_fast.onnx")?')
    print(f"      .into_optimized()?")
    print(f"      .into_runnable()?;")
    print(f"  let input = tract_ndarray::arr2(&[features]);")
    print(f"  let result = model.run(tvec!(input.into()))?;")
    print("=" * 60)


if __name__ == "__main__":
    main()
