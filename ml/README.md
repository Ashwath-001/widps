# WIDPS ML Pipeline — Complete Guide

## Overview

The ML subsystem provides 3-tier intelligent detection alongside the rule-based engine:

| Model | Type | Purpose | Accuracy | Script |
|-------|------|---------|----------|--------|
| Random Forest | Supervised | Classify 6 known attack types | 99.55% | `train_model.py` |
| Isolation Forest | Unsupervised | Detect unknown/zero-day anomalies | N/A | `isolation_forest.py` |
| SHAP Explainer | Post-hoc | Explain classification decisions | N/A | `shap_explainer.py` |
| Online Learner | Incremental | Improve model from admin feedback | ≥99% gate | `online_trainer.py` |

---

## Quick Start (Train Everything from Scratch)

```bash
# 1. Setup
cd ml
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Feature extraction (takes ~2-5 min on AWID3 dataset)
python feature_extraction.py

# 3. Train supervised classifier
python train_model.py

# 4. Train zero-day anomaly detector
python isolation_forest.py --train

# 5. Verify
python inference.py --simulate
python inference.py --benchmark

# 6. (Optional) Export ONNX for Rust-native inference
python inference.py --export-onnx

# 7. (Optional) Evaluate and get confusion matrix
python inference.py --evaluate-json
```

Total time: ~5 minutes on Pi 5, ~1 minute on a laptop.

---

## Prerequisites & Installation

### System Requirements
- Python 3.10+
- 4GB RAM minimum (8GB recommended for SHAP)
- AWID3 dataset in `dataset/archive/CSV/`

### Python Environment Setup

```bash
cd ml
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

### Dependencies (`requirements.txt`)

| Package | Version | Purpose |
|---------|---------|---------|
| numpy | ≥1.24.0 | Numerical computation |
| pandas | ≥2.0.0 | DataFrame operations, CSV loading |
| scikit-learn | ≥1.3.0 | Random Forest, Isolation Forest, metrics |
| xgboost | ≥2.0.0 | Alternative classifier (optional) |
| matplotlib | ≥3.7.0 | Training visualization plots |
| joblib | ≥1.3.0 | Model serialization |
| skl2onnx | latest | ONNX conversion |
| onnxruntime | latest | ONNX inference verification |
| shap | ≥0.43.0 | Explainability (SHAP values) |

---

## Pipeline Architecture

```
 AWID3 CSV Dataset        Feature Extraction        Model Training
┌──────────────────┐     ┌──────────────────────┐   ┌─────────────────────┐
│ 1.Deauth/        │────►│ feature_extraction.py │──►│ train_model.py      │
│ 2.Disas/         │     │                      │   │  → model_rf.joblib  │
│ 3.(Re)Assoc/     │     │ Tokenize frames      │   └─────────────────────┘
│ 4.Rogue_AP/      │     │ Build 1s windows     │            │
│ 5.Krack/         │     │ Extract 20 stats     │            ▼
│ 6.Kr00k/         │     │ TF-IDF (100 dims)    │   ┌─────────────────────┐
│ 12.Evil_Twin/    │     │                      │   │ isolation_forest.py │
│ (Normal class)   │     │ Output:              │   │  → if_model.joblib  │
└──────────────────┘     │  features_train.csv  │   └─────────────────────┘
                         │  features_test.csv   │            │
                         │  tfidf_vectorizer    │            ▼
                         │  label_encoder       │   ┌─────────────────────┐
                         └──────────────────────┘   │ inference.py --stdin│
                                                    │ (Rust integration)  │
                                                    └─────────────────────┘
```

---

## Step-by-Step Training Guide

### Step 1: Feature Extraction

Converts raw 802.11 frames from AWID3 CSVs into labeled 1-second time windows.

```bash
python feature_extraction.py
```

**Input:** `dataset/archive/CSV/` — AWID3 folders

**Dataset Folder → Label Mapping:**

| Folder | Assigned Label | Attack Type |
|--------|---------------|-------------|
| `1.Deauth/` | Deauth_Flood | Deauthentication flood |
| `2.Disas/` | Deauth_Flood | Disassociation flood |
| `3.(Re)Assoc/` | Auth_Flood | Authentication/association flood |
| `4.Rogue_AP/` | Evil_Twin | Rogue AP / Evil Twin |
| `12.Evil_Twin/` | Evil_Twin | Evil Twin with credential theft |
| `5.Krack/` | Krack | Key Reinstallation Attack |
| `6.Kr00k/` | Kr00k | Encryption key zeroing exploit |
| All other traffic | Normal | Legitimate traffic |

**NLP-Inspired Frame Tokenization:**

Each 802.11 frame is converted into a text token:
```
T{type}S{subtype}_B{broadcast}_R{reason}_P{protected}_RT{retry}_D{duration_bin}
```

Example tokens:
- `T0S12_B1_R1_P0_RT0_D0` → Deauth frame, broadcast, has reason code
- `T0S8_B1_R0_P0_RT0_D0` → Beacon frame, broadcast, no reason
- `T2S0_B0_R0_P1_RT0_DM` → Data frame, unicast, protected, medium duration

A 1-second window of frames becomes a "sentence" of tokens, vectorized with TF-IDF.

**Window Construction:**
- Duration: 1.0 second (configurable via `WINDOW_SIZE_SEC`)
- Label assignment: If >5% of frames in window are attack, label = majority attack type
- Frames grouped by `frame.time_relative` field

**20 Statistical Features Per Window:**

| # | Feature Name | Description |
|---|-------------|-------------|
| 1 | `frame_count` | Total frames in window |
| 2 | `rssi_mean` | Average signal strength (dBm) |
| 3 | `rssi_std` | Signal strength variation |
| 4 | `inter_frame_time_mean` | Average gap between frames |
| 5 | `inter_frame_time_min` | Minimum gap (burst indicator) |
| 6 | `inter_frame_time_std` | Timing regularity |
| 7 | `frame_length_mean` | Average frame size (bytes) |
| 8 | `frame_length_std` | Frame size variation |
| 9 | `unique_subtypes` | Number of distinct frame subtypes |
| 10 | `deauth_disassoc_ratio` | % deauth+disassoc frames |
| 11 | `beacon_ratio` | % beacon frames |
| 12 | `probe_request_ratio` | % probe request frames |
| 13 | `probe_response_ratio` | % probe response frames |
| 14 | `broadcast_ratio` | % broadcast destination frames |
| 15 | `unique_src_macs` | Distinct source MAC addresses |
| 16 | `unique_dst_macs` | Distinct destination MAC addresses |
| 17 | `protected_frame_ratio` | % frames with encryption flag |
| 18 | `seq_anomaly_backward_ratio` | % backward sequence jumps |
| 19 | `seq_anomaly_jump_ratio` | % large sequence jumps (>500) |
| 20 | `duration_mean` | Average frame duration field |

**100 TF-IDF Features:**
- N-gram range: (1, 3) — unigrams, bigrams, trigrams of frame tokens
- Max features: 100 (most informative n-grams selected)
- Vocabulary captures frame type transition patterns

**Total feature vector: 120 dimensions** (20 stats + 100 TF-IDF)

**Output files (in `ml/output/`):**

| File | Description |
|------|-------------|
| `features_train.csv` | 70% of windows (training set) |
| `features_test.csv` | 30% of windows (held-out test set) |
| `tfidf_vectorizer.joblib` | Fitted TF-IDF vectorizer (for inference) |
| `label_encoder.joblib` | Label ↔ integer mapping |
| `feature_names.txt` | All 120 feature column names |

**Required CSV Columns from AWID3:**

```
wlan.fc.type, wlan.fc.subtype, wlan.da, wlan.sa, wlan.fixed.reason_code,
wlan.fc.protected, wlan.fc.retry, wlan.duration, frame.time_relative,
frame.time_delta, frame.len, radiotap.dbm_antsignal, radiotap.channel.freq,
radiotap.datarate, wlan.seq, wlan.ssid, wlan.bssid, Label
```

---

### Step 2: Train Random Forest Classifier

```bash
python train_model.py
```

**Hyperparameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `n_estimators` | 150 | Balances accuracy vs inference time |
| `max_depth` | 15 | Prevents overfitting while capturing patterns |
| `min_samples_leaf` | 5 | Ensures leaf nodes have enough support |
| `min_samples_split` | 10 | Prevents splits on noise |
| `class_weight` | "balanced" | Handles class imbalance in dataset |
| `n_jobs` | -1 | Uses all CPU cores for training |
| `random_state` | 42 | Reproducible results |

**What it does:**
1. Loads `features_train.csv` and `features_test.csv`
2. Trains Random Forest with 5-fold cross-validation
3. Evaluates on held-out test set
4. Prints classification report (precision, recall, F1 per class)
5. Prints confusion matrix
6. If XGBoost installed, also trains XGBClassifier for comparison
7. Saves the best model as `model_rf.joblib`
8. Generates accuracy plot if matplotlib available

**Output:**
- `ml/output/model_rf.joblib` — serialized sklearn RandomForestClassifier

**Expected Results:**
```
Classes: ['Auth_Flood', 'Deauth_Flood', 'Evil_Twin', 'Krack', 'Kr00k', 'Normal']
Accuracy: 99.55%
F1 (macro): 0.9952
```

---

### Step 3: Train Isolation Forest (Zero-Day Detection)

```bash
python isolation_forest.py --train
```

**Purpose:** Detects unknown attacks that the Random Forest hasn't been trained on.

**How it works:**
1. Extracts only Normal-class windows from training data
2. Normalizes features with StandardScaler
3. Trains Isolation Forest to model "normal" distribution
4. At runtime: if RF says "Normal" but IF says "anomaly" with >60% confidence → flag as `Zero_Day_Anomaly`

**Hyperparameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `n_estimators` | 150 | More trees = more stable anomaly scores |
| `contamination` | 0.05 | Assumes ≤5% mislabeled normal in training |
| `max_samples` | auto | sqrt(n_samples) per tree |
| `random_state` | 42 | Reproducibility |

**Output:**
- `ml/output/isolation_forest.joblib` — trained model
- `ml/output/if_scaler.joblib` — fitted StandardScaler

**Testing:**
```bash
python isolation_forest.py --test
```
Reports anomaly detection rate on test set by class.

---

### Step 4: ONNX Export (Optional)

```bash
python inference.py --export-onnx
```

Converts the Random Forest to ONNX for Rust-native inference via the `tract` or `onnxruntime` crate. Enables sub-1ms inference on ARM without Python.

**Output:** `ml/output/widps_model.onnx`

**Requirements:** `pip install skl2onnx`

---

## Inference Modes

### `--stdin` (Production: Rust Backend Integration)

```bash
python inference.py --stdin
```

The Rust backend spawns this as a long-running subprocess. Communication is JSON over stdin/stdout:

**Input (one JSON frame per line on stdin):**
```json
{
  "fc_type": 0,
  "fc_subtype": 12,
  "dst": "ff:ff:ff:ff:ff:ff",
  "src": "aa:bb:cc:dd:ee:ff",
  "rssi": -65,
  "frame_length": 86,
  "duration": 0,
  "protected": 0,
  "retry": 0,
  "reason_code": 7,
  "seq_num": 1024,
  "inter_frame_time": 0.001,
  "timestamp": 1723567890.123
}
```

**Output (one JSON prediction per completed 1-second window on stdout):**
```json
{
  "label": "Deauth_Flood",
  "confidence": 0.9823,
  "probabilities": {
    "Normal": 0.0102,
    "Deauth_Flood": 0.9823,
    "Auth_Flood": 0.0015,
    "Evil_Twin": 0.0023,
    "Krack": 0.0012,
    "Kr00k": 0.0025
  },
  "threat_score": 83,
  "inference_ms": 2.1,
  "frame_count": 127,
  "window_duration_sec": 1.0,
  "isolation_forest": {
    "is_anomaly": false,
    "confidence": 0.12,
    "anomaly_score": 0.31
  },
  "shap_explanation": {
    "top_features": [
      {"name": "deauth_disassoc_ratio", "shap_value": 0.42, "direction": "attack"},
      {"name": "inter_frame_time_min", "shap_value": -0.38, "direction": "attack"},
      {"name": "frame_count", "shap_value": 0.21, "direction": "attack"}
    ],
    "base_value": 0.16,
    "explain_ms": 4.2
  }
}
```

**Threat Score Calculation:**
```python
severity_weights = {
    "Normal": 0, "Auth_Flood": 60, "Deauth_Flood": 85,
    "Evil_Twin": 90, "Krack": 95, "Kr00k": 80
}
threat_score = int(severity_weights[label] * confidence)
```

### `--simulate` (Test Without Hardware)

```bash
python inference.py --simulate
```

Replays the test dataset through the full pipeline. Reports per-window predictions, accuracy, and alerts fired.

### `--live` (Watch Files)

```bash
python inference.py --live
```

Monitors `widps_alerts.jsonl` and `widps_networks.json` for new data. Classifies windows from file updates.

### `--evaluate-json` (Confusion Matrix API)

```bash
python inference.py --evaluate-json
```

Evaluates the model on the full test set and outputs a JSON confusion matrix to stdout. Used by the backend's `/api/ai/accuracy` endpoint.

**Output format:**
```json
{
  "matrix": [[980,0,0,0,0,1], [0,450,2,0,0,0], ...],
  "labels": ["Auth_Flood","Deauth_Flood","Evil_Twin","Krack","Kr00k","Normal"],
  "accuracy": 0.9955,
  "total_samples": 2847
}
```

### `--benchmark` (Performance Testing)

```bash
python inference.py --benchmark
```

Generates 100 synthetic windows and measures throughput. Typical results:
- ~500 windows/sec on Pi 5
- ~0.001ms per window in ONNX mode
- ~2ms per window in Python (sklearn predict)

---

## SHAP Explainability

### What Is It?

SHAP (SHapley Additive exPlanations) shows exactly which features caused the model to predict an attack. For each prediction, it attributes a contribution score to every feature.

### How to Use

```bash
# Test on sample data
python shap_explainer.py --test

# Stdin mode (used by inference.py internally)
python shap_explainer.py --stdin
```

### What It Returns

For each non-Normal prediction with confidence ≥50%, SHAP explains which features pushed the decision:

```json
{
  "top_features": [
    {"name": "deauth_disassoc_ratio", "shap_value": 0.42, "contribution_pct": 38.2, "direction": "attack"},
    {"name": "inter_frame_time_min", "shap_value": -0.38, "contribution_pct": 34.5, "direction": "attack"},
    {"name": "frame_count", "shap_value": 0.21, "contribution_pct": 19.1, "direction": "attack"}
  ],
  "base_value": 0.167,
  "explain_ms": 4.2
}
```

**Interpretation:**
- `shap_value > 0` → pushes toward predicted class
- `shap_value < 0` → pushes away from Normal
- `contribution_pct` → relative importance among top features
- `direction` → "attack" means feature supports attack classification

### Integration

SHAP runs inside `inference.py` automatically. Results are:
1. Included in the JSON output on stdout (sent to Rust backend)
2. Stored in SQLite (`shap_explanations` table) via the Rust backend
3. Displayed in the SHAP Explainability dashboard page

---

## Online Learning (Incremental Retraining)

### Concept

The model improves during deployment via admin feedback loop:

```
Alert Appears → Admin Confirms → Label Saved to DB → Retraining → New Model Deployed
```

### Usage

```bash
# Check for pending samples, retrain if ≥10 accumulated
python online_trainer.py --retrain

# Run as background daemon (checks every 60s)
python online_trainer.py --daemon

# Force retrain regardless of sample count
python online_trainer.py --force
```

### Safety Guards

| Guard | Threshold | Action |
|-------|-----------|--------|
| Minimum samples | 10 | Won't retrain with fewer samples |
| Accuracy gate | 99% | Rejects new model if accuracy drops below |
| Backup | Always | Old model saved as `.backup` before replacement |
| Idempotent | samples.used_in_retrain | Samples marked once used |

### How Admin Labels Samples

1. Dashboard → Threat Map or Event Log
2. Click alert → "Confirm Attack" button
3. Select correct label from dropdown
4. POST `/api/alerts/:id/confirm` with `{"label": "Deauth_Flood", "features": [...]}`
5. Saved to `confirmed_samples` table in SQLite

### Retraining Process

1. Load original `features_train.csv`
2. Fetch new confirmed samples from SQLite
3. Append new samples to training data
4. Retrain Random Forest (same hyperparameters)
5. Evaluate on `features_test.csv`
6. If accuracy ≥ 99% → replace model, else reject
7. Retrain Isolation Forest on updated normal baseline
8. Mark samples as `used_in_retrain = 1`

---

## Isolation Forest Deep Dive

### What It Catches

The Isolation Forest catches attacks the Random Forest hasn't seen during training:
- New attack variants not in AWID3 dataset
- Modified versions of known attacks
- Protocol anomalies that don't fit any class
- Novel tooling signatures

### Decision Logic

```python
# Inside inference.py
if rf_label == "Normal" and isolation_forest.is_anomaly and if_confidence > 0.6:
    label = "Zero_Day_Anomaly"
    threat_score = int(70 * if_confidence)
```

### Tuning

Adjust in `isolation_forest.py`:
- `contamination`: Lower (0.01) = fewer false positives, misses more anomalies
- `contamination`: Higher (0.10) = catches more, but more false positives
- Confidence threshold (0.6): Requires high isolation score before overriding RF

---

## File Reference

```
ml/
├── feature_extraction.py    # CSV → tokenization → TF-IDF → train/test split
├── train_model.py           # Random Forest + XGBoost training
├── isolation_forest.py      # Unsupervised zero-day anomaly training
├── inference.py             # All inference modes (stdin, simulate, live, eval, bench)
├── shap_explainer.py        # SHAP TreeExplainer for model interpretability
├── online_trainer.py        # Incremental retraining from admin feedback
├── requirements.txt         # Python dependencies
├── README.md                # This file
└── output/                  # Trained artifacts (gitignored)
    ├── model_rf.joblib          # Main classifier (Random Forest)
    ├── model_rf.joblib.backup   # Previous model (after online retrain)
    ├── isolation_forest.joblib  # Zero-day anomaly detector
    ├── if_scaler.joblib         # Feature normalizer for IF
    ├── tfidf_vectorizer.joblib  # Fitted TF-IDF (maps tokens → features)
    ├── label_encoder.joblib     # Maps class names ↔ integers
    ├── feature_names.txt        # 120 feature names (one per line)
    ├── features_train.csv       # Training windows (70%)
    ├── features_test.csv        # Test windows (30%)
    └── widps_model.onnx         # ONNX export (optional)
```

---

## Integration with Rust Backend

The Rust binary spawns inference.py as a long-running subprocess:

```rust
// In ml_bridge.rs
MlBridge::spawn("ml/.venv/bin/python", "ml/inference.py")
// Internally adds --stdin flag
```

**Data flow:**
1. Rust capture loop receives raw 802.11 frames
2. Each frame is serialized to JSON and written to Python's stdin
3. Python buffers frames into 1-second windows
4. When window completes → predict → write JSON result to stdout
5. Rust reads stdout, parses prediction, broadcasts via SSE
6. Dashboard displays prediction in real-time

**If ML process crashes:** Rust backend continues operating (rule-based detection still active). ML predictions show as "Model Offline" in dashboard.

---

## Backend API Endpoints for ML

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ai/predict` | GET | Current/latest ML prediction |
| `/api/ai/history` | GET | Last 100 predictions from DB |
| `/api/ai/shap` | GET | Last 20 SHAP explanations |
| `/api/ai/accuracy` | GET | Confusion matrix + accuracy (runs evaluation) |
| `/api/alerts/:id/confirm` | POST | Submit confirmed label for retraining |

---

## Troubleshooting

### "Model not found"
```bash
# Train the model first
python ml/train_model.py
```

### "features_test.csv not found"
```bash
# Run feature extraction first
python ml/feature_extraction.py
```

### "SHAP not available"
```bash
pip install shap
```

### "Isolation Forest not trained"
```bash
python ml/isolation_forest.py --train
```

### "XGBoost not installed"
This is optional. Random Forest is the primary model. Install if you want comparison:
```bash
pip install xgboost
```

### Low accuracy after retraining
- Check if confirmed samples have correct labels
- Increase `RETRAIN_THRESHOLD` in online_trainer.py
- Review the rejected model's classification report in stderr output
- Manually inspect `confirmed_samples` table in SQLite

### ML process not connecting to Rust
- Verify venv exists: `ls ml/.venv/bin/python`
- Check model exists: `ls ml/output/model_rf.joblib`
- Run manually: `ml/.venv/bin/python ml/inference.py --stdin` then type a JSON frame

---

## Performance Benchmarks (Raspberry Pi 5, 8GB)

| Metric | Value |
|--------|-------|
| Training time (RF) | ~45 seconds |
| Training time (IF) | ~15 seconds |
| Feature extraction | ~3 minutes (full AWID3) |
| Inference (per window) | ~2ms (Python) / ~0.001ms (ONNX) |
| SHAP explanation | ~4ms per prediction |
| Memory usage | ~180MB (model loaded) |
| Throughput | 500+ windows/sec |
| Startup time | ~3 seconds (model loading) |
