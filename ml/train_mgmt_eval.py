"""
Train and evaluate the management-frame model with a split by capture file.

Reads ml/output_mgmt/ (produced by extract_mgmt_features.py), where whole
capture files are assigned to train or test. Reports:

* hold-out results on files the model never saw,
* grouped cross-validation (GroupKFold by capture file) over all data,
* a rules-only baseline (deauth/disassoc ratio threshold) on the same test set.

Usage (from the repository root):
    ml/.venv/bin/python ml/train_mgmt_eval.py
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold

OUT = Path("ml/output_mgmt")
SEED = 42
META = ("label", "label_name", "file", "folder")

RF_PARAMS = dict(n_estimators=150, max_depth=15, min_samples_leaf=5,
                 min_samples_split=10, class_weight="balanced", n_jobs=-1, random_state=SEED)


def main():
    train = pd.read_csv(OUT / "features_train.csv")
    test = pd.read_csv(OUT / "features_test.csv")
    feats = [c for c in train.columns if c not in META]
    le = joblib.load(OUT / "label_encoder.joblib")

    Xtr, ytr = train[feats].to_numpy(), train["label_name"].to_numpy()
    Xte, yte = test[feats].to_numpy(), test["label_name"].to_numpy()

    print(f"Train windows: {len(train)} from {train['file'].nunique()} files")
    print(f"Test windows:  {len(test)} from {test['file'].nunique()} files (unseen)")
    print("Train classes:", train["label_name"].value_counts().to_dict())
    print("Test classes: ", test["label_name"].value_counts().to_dict())

    # The model is trained on integer-encoded labels because ml/inference.py
    # indexes predict_proba() with the predicted class.
    rf = RandomForestClassifier(**RF_PARAMS).fit(Xtr, train["label"].to_numpy())
    pred = le.inverse_transform(rf.predict(Xte))
    labels = sorted(set(yte) | set(pred) | set(ytr))

    report = classification_report(yte, pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(yte, pred, labels=labels)
    holdout = {
        "accuracy": float(accuracy_score(yte, pred)),
        "f1_macro": float(f1_score(yte, pred, labels=labels, average="macro", zero_division=0)),
        "per_class": {k: v for k, v in report.items() if k in labels},
        "labels": labels,
        "confusion_matrix": cm.tolist(),
    }

    # Grouped CV over every file (train + test) so each fold tests on unseen files.
    full = pd.concat([train, test], ignore_index=True)
    X, y, groups = full[feats].to_numpy(), full["label_name"].to_numpy(), full["file"].to_numpy()
    y_int = full["label"].to_numpy()
    n_splits = min(5, len(set(groups)))
    accs, f1s = [], []
    for tr_idx, te_idx in GroupKFold(n_splits=n_splits).split(X, y, groups):
        m = RandomForestClassifier(**RF_PARAMS).fit(X[tr_idx], y_int[tr_idx])
        p = le.inverse_transform(m.predict(X[te_idx]))
        accs.append(accuracy_score(y[te_idx], p))
        f1s.append(f1_score(y[te_idx], p, average="macro", zero_division=0))
    grouped_cv = {
        "scheme": f"GroupKFold({n_splits}) by capture file",
        "accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
        "f1_macro_mean": float(np.mean(f1s)), "f1_macro_std": float(np.std(f1s)),
    }

    # Rules-only baseline: a deauth/disassoc ratio threshold, nothing else.
    ratio = test["deauth_disassoc_ratio"].to_numpy()
    rule_pred = np.where(ratio >= 0.3, "Deauth_Flood", "Normal")
    rule = {
        "rule": "Deauth_Flood if deauth_disassoc_ratio >= 0.3 else Normal",
        "accuracy": float(accuracy_score(yte, rule_pred)),
        "f1_macro": float(f1_score(yte, rule_pred, average="macro", zero_division=0)),
        "recall_deauth_flood": float(
            ((rule_pred == "Deauth_Flood") & (yte == "Deauth_Flood")).sum() / max((yte == "Deauth_Flood").sum(), 1)),
    }

    joblib.dump(rf, OUT / "model_rf.joblib")
    result = {"holdout_unseen_files": holdout, "grouped_cv": grouped_cv, "rules_baseline": rule,
              "train_windows": int(len(train)), "test_windows": int(len(test)),
              "train_files": int(train["file"].nunique()), "test_files": int(test["file"].nunique())}
    (OUT / "eval_report.json").write_text(json.dumps(result, indent=2))

    print("\n=== Hold-out on unseen files ===")
    print(classification_report(yte, pred, labels=labels, zero_division=0))
    print("Confusion matrix (rows = true, cols = predicted):", labels)
    print(cm)
    print("\n=== Grouped CV ===")
    print(json.dumps(grouped_cv, indent=2))
    print("\n=== Rules baseline ===")
    print(json.dumps(rule, indent=2))


if __name__ == "__main__":
    main()
