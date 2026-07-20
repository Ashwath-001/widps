import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
)
from sklearn.model_selection import cross_val_score
import joblib
import warnings
import time

warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[WARN] XGBoost not installed. Only Random Forest will be trained.")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLT = True
except ImportError:
    HAS_PLT = False

OUTPUT_DIR = Path("ml/output")
SEED = 42


def load_data():
    train_path = OUTPUT_DIR / "features_train.csv"
    test_path = OUTPUT_DIR / "features_test.csv"

    if not train_path.exists():
        print(f"[ERROR] {train_path} not found. Run feature_extraction.py first.")
        return None, None, None, None, None

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    feature_cols = [c for c in train_df.columns if c not in ("label", "label_name")]

    X_train = train_df[feature_cols].values
    y_train = train_df["label"].values
    X_test = test_df[feature_cols].values
    y_test = test_df["label"].values

    label_names = sorted(train_df["label_name"].unique())

    print(f"[Data] Train: {X_train.shape} | Test: {X_test.shape}")
    print(f"[Data] Classes: {label_names}")
    print(f"[Data] Features per sample: {X_train.shape[1]}")

    return X_train, y_train, X_test, y_test, label_names


def train_random_forest(X_train, y_train, X_test, y_test, label_names):
    print("\n" + "=" * 60)
    print("RANDOM FOREST CLASSIFIER")
    print("=" * 60)

    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_leaf=5,
        min_samples_split=10,
        class_weight="balanced",
        n_jobs=-1,
        random_state=SEED,
    )

    t0 = time.time()
    rf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.2f}s")

    t0 = time.time()
    y_pred = rf.predict(X_test)
    pred_time = time.time() - t0
    avg_inference_ms = (pred_time / len(X_test)) * 1000

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")

    print(f"  Accuracy:         {acc:.4f}")
    print(f"  F1 (macro):       {f1_macro:.4f}")
    print(f"  F1 (weighted):    {f1_weighted:.4f}")
    print(f"  Avg inference:    {avg_inference_ms:.3f} ms/sample")

    report = classification_report(y_test, y_pred, target_names=label_names)
    print(f"\n  Classification Report:\n{report}")

    print("  Running 5-fold cross-validation...")
    cv_scores = cross_val_score(rf, X_train, y_train, cv=5, scoring="f1_macro", n_jobs=-1)
    print(f"  CV F1 (macro): {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    model_path = OUTPUT_DIR / "model_rf.joblib"
    joblib.dump(rf, model_path)
    print(f"\n  [Saved] {model_path}")

    return rf, y_pred, acc, f1_macro


def train_xgboost(X_train, y_train, X_test, y_test, label_names):
    if not HAS_XGB:
        return None, None, 0, 0

    print("\n" + "=" * 60)
    print("XGBOOST CLASSIFIER")
    print("=" * 60)

    num_classes = len(set(y_train))

    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        use_label_encoder=False,
        num_class=num_classes,
        n_jobs=-1,
        random_state=SEED,
        verbosity=0,
    )

    t0 = time.time()
    xgb.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.2f}s")

    t0 = time.time()
    y_pred = xgb.predict(X_test)
    pred_time = time.time() - t0
    avg_inference_ms = (pred_time / len(X_test)) * 1000

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")

    print(f"  Accuracy:         {acc:.4f}")
    print(f"  F1 (macro):       {f1_macro:.4f}")
    print(f"  F1 (weighted):    {f1_weighted:.4f}")
    print(f"  Avg inference:    {avg_inference_ms:.3f} ms/sample")

    report = classification_report(y_test, y_pred, target_names=label_names)
    print(f"\n  Classification Report:\n{report}")

    model_path = OUTPUT_DIR / "model_xgb.joblib"
    joblib.dump(xgb, model_path)
    print(f"\n  [Saved] {model_path}")

    return xgb, y_pred, acc, f1_macro


def plot_confusion_matrix(y_test, y_pred, label_names, model_name="RF"):
    if not HAS_PLT:
        return

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)

    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=label_names,
        yticklabels=label_names,
        title=f"Confusion Matrix - {model_name}",
        ylabel="True Label",
        xlabel="Predicted Label",
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")

    fig.tight_layout()
    path = OUTPUT_DIR / f"confusion_matrix_{model_name.lower()}.png"
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [Saved] {path}")


def plot_feature_importance(model, feature_names, top_n=25, model_name="RF"):
    if not HAS_PLT:
        return

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(range(top_n), importances[indices][::-1], align="center", color="#3B82F6")
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([feature_names[i] for i in indices][::-1], fontsize=8)
    ax.set_xlabel("Feature Importance")
    ax.set_title(f"Top {top_n} Feature Importances - {model_name}")
    fig.tight_layout()

    path = OUTPUT_DIR / f"feature_importance_{model_name.lower()}.png"
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [Saved] {path}")


def save_report(rf_acc, rf_f1, xgb_acc, xgb_f1, label_names, y_test, rf_pred, xgb_pred):
    report_path = OUTPUT_DIR / "classification_report.txt"

    with open(report_path, "w") as f:
        f.write("WIDPS - ML Model Evaluation Report\n")
        f.write("=" * 60 + "\n\n")

        f.write("RANDOM FOREST\n")
        f.write("-" * 40 + "\n")
        f.write(f"Accuracy: {rf_acc:.4f}\n")
        f.write(f"F1 Macro: {rf_f1:.4f}\n")
        f.write(classification_report(y_test, rf_pred, target_names=label_names))
        f.write("\n\n")

        if xgb_pred is not None:
            f.write("XGBOOST\n")
            f.write("-" * 40 + "\n")
            f.write(f"Accuracy: {xgb_acc:.4f}\n")
            f.write(f"F1 Macro: {xgb_f1:.4f}\n")
            f.write(classification_report(y_test, xgb_pred, target_names=label_names))
            f.write("\n\n")

        best = "Random Forest" if rf_f1 >= xgb_f1 else "XGBoost"
        f.write("COMPARISON\n")
        f.write("-" * 40 + "\n")
        f.write(f"Best model (by F1 macro): {best}\n")

    print(f"\n[Saved] {report_path}")


def main():
    print("=" * 70)
    print("WIDPS - Model Training Pipeline")
    print("=" * 70)

    result = load_data()
    if result[0] is None:
        return
    X_train, y_train, X_test, y_test, label_names = result

    feature_names_path = OUTPUT_DIR / "feature_names.txt"
    if feature_names_path.exists():
        feature_names = feature_names_path.read_text().strip().split("\n")
    else:
        feature_names = [f"f_{i}" for i in range(X_train.shape[1])]

    rf, rf_pred, rf_acc, rf_f1 = train_random_forest(
        X_train, y_train, X_test, y_test, label_names
    )

    xgb, xgb_pred, xgb_acc, xgb_f1 = train_xgboost(
        X_train, y_train, X_test, y_test, label_names
    )

    print("\n[Plots] Generating visualizations...")
    plot_confusion_matrix(y_test, rf_pred, label_names, "RF")
    plot_feature_importance(rf, feature_names, top_n=25, model_name="RF")

    if xgb is not None and xgb_pred is not None:
        plot_confusion_matrix(y_test, xgb_pred, label_names, "XGB")
        plot_feature_importance(xgb, feature_names, top_n=25, model_name="XGB")

    save_report(rf_acc, rf_f1, xgb_acc, xgb_f1, label_names,
                y_test, rf_pred, xgb_pred)

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print(f"\n  Random Forest:  Accuracy={rf_acc:.4f}  F1={rf_f1:.4f}")
    if xgb is not None:
        print(f"  XGBoost:        Accuracy={xgb_acc:.4f}  F1={xgb_f1:.4f}")
        winner = "Random Forest" if rf_f1 >= xgb_f1 else "XGBoost"
        print(f"\n  Winner: {winner}")

    print(f"\n  Models saved to: {OUTPUT_DIR}/")
    print("=" * 70)


if __name__ == "__main__":
    main()
