import os
import json
import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def evaluate_all_models(X_test, y_test, model_dir):
    print("[ML EVALUATION] Evaluating all trained models on test dataset...")
    metrics = {}

    rf_path = os.path.join(model_dir, "random_forest.joblib")
    svm_path = os.path.join(model_dir, "svm.joblib")
    ann_path = os.path.join(model_dir, "ann.joblib")
    iso_path = os.path.join(model_dir, "isolation_forest.joblib")

    # 1. Random Forest
    if os.path.exists(rf_path):
        rf = joblib.load(rf_path)
        y_pred = rf.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        metrics['Random Forest'] = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1_score': float(f1_score(y_test, y_pred)),
            'fpr': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    # 2. SVM
    if os.path.exists(svm_path):
        svm = joblib.load(svm_path)
        y_pred = svm.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        metrics['SVM'] = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1_score': float(f1_score(y_test, y_pred)),
            'fpr': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    # 3. ANN
    if os.path.exists(ann_path):
        ann = joblib.load(ann_path)
        y_pred = ann.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        metrics['ANN'] = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1_score': float(f1_score(y_test, y_pred)),
            'fpr': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    # 4. Isolation Forest (Anomaly Detection)
    if os.path.exists(iso_path):
        iso = joblib.load(iso_path)
        # Isolation Forest returns -1 for anomaly, 1 for normal
        raw_pred = iso.predict(X_test)
        y_pred = np.where(raw_pred == -1, 1, 0) # Map anomaly to 1 (malicious)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        metrics['Isolation Forest'] = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
            'fpr': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    output_path = os.path.join(model_dir, "evaluation_metrics.json")
    with open(output_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[ML EVALUATION] Evaluation results saved to {output_path}")
    return metrics
