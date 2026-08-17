import os
import joblib
from sklearn.ensemble import IsolationForest

def train_isolation_forest(X_train, y_train, model_dir):
    print("[ML TRAIN] Training Isolation Forest Anomaly Detector...")
    # Train Isolation Forest primarily on safe baseline samples
    X_safe = X_train[y_train == 0]
    
    if len(X_safe) == 0:
        X_safe = X_train

    iso_model = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_safe)

    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "isolation_forest.joblib")
    joblib.dump(iso_model, model_path)
    print(f"[ML TRAIN] Isolation Forest model saved to {model_path}")
    return iso_model
