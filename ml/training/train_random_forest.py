import os
import joblib
from sklearn.ensemble import RandomForestClassifier

def train_random_forest(X_train, y_train, model_dir):
    print("[ML TRAIN] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "random_forest.joblib")
    joblib.dump(rf_model, model_path)
    print(f"[ML TRAIN] Random Forest model saved to {model_path}")
    return rf_model
