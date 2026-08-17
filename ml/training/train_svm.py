import os
import joblib
from sklearn.svm import SVC

def train_svm(X_train, y_train, model_dir):
    print("[ML TRAIN] Training Support Vector Machine (SVM) Classifier...")
    svm_model = SVC(
        kernel='rbf',
        C=1.0,
        probability=True,
        random_state=42
    )
    svm_model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "svm.joblib")
    joblib.dump(svm_model, model_path)
    print(f"[ML TRAIN] SVM model saved to {model_path}")
    return svm_model
