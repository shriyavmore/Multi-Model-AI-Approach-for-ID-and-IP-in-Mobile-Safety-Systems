import os
import joblib
from sklearn.neural_network import MLPClassifier

def train_ann(X_train, y_train, model_dir):
    print("[ML TRAIN] Training Artificial Neural Network (ANN) Classifier...")
    ann_model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation='relu',
        solver='adam',
        max_iter=300,
        random_state=42,
        early_stopping=True
    )
    ann_model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "ann.joblib")
    joblib.dump(ann_model, model_path)
    print(f"[ML TRAIN] ANN model saved to {model_path}")
    return ann_model
