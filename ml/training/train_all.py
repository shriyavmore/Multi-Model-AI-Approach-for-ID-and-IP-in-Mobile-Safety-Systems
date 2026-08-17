import os
import sys

# Ensure workspace root is in python path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml.datasets.generate_dataset import generate_mobile_security_dataset
from ml.preprocessing.preprocess import preprocess_and_balance_dataset
from ml.training.train_random_forest import train_random_forest
from ml.training.train_svm import train_svm
from ml.training.train_ann import train_ann
from ml.training.train_isolation_forest import train_isolation_forest
from ml.training.evaluate_models import evaluate_all_models

def run_full_ml_pipeline():
    print("=" * 60)
    print("STARTING FULL ML TRAINING PIPELINE FOR MOBILE IDPS")
    print("=" * 60)

    dataset_dir = os.path.join(BASE_DIR, "ml", "datasets")
    model_dir = os.path.join(BASE_DIR, "ml", "models")
    
    # 1. Generate Dataset
    csv_path = generate_mobile_security_dataset(n_samples=10000, random_state=42)

    # 2. Preprocess & Scale
    X_train, X_test, y_train, y_test, scaler = preprocess_and_balance_dataset(
        csv_path, test_size=0.2, save_scaler_dir=model_dir
    )

    # 3. Train Classifier Models
    train_random_forest(X_train, y_train, model_dir)
    train_svm(X_train, y_train, model_dir)
    train_ann(X_train, y_train, model_dir)
    train_isolation_forest(X_train, y_train, model_dir)

    # 4. Evaluate Models & Save Metrics
    metrics = evaluate_all_models(X_test, y_test, model_dir)

    print("=" * 60)
    print("ML PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    return metrics

if __name__ == "__main__":
    run_full_ml_pipeline()
