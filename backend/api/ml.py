import os
import json
from fastapi import APIRouter, Body, HTTPException
from ml.inference.predictor import MLPredictor

router = APIRouter(prefix="/api/ml", tags=["Machine Learning Inference & Metrics"])
predictor = MLPredictor()

@router.post("/predict")
def run_ml_predict(features: dict = Body(...)):
    """
    Direct ML model inference on feature vector across Random Forest, SVM, ANN, and Isolation Forest.
    """
    return predictor.predict(features)

@router.get("/performance")
def get_ml_model_performance():
    """
    Returns trained ML model evaluation metrics (Accuracy, Precision, Recall, F1-Score, FPR, Confusion Matrix).
    """
    model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ml", "models")
    metrics_path = os.path.join(model_dir, "evaluation_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            return json.load(f)
    else:
        raise HTTPException(status_code=404, detail="ML evaluation metrics not found. Run training pipeline first.")
