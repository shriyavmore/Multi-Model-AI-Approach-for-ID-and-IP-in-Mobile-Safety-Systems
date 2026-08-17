from ml.inference.predictor import MLPredictor

predictor_instance = MLPredictor()

def evaluate_multi_model_ensemble(
    feature_dict: dict,
    static_result: dict,
    dynamic_result: dict,
    behavioral_result: dict,
    custom_weights: dict = None
):
    """
    Ensembles outputs from Random Forest, SVM, ANN, and Isolation Forest
    alongside Static score, Dynamic score, Behavioral score, and Signature check
    into a unified decision, confidence, overall risk score, and XAI findings.
    """
    if custom_weights is None:
        weights = {
            "random_forest": 0.25,
            "svm": 0.20,
            "ann": 0.30,
            "isolation_forest": 0.15,
            "static_score": 0.05,
            "behavioral_score": 0.05
        }
    else:
        weights = custom_weights

    # Run ML Inference
    ml_preds = predictor_instance.predict(feature_dict)

    rf_prob = ml_preds['random_forest']['malware_probability']
    svm_prob = ml_preds['svm']['malware_probability']
    ann_prob = ml_preds['ann']['malware_probability']
    iso_anomaly_score = ml_preds['isolation_forest']['anomaly_score']
    is_anomaly = ml_preds['isolation_forest']['is_anomaly']

    static_score = static_result.get('static_score', 0)
    behavioral_score = behavioral_result.get('behavioral_score', 0)
    signature_match = static_result.get('signature_match', False)
    malware_name = static_result.get('malware_name')

    # Weighted Risk Score (0-100)
    weighted_score = (
        (rf_prob * 100 * weights['random_forest']) +
        (svm_prob * 100 * weights['svm']) +
        (ann_prob * 100 * weights['ann']) +
        (iso_anomaly_score * 100 * weights['isolation_forest']) +
        (static_score * weights['static_score']) +
        (behavioral_score * weights['behavioral_score'])
    )

    if signature_match:
        final_score = 100
    else:
        final_score = int(round(min(100, max(0, weighted_score))))

    # Model Consensus / Agreement
    malicious_votes = sum([
        1 if rf_prob >= 0.5 else 0,
        1 if svm_prob >= 0.5 else 0,
        1 if ann_prob >= 0.5 else 0
    ])

    if malicious_votes >= 2:
        ensemble_classification = "MALICIOUS"
        confidence = float(np.mean([rf_prob if rf_prob >= 0.5 else (1 - rf_prob),
                                    svm_prob if svm_prob >= 0.5 else (1 - svm_prob),
                                    ann_prob if ann_prob >= 0.5 else (1 - ann_prob)]))
    elif malicious_votes == 1 or is_anomaly or final_score >= 45:
        ensemble_classification = "SUSPICIOUS"
        confidence = 0.75
    else:
        ensemble_classification = "SAFE"
        confidence = float(1.0 - (final_score / 100.0))

    # Construct Explainable AI (XAI) Reason List
    xai_reasons = []

    if signature_match:
        xai_reasons.append(f"APK hash matches known malware signature in database ({malware_name or 'Known Malware'})")

    if static_result.get("findings"):
        for f in static_result["findings"]:
            if "CRITICAL" in f or "SUSPICIOUS" in f or "WARNING" in f:
                xai_reasons.append(f)

    if behavioral_score >= 50:
        xai_reasons.append(f"High behavioral risk score ({behavioral_score}/100) with excessive resource/permission usage")

    if dynamic_result.get("dynamic_indicators"):
        for ind in dynamic_result["dynamic_indicators"]:
            if "High" in ind or "Elevated" in ind or "Excessive" in ind or "Frequent" in ind:
                xai_reasons.append(f"Dynamic behavior: {ind}")

    if malicious_votes >= 2:
        xai_reasons.append(f"AI ML Model Consensus: {malicious_votes}/3 classifiers (RF, SVM, ANN) agree on MALICIOUS classification")

    if is_anomaly:
        xai_reasons.append(f"Isolation Forest detected abnormal execution patterns (Anomaly Score: {iso_anomaly_score:.2f})")

    if not xai_reasons:
        xai_reasons.append("All AI models, signature databases, and behavioral monitors classified application as SAFE.")

    return {
        "final_classification": ensemble_classification,
        "final_risk_score": final_score,
        "confidence": float(round(confidence, 2)),
        "ml_predictions": ml_preds,
        "model_agreement": f"{malicious_votes}/3 Classifiers Agree",
        "anomaly_detected": is_anomaly,
        "xai_reasons": xai_reasons
    }
import numpy as np
