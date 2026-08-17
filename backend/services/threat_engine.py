def evaluate_threat_level(
    ensemble_result: dict,
    static_result: dict,
    behavioral_result: dict
):
    """
    Rule-based decision layer following ML inference and ensemble evaluation.
    Determines exact threat severity (CRITICAL, HIGH, MEDIUM, LOW) and status.
    """
    signature_match = static_result.get("signature_match", False)
    final_score = ensemble_result.get("final_risk_score", 0)
    confidence = ensemble_result.get("confidence", 0.0)
    classification = ensemble_result.get("final_classification", "SAFE")
    behavioral_score = behavioral_result.get("behavioral_score", 0)
    is_anomaly = ensemble_result.get("anomaly_detected", False)
    dangerous_perms = static_result.get("dangerous_permissions_count", 0)

    # 1. Known Malicious Hash Rule
    if signature_match:
        severity = "CRITICAL"
        threat_type = "Known Malware Signature Match"
        description = "Application hash directly matches a known high-severity malware signature in the local threat database."

    # 2. High Confidence ML + High Behavioral Risk
    elif classification == "MALICIOUS" and confidence >= 0.85 and behavioral_score >= 60:
        severity = "CRITICAL"
        threat_type = "Confirmed AI Multi-Model Threat"
        description = f"Multi-model AI ensemble classified application as MALICIOUS with {confidence*100:.0f}% confidence and high behavioral score ({behavioral_score}/100)."

    # 3. Malicious Classification or High Score
    elif classification == "MALICIOUS" or final_score >= 70:
        severity = "HIGH"
        threat_type = "High Risk Malicious Activity"
        description = f"Application exhibit high-risk features and suspicious activity with risk score {final_score}/100."

    # 4. Anomaly Detected + Dangerous Permissions
    elif (is_anomaly or classification == "SUSPICIOUS") and dangerous_perms > 0:
        severity = "MEDIUM"
        threat_type = "Anomalous Behavioral Profile"
        description = "Isolation Forest flagged abnormal activity pattern combined with dangerous sensitive permissions."

    # 5. Mild Suspicious / Low Risk
    elif final_score >= 30:
        severity = "LOW"
        threat_type = "Low Severity Security Note"
        description = "Minor permission or SDK warnings detected, but low overall threat risk."

    else:
        severity = "LOW"
        threat_type = "Benign Application"
        description = "Application exhibits standard behavior and no known threat patterns."

    return {
        "severity": severity,
        "threat_type": threat_type,
        "description": description,
        "final_classification": classification,
        "final_score": final_score
    }
