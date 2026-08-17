def analyze_behavioral_risk(app_data: dict, static_result: dict, dynamic_result: dict):
    """
    Behavioral analysis engine converting static permission usage frequency,
    dynamic API indicators, and network patterns into a behavioral risk score.
    """
    perm_count = static_result.get("dangerous_permissions_count", 0)
    net_conn = dynamic_result.get("network_connections", 0)
    bg_freq = dynamic_result.get("background_execution_freq", 0.0)
    api_calls = dynamic_result.get("suspicious_api_calls", 0)
    exfil_kb = dynamic_result.get("data_exfiltered_kb", 0.0)

    score = 0
    reasons = []

    if net_conn > 15:
        score += 25
        reasons.append("Unusual high-frequency network activity to remote IP addresses.")

    if bg_freq > 5.0:
        score += 25
        reasons.append("Excessive background execution without persistent user visibility.")

    if perm_count >= 3:
        score += 25
        reasons.append("Sensitive permission usage (SMS/Location/Camera/Contacts) active in background.")

    if api_calls > 3:
        score += 25
        reasons.append("Suspicious runtime reflection and dynamic code loader execution.")

    behavioral_score = min(100, score)

    if behavioral_score >= 75:
        risk_level = "HIGH"
    elif behavioral_score >= 45:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("Behavioral patterns match standard Android application profiles.")

    return {
        "behavioral_score": behavioral_score,
        "risk_level": risk_level,
        "reasons": reasons
    }
