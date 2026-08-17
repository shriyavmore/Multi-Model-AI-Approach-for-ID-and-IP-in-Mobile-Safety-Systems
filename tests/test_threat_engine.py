import pytest
from backend.services.threat_engine import evaluate_threat_level
from backend.services.prevention_service import generate_prevention_plan

def test_critical_threat_evaluation():
    ensemble_res = {"final_risk_score": 95, "confidence": 0.95, "final_classification": "MALICIOUS", "anomaly_detected": True}
    static_res = {"signature_match": True, "dangerous_permissions_count": 5}
    behavioral_res = {"behavioral_score": 85}

    threat = evaluate_threat_level(ensemble_res, static_res, behavioral_res)
    assert threat["severity"] == "CRITICAL"
    assert "Known Malware" in threat["threat_type"]

def test_prevention_plan_generation():
    app_data = {"package_name": "com.test.malware", "app_name": "Malware App"}
    threat_res = {"severity": "CRITICAL"}
    static_res = {"signature_match": True}

    plan = generate_prevention_plan(app_data, threat_res, static_res)
    assert plan["prevention_status"] == "ACTION_REQUIRED"
    assert len(plan["programmatic_actions"]) >= 2
    assert len(plan["guided_user_workflow"]) >= 2
