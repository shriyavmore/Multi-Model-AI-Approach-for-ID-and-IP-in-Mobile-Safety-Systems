import pytest
from backend.services.unified_risk_engine import (
    calculate_unified_risk_score,
    generate_explainable_risk_factors,
    map_risk_level
)

def test_risk_level_mapping():
    assert map_risk_level(15) == "LOW"
    assert map_risk_level(45) == "MEDIUM"
    assert map_risk_level(75) == "HIGH"
    assert map_risk_level(95) == "CRITICAL"

def test_unified_risk_score_calculation():
    res = calculate_unified_risk_score(
        app_risk_score=85,
        permission_risk_score=90,
        behavior_risk_score=70,
        network_risk_score=40,
        room_risk_score=30
    )
    assert res["unified_risk_score"] > 65
    assert res["risk_level"] in ["HIGH", "CRITICAL"]

def test_explainable_risk_factors():
    perms = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_SMS"
    ]
    res = generate_explainable_risk_factors(
        permissions=perms,
        dangerous_count=4,
        suspicious_combos=["Requests location + microphone + SMS permissions"],
        min_sdk=21,
        target_sdk=33
    )
    assert len(res["risk_factors"]) >= 4
    assert any("CAMERA" in rf for rf in res["risk_factors"])
    assert "Review application permissions" in res["recommendation"]
