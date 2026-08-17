import pytest
from backend.services.room_security_service import scan_room_surveillance_risk

def test_room_security_clean_scan():
    res = scan_room_surveillance_risk({"simulate_threat": False, "devices": []})
    assert res["risk_score"] <= 30
    assert res["status"] == "NO_SIGNIFICANT_RISK"
    assert "Potential Hidden-Camera" in res["assessment_title"]

def test_room_security_surveillance_threat():
    res = scan_room_surveillance_risk({"simulate_threat": True})
    assert res["risk_score"] > 30
    assert res["status"] in ["POTENTIAL_RISK", "DEMO_SIMULATED_THREAT"]
    assert len(res["detected_devices"]) >= 1
    assert any("RTSP" in reason or "Dahua" in reason or "Demo" in reason for dev in res["detected_devices"] for reason in dev["reasons"])

def test_room_security_cellular_scan():
    res = scan_room_surveillance_risk({"transport_type": "Cellular", "simulate_threat": False})
    assert res["status"] == "CELLULAR_DATA_ACTIVE"
    assert res["risk_score"] == 10
    assert "unavailable on cellular data" in res["message"]
    assert len(res["detected_devices"]) == 0

