import pytest
from backend.services.network_service import analyze_network_security

def test_secure_private_wifi_analysis():
    payload = {
        "ssid": "Home_WiFi_Secure",
        "bssid": "00:11:22:33:44:55",
        "transport_type": "Wi-Fi",
        "security_type": "WPA3",
        "is_validated": True,
        "is_public_guest": False
    }
    res = analyze_network_security(payload)
    assert res["network_risk_score"] <= 30
    assert res["risk_level"] == "LOW"
    assert "Potentially Suspicious Network" not in res["assessment_label"]

def test_open_public_wifi_analysis():
    payload = {
        "ssid": "Hotel_Guest_Free",
        "bssid": "00:AA:BB:CC:DD:EE",
        "transport_type": "Wi-Fi",
        "security_type": "OPEN",
        "is_validated": False,
        "is_public_guest": True
    }
    res = analyze_network_security(payload)
    assert res["network_risk_score"] >= 60
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert res["assessment_label"] == "Potentially Suspicious Network"
