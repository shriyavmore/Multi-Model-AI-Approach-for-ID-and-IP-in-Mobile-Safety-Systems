import pytest
from backend.services.static_analysis import analyze_static_features

def test_safe_app_static_analysis():
    payload = {
        "package_name": "com.example.calculator",
        "permissions": ["android.permission.INTERNET"],
        "min_sdk": 26,
        "target_sdk": 33
    }
    res = analyze_static_features(payload)
    assert res["static_score"] < 35
    assert res["risk_level"] == "LOW"
    assert res["signature_match"] is False

def test_suspicious_permissions_static_analysis():
    payload = {
        "package_name": "com.example.suspicious",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO"
        ],
        "min_sdk": 21,
        "target_sdk": 33
    }
    res = analyze_static_features(payload)
    assert res["static_score"] >= 60
    assert any("Requests location + microphone + SMS permissions" in f for f in res["findings"])

def test_known_malicious_hash_static_analysis():
    payload = {
        "package_name": "com.example.malware",
        "apk_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "is_known_malware_hash": True,
        "malware_family": "Trojan.AndroidOS.Joker.A"
    }
    res = analyze_static_features(payload)
    assert res["static_score"] == 100
    assert res["signature_match"] is True
    assert res["risk_level"] == "CRITICAL"
