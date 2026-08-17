from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database.db import get_db
from backend.api.scan import run_full_app_scan
from backend.services.network_service import analyze_network_security
from backend.services.room_security_service import scan_room_surveillance_risk
from backend.services.monitoring_service import monitoring_service_instance

router = APIRouter(prefix="/api/demo", tags=["Academic Demo Scenarios"])

DEMO_SCENARIOS = {
    "reviewer_demo_1": {
        "scenario_id": "reviewer_demo_1",
        "title": "Reviewer Demo 1 — Existing Application Monitoring",
        "description": "Loads installed apps, evaluates permissions and correlation, displays risk scores and explainable reasons.",
        "type": "APP_BATCH",
        "expected_classification": "BATCH_ANALYSIS"
    },
    "reviewer_demo_2": {
        "scenario_id": "reviewer_demo_2",
        "title": "Reviewer Demo 2 — Automatic New-App Installation Event",
        "description": "Simulates package install event broadcast (com.unknown.stealthapp), triggers real-time risk engine, notification, and dashboard update.",
        "type": "NEW_APP_EVENT",
        "app_name": "Unknown Stealth Tracker",
        "package_name": "com.unknown.stealthapp",
        "version": "1.0.0",
        "apk_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "permissions": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ],
        "expected_classification": "MALICIOUS",
        "expected_risk": "High/Critical"
    },
    "reviewer_demo_3": {
        "scenario_id": "reviewer_demo_3",
        "title": "Reviewer Demo 3 — Wi-Fi Network Security & Network Change",
        "description": "Simulates network switch to 'Hotel_Guest' (Unencrypted/Public Wi-Fi), evaluates security risk, and dispatches network security alert.",
        "type": "NETWORK_CHANGE",
        "ssid": "Hotel_Guest",
        "security_type": "OPEN",
        "is_public_guest": True,
        "expected_risk": "MEDIUM/HIGH"
    },
    "reviewer_demo_4": {
        "scenario_id": "reviewer_demo_4",
        "title": "Reviewer Demo 4 — Room Security & Surveillance Assessment",
        "description": "Executes potential hidden-camera risk scan, evaluates RTSP/ONVIF ports & camera MAC OUI vendor signatures, displays findings and recommendations.",
        "type": "ROOM_SECURITY",
        "expected_risk": "POTENTIAL_RISK"
    },
    "demo_1_safe": {
        "scenario_id": "demo_1_safe",
        "title": "Demo 1 — Safe Application",
        "app_name": "Calculator & Notes Pro",
        "package_name": "com.demo.safeapp",
        "version": "2.4.0",
        "apk_hash": "a1b2c3d4e5f67890safehash1234567890abcdef1234567890abcdef1234567890",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_EXTERNAL_STORAGE"
        ],
        "network_connections_count": 2,
        "background_exec_frequency": 0.5,
        "suspicious_api_calls_count": 0,
        "data_exfil_volume_kb": 12.5,
        "min_sdk": 24,
        "target_sdk": 33,
        "apk_entropy": 5.4,
        "is_simulated": True,
        "expected_classification": "SAFE",
        "expected_risk": "Low"
    },
    "demo_2_suspicious": {
        "scenario_id": "demo_2_suspicious",
        "title": "Demo 2 — Suspicious Application",
        "app_name": "Super Battery Booster & Cleaner",
        "package_name": "com.demo.suspiciouscleaner",
        "version": "1.0.8",
        "apk_hash": "b2c3d4e5f6789012suspicioushash34567890abcdef1234567890abcdef12345",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        ],
        "network_connections_count": 12,
        "background_exec_frequency": 4.5,
        "suspicious_api_calls_count": 2,
        "data_exfil_volume_kb": 650.0,
        "min_sdk": 21,
        "target_sdk": 30,
        "apk_entropy": 6.8,
        "is_simulated": True,
        "expected_classification": "SUSPICIOUS",
        "expected_risk": "Medium/High"
    },
    "demo_3_malicious": {
        "scenario_id": "demo_3_malicious",
        "title": "Demo 3 — Malicious Application",
        "app_name": "Free Premium Banking Pay & Rewards",
        "package_name": "com.demo.malwaretrojan",
        "version": "3.1.0",
        "apk_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "permissions": [
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ],
        "network_connections_count": 48,
        "background_exec_frequency": 8.8,
        "suspicious_api_calls_count": 14,
        "data_exfil_volume_kb": 14800.0,
        "min_sdk": 19,
        "target_sdk": 28,
        "apk_entropy": 7.7,
        "is_simulated": True,
        "is_known_malware_hash": True,
        "malware_family": "Trojan.AndroidOS.Joker.A",
        "expected_classification": "MALICIOUS",
        "expected_risk": "Critical"
    }
}

@router.get("/scenarios")
def list_demo_scenarios():
    """
    Returns the list of demo scenarios.
    """
    return list(DEMO_SCENARIOS.values())

@router.post("/run/{scenario_id}")
def run_demo_scenario(scenario_id: str, db: Session = Depends(get_db)):
    """
    Executes a full interactive security scan on one of the pre-configured demo scenarios.
    """
    if scenario_id not in DEMO_SCENARIOS:
        return {"error": "Invalid demo scenario ID"}

    sc = DEMO_SCENARIOS[scenario_id]

    if scenario_id == "reviewer_demo_2":
        # Simulate new app installation event
        scan_output = run_full_app_scan({
            "app_name": sc["app_name"],
            "package_name": sc["package_name"],
            "version": sc["version"],
            "apk_hash": sc["apk_hash"],
            "permissions": sc["permissions"],
            "network_connections_count": 28,
            "background_exec_frequency": 7.2,
            "suspicious_api_calls_count": 8,
            "data_exfil_volume_kb": 3200.0,
            "min_sdk": 19,
            "target_sdk": 29
        }, db=db)
        monitoring_service_instance.add_event(
            package_name=sc["package_name"],
            event_type="NEW_APP_INSTALLED",
            severity="HIGH",
            risk_score=scan_output["ai_ml_ensemble"]["final_risk_score"],
            description=f"New application detected: {sc['app_name']}. Unified Risk: {scan_output['ai_ml_ensemble']['final_risk_score']}/100."
        )
        scan_output["demo_scenario_meta"] = {
            "scenario_id": scenario_id,
            "title": sc["title"],
            "event_triggered": "NEW_APP_INSTALLED"
        }
        return scan_output

    elif scenario_id == "reviewer_demo_3":
        # Network change demo
        res = analyze_network_security({
            "ssid": "Hotel_Guest",
            "bssid": "00:11:22:33:44:55",
            "transport_type": "Wi-Fi",
            "security_type": "OPEN",
            "is_validated": False,
            "is_public_guest": True
        })
        monitoring_service_instance.add_event(
            package_name="Hotel_Guest",
            event_type="NETWORK_CHANGE_ALERT",
            severity=res["risk_level"],
            risk_score=res["network_risk_score"],
            description="Network changed to Hotel_Guest (Unencrypted / Guest Wi-Fi). Avoid sensitive activities."
        )
        return {
            "demo_scenario_meta": {"scenario_id": scenario_id, "title": sc["title"]},
            "network_analysis": res
        }

    elif scenario_id == "reviewer_demo_4":
        # Room security demo
        res = scan_room_surveillance_risk({"simulate_threat": True})
        return {
            "demo_scenario_meta": {"scenario_id": scenario_id, "title": sc["title"]},
            "room_security_analysis": res
        }

    else:
        # App scan
        scenario_payload = sc.copy()
        scan_output = run_full_app_scan(scenario_payload, db=db)
        scan_output["demo_scenario_meta"] = {
            "scenario_id": scenario_id,
            "title": sc["title"],
            "is_demo_data": True,
            "academic_note": "DEMO / SIMULATED MALWARE DATASET SAMPLE"
        }
        return scan_output
