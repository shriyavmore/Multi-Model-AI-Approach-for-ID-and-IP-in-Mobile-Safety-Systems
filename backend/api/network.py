from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
import json

from backend.database.db import get_db
from backend.database.models import NetworkScan
from backend.services.network_service import analyze_network_security
from backend.services.monitoring_service import monitoring_service_instance

router = APIRouter(prefix="/api/v1/network", tags=["Network Security"])

# In-memory latest status fallback
latest_network_status = {
    "ssid": "Active Device Network",
    "bssid": "00:11:22:33:44:55",
    "transport_type": "Wi-Fi",
    "security_type": "WPA2",
    "is_validated": True,
    "is_public_guest": False,
    "network_risk_score": 15,
    "risk_level": "LOW",
    "assessment_label": "Trusted / Standard Network",
    "findings": [
        "✓ Encrypted Wireless Transport: Standard device network connection.",
        "✓ Validated Connection: Active Internet routing."
    ],
    "recommendation": "Network monitoring active."
}


@router.get("/status")
def get_network_status(db: Session = Depends(get_db)):
    """
    Returns current active network security status.
    """
    latest_db = db.query(NetworkScan).order_by(NetworkScan.scanned_at.desc()).first()
    if latest_db:
        findings = []
        if latest_db.findings_json:
            try:
                findings = json.loads(latest_db.findings_json)
            except Exception:
                findings = [latest_db.findings_json]

        return {
            "id": latest_db.id,
            "ssid": latest_db.ssid,
            "bssid": latest_db.bssid,
            "transport_type": latest_db.transport_type,
            "security_type": latest_db.security_type,
            "is_validated": latest_db.is_validated,
            "is_public_guest": latest_db.is_public_guest,
            "network_risk_score": latest_db.risk_score,
            "risk_level": latest_db.risk_level,
            "assessment_label": "Potentially Suspicious Network" if latest_db.risk_score >= 40 else "Trusted / Standard Network",
            "findings": findings,
            "scanned_at": latest_db.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    return latest_network_status

@router.post("/analyze")
def analyze_network_endpoint(payload: dict = Body(...), db: Session = Depends(get_db)):
    """
    Analyzes connected network characteristics, evaluates security risks,
    saves record to database, and triggers monitoring event if risk/change detected.
    """
    global latest_network_status
    result = analyze_network_security(payload)

    # Database persistence
    scan_record = NetworkScan(
        ssid=result["ssid"],
        bssid=result["bssid"],
        transport_type=result["transport_type"],
        security_type=result["security_type"],
        is_validated=result["is_validated"],
        is_public_guest=result["is_public_guest"],
        risk_score=result["network_risk_score"],
        risk_level=result["risk_level"],
        findings_json=json.dumps(result["findings"])
    )
    db.add(scan_record)
    db.commit()

    latest_network_status = result

    # Push to real-time monitoring stream if risk level is MEDIUM or higher
    if result["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
        monitoring_service_instance.add_event(
            package_name=result["ssid"],
            event_type="NETWORK_CHANGE_ALERT",
            severity=result["risk_level"],
            risk_score=result["network_risk_score"],
            description=f"Connected to {result['ssid']} ({result['security_type']}). {result['assessment_label']}."
        )

    return result
