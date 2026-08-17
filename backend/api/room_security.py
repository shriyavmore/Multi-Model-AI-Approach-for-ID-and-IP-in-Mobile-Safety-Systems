from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
import json

from backend.database.db import get_db
from backend.database.models import RoomSecurityScan
from backend.services.room_security_service import scan_room_surveillance_risk
from backend.services.monitoring_service import monitoring_service_instance

router = APIRouter(prefix="/api/v1/room-security", tags=["Room / Physical Security"])

@router.post("/scan")
def run_room_security_scan(payload: dict = Body(default={}), db: Session = Depends(get_db)):
    """
    Executes Potential Hidden-Camera / Surveillance Device Risk Assessment.
    Analyzes local network devices, RTSP/ONVIF ports, MAC vendors, and camera SSIDs.
    """
    result = scan_room_surveillance_risk(payload)

    # Persist in DB
    scan_record = RoomSecurityScan(
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        status=result["status"],
        detected_devices_json=json.dumps(result["detected_devices"]),
        summary_json=json.dumps(result["findings"])
    )
    db.add(scan_record)
    db.commit()

    if result["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
        monitoring_service_instance.add_event(
            package_name="Room_Security_Scan",
            event_type="SURVEILLANCE_RISK_DETECTED",
            severity=result["risk_level"],
            risk_score=result["risk_score"],
            description=f"Room Security Assessment: {len(result['detected_devices'])} potential surveillance signal(s) detected."
        )

    return result

@router.get("/history")
def get_room_security_history(db: Session = Depends(get_db)):
    """
    Returns scan history for Room Security scans.
    """
    history = db.query(RoomSecurityScan).order_by(RoomSecurityScan.scanned_at.desc()).all()
    results = []
    for h in history:
        try:
            devs = json.loads(h.detected_devices_json)
        except Exception:
            devs = []
        try:
            findings = json.loads(h.summary_json)
        except Exception:
            findings = []

        results.append({
            "id": h.id,
            "risk_score": h.risk_score,
            "risk_level": h.risk_level,
            "status": h.status,
            "detected_devices": devs,
            "findings": findings,
            "scanned_at": h.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return results
