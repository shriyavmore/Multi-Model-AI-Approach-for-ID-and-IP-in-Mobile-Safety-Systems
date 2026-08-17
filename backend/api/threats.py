from fastapi import APIRouter, Depends, Body, HTTPException
from sqlalchemy.orm import Session
from backend.database.db import get_db
from backend.database.models import Threat, Application
from backend.services.threat_engine import evaluate_threat_level

router = APIRouter(prefix="/api/threats", tags=["Threat Decision & Threats"])

@router.get("")
def get_threats(db: Session = Depends(get_db)):
    """
    Returns list of all active/resolved security threats detected in the system.
    """
    threats = db.query(Threat).order_by(Threat.detected_at.desc()).all()
    result = []
    for t in threats:
        app = db.query(Application).filter(Application.id == t.application_id).first()
        result.append({
            "id": t.id,
            "application_id": t.application_id,
            "package_name": app.package_name if app else "Unknown",
            "app_name": app.app_name if app else "Unknown App",
            "threat_type": t.threat_type,
            "severity": t.severity,
            "description": t.description,
            "status": t.status,
            "detected_at": t.detected_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return result

@router.post("/evaluate")
def evaluate_threat_standalone(payload: dict = Body(...)):
    """
    Evaluates threat level standalone given ensemble, static, and behavioral results.
    """
    ensemble_res = payload.get("ensemble_result", {})
    static_res = payload.get("static_result", {})
    behavioral_res = payload.get("behavioral_result", {})
    return evaluate_threat_level(ensemble_res, static_res, behavioral_res)
