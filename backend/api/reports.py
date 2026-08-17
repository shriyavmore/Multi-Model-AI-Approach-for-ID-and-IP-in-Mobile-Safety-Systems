from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.db import get_db
from backend.database.models import Scan, Application, ModelPrediction, Threat
from backend.services.prevention_service import generate_prevention_plan

router = APIRouter(prefix="/api/reports", tags=["Security Reports"])

@router.get("/{scan_id}")
def get_security_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generates structured security report for a specific application scan.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    app = db.query(Application).filter(Application.id == scan.application_id).first()
    preds = db.query(ModelPrediction).filter(ModelPrediction.scan_id == scan.id).all()

    model_results = {}
    for p in preds:
        model_results[p.model_name] = {
            "prediction": p.prediction,
            "confidence": p.confidence
        }

    threat = db.query(Threat).filter(Threat.application_id == app.id).order_by(Threat.detected_at.desc()).first()

    threat_dict = {
        "severity": threat.severity if threat else ("HIGH" if scan.final_classification == "MALICIOUS" else "LOW")
    }

    prevention = generate_prevention_plan(
        {"package_name": app.package_name, "app_name": app.app_name},
        threat_dict,
        {"signature_match": False}
    )

    return {
        "report_id": f"REP-{scan.id:06d}",
        "generated_at": scan.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
        "application_info": {
            "app_name": app.app_name,
            "package_name": app.package_name,
            "version": app.version,
            "apk_hash": app.apk_hash,
            "installed_at": app.installed_at.strftime("%Y-%m-%d %H:%M:%S") if app.installed_at else None
        },
        "static_analysis": {
            "static_score": scan.static_score,
            "permissions_count": len(app.permissions) if app.permissions else 0
        },
        "dynamic_behavioral_analysis": {
            "dynamic_score": scan.dynamic_score,
            "behavioral_score": scan.behavioral_score
        },
        "ai_ml_results": model_results,
        "final_verdict": {
            "classification": scan.final_classification,
            "risk_score": scan.final_score,
            "confidence": 0.94 if scan.final_classification == "MALICIOUS" else 0.90
        },
        "recommended_action": prevention
    }
