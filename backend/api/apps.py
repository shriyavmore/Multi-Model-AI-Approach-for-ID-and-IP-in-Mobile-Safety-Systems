from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.db import get_db
from backend.database.models import Application, Permission, Scan
from backend.services.unified_risk_engine import map_risk_level, generate_explainable_risk_factors

router = APIRouter(prefix="/api/apps", tags=["Installed Applications"])

@router.get("")
def get_installed_apps(db: Session = Depends(get_db)):
    """
    Returns list of applications in the system registry along with latest scan results.
    """
    apps = db.query(Application).all()
    result = []
    for app in apps:
        latest_scan = db.query(Scan).filter(Scan.application_id == app.id).order_by(Scan.scan_time.desc()).first()
        perms = [p.permission_name for p in app.permissions]

        score = latest_scan.final_score if latest_scan else 15
        risk_level = map_risk_level(score) if latest_scan else "LOW"
        classification = latest_scan.final_classification if latest_scan else "SAFE"

        explainability = generate_explainable_risk_factors(
            permissions=perms,
            dangerous_count=sum(1 for p in perms if "SMS" in p or "LOCATION" in p or "CAMERA" in p or "RECORD_AUDIO" in p or "ADMIN" in p or "ALERT" in p),
            suspicious_combos=[],
            min_sdk=21,
            target_sdk=33
        )

        result.append({
            "id": app.id,
            "package_name": app.package_name,
            "app_name": app.app_name,
            "version": app.version,
            "apk_hash": app.apk_hash,
            "installed_at": app.installed_at.strftime("%Y-%m-%d %H:%M:%S") if app.installed_at else None,
            "permission_count": len(perms),
            "permissions": perms,
            "risk_score": score,
            "risk_level": risk_level,
            "risk_factors": explainability["risk_factors"],
            "recommendation": explainability["recommendation"],
            "latest_scan": {
                "scan_id": latest_scan.id,
                "final_classification": classification,
                "final_score": score,
                "risk_level": risk_level,
                "scan_time": latest_scan.scan_time.strftime("%Y-%m-%d %H:%M:%S")
            } if latest_scan else None
        })
    return result

@router.get("/{package_name}")
def get_app_details(package_name: str, db: Session = Depends(get_db)):
    """
    Returns detailed application record, permissions, and complete scan history.
    """
    app = db.query(Application).filter(Application.package_name == package_name).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    perms = [p.permission_name for p in app.permissions]
    scans = db.query(Scan).filter(Scan.application_id == app.id).order_by(Scan.scan_time.desc()).all()

    scan_history = []
    for s in scans:
        scan_history.append({
            "scan_id": s.id,
            "scan_time": s.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            "static_score": s.static_score,
            "dynamic_score": s.dynamic_score,
            "behavioral_score": s.behavioral_score,
            "final_score": s.final_score,
            "risk_level": map_risk_level(s.final_score),
            "final_classification": s.final_classification
        })

    explainability = generate_explainable_risk_factors(
        permissions=perms,
        dangerous_count=sum(1 for p in perms if "SMS" in p or "LOCATION" in p or "CAMERA" in p or "RECORD_AUDIO" in p or "ADMIN" in p or "ALERT" in p),
        suspicious_combos=[],
        min_sdk=21,
        target_sdk=33
    )

    latest_score = scan_history[0]["final_score"] if scan_history else 15

    return {
        "id": app.id,
        "package_name": app.package_name,
        "app_name": app.app_name,
        "version": app.version,
        "apk_hash": app.apk_hash,
        "installed_at": app.installed_at.strftime("%Y-%m-%d %H:%M:%S") if app.installed_at else None,
        "permissions": perms,
        "risk_score": latest_score,
        "risk_level": map_risk_level(latest_score),
        "risk_factors": explainability["risk_factors"],
        "recommendation": explainability["recommendation"],
        "scan_history": scan_history
    }
