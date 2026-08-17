from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.db import get_db
from backend.database.models import Alert, Threat, Application

router = APIRouter(prefix="/api/alerts", tags=["Alert System"])

@router.get("")
def get_alerts(db: Session = Depends(get_db)):
    """
    Retrieves all generated security alerts.
    """
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    result = []
    for a in alerts:
        threat = db.query(Threat).filter(Threat.id == a.threat_id).first()
        app = db.query(Application).filter(Application.id == threat.application_id).first() if threat else None
        result.append({
            "id": a.id,
            "threat_id": a.threat_id,
            "package_name": app.package_name if app else "com.system.threat",
            "app_name": app.app_name if app else "Target Application",
            "message": a.message,
            "severity": a.severity,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": a.resolved
        })
    return result

@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Marks an alert and its associated threat as RESOLVED.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.resolved = True
    if alert.threat:
        alert.threat.status = "RESOLVED"
    db.commit()

    return {"message": f"Alert {alert_id} successfully marked as RESOLVED", "status": "RESOLVED"}
