from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from datetime import datetime

from backend.database.db import get_db
from backend.database.models import Application, Permission, Scan, ModelPrediction, Threat, Alert
from backend.services.static_analysis import analyze_static_features
from backend.services.dynamic_analysis import analyze_dynamic_telemetry
from backend.services.behavioral_analysis import analyze_behavioral_risk
from backend.services.ensemble_engine import evaluate_multi_model_ensemble
from backend.services.threat_engine import evaluate_threat_level
from backend.services.prevention_service import generate_prevention_plan
from backend.services.monitoring_service import monitoring_service_instance

from backend.services.unified_risk_engine import calculate_unified_risk_score

router = APIRouter(prefix="/api", tags=["Scan & Analysis"])


@router.post("/scan")
def run_full_app_scan(payload: dict = Body(...), db: Session = Depends(get_db)):
    """
    Executes complete multi-model AI security scan on an application:
    Static + Signature + Dynamic + Behavioral + RF/SVM/ANN/Isolation Forest ML Ensemble + Threat Engine + Prevention Plan.
    Persists scan, model predictions, threats, and alerts into database.
    """
    package_name = payload.get("package_name")
    app_name = payload.get("app_name", "Unknown Application")
    version = payload.get("version", "1.0.0")
    apk_hash = payload.get("apk_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    permissions = payload.get("permissions", [])

    if not package_name:
        raise HTTPException(status_code=400, detail="package_name is required")

    # 1. Database application registration / update
    app = db.query(Application).filter(Application.package_name == package_name).first()
    if not app:
        app = Application(
            package_name=package_name,
            app_name=app_name,
            version=version,
            apk_hash=apk_hash,
            installed_at=datetime.utcnow()
        )
        db.add(app)
        db.commit()
        db.refresh(app)
        
        # Save permissions
        for p in permissions:
            db.add(Permission(application_id=app.id, permission_name=p))
        db.commit()
    else:
        app.app_name = app_name
        app.version = version
        app.apk_hash = apk_hash
        db.commit()

    # 2. Run Defensive Pipeline Modules
    static_res = analyze_static_features(payload, db=db)
    dynamic_res = analyze_dynamic_telemetry(payload)
    behavioral_res = analyze_behavioral_risk(payload, static_res, dynamic_res)

    # 3. Construct Feature Vector for ML Models
    perm_set = set(permissions)
    feature_dict = {
        'perm_sms': 1 if "android.permission.SEND_SMS" in perm_set or "android.permission.READ_SMS" in perm_set else 0,
        'perm_location': 1 if "android.permission.ACCESS_FINE_LOCATION" in perm_set or "android.permission.ACCESS_COARSE_LOCATION" in perm_set else 0,
        'perm_camera': 1 if "android.permission.CAMERA" in perm_set else 0,
        'perm_microphone': 1 if "android.permission.RECORD_AUDIO" in perm_set else 0,
        'perm_contacts': 1 if "android.permission.READ_CONTACTS" in perm_set or "android.permission.WRITE_CONTACTS" in perm_set else 0,
        'perm_storage': 1 if "android.permission.READ_EXTERNAL_STORAGE" in perm_set or "android.permission.WRITE_EXTERNAL_STORAGE" in perm_set else 0,
        'perm_admin': 1 if "android.permission.BIND_DEVICE_ADMIN" in perm_set else 0,
        'perm_boot': 1 if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_set else 0,
        'perm_system_alert': 1 if "android.permission.SYSTEM_ALERT_WINDOW" in perm_set else 0,
        'perm_install_packages': 1 if "android.permission.REQUEST_INSTALL_PACKAGES" in perm_set else 0,
        'total_permissions': len(permissions),
        'dangerous_perm_count': static_res['dangerous_permissions_count'],
        'network_connections_count': dynamic_res['network_connections'],
        'background_exec_frequency': dynamic_res['background_execution_freq'],
        'suspicious_api_calls_count': dynamic_res['suspicious_api_calls'],
        'data_exfil_volume_kb': dynamic_res['data_exfiltered_kb'],
        'min_sdk_version': payload.get("min_sdk", 21),
        'target_sdk_version': payload.get("target_sdk", 33),
        'apk_entropy': payload.get("apk_entropy", 6.2),
        'hash_reputation_score': 0.0 if static_res['signature_match'] else 95.0
    }

    # 4. Multi-Model Ensemble AI Engine
    ensemble_res = evaluate_multi_model_ensemble(
        feature_dict, static_res, dynamic_res, behavioral_res, payload.get("custom_weights")
    )

    # 5. Threat Decision Engine
    threat_res = evaluate_threat_level(ensemble_res, static_res, behavioral_res)

    # 6. Prevention Actions
    prevention_res = generate_prevention_plan(payload, threat_res, static_res)

    # 7. Database Persistence
    scan_record = Scan(
        application_id=app.id,
        static_score=static_res['static_score'],
        dynamic_score=dynamic_res['dynamic_score'],
        behavioral_score=behavioral_res['behavioral_score'],
        final_score=ensemble_res['final_risk_score'],
        final_classification=ensemble_res['final_classification']
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # Save model predictions
    ml_preds = ensemble_res['ml_predictions']
    for m_name, m_info in [
        ("Random Forest", ml_preds['random_forest']),
        ("SVM", ml_preds['svm']),
        ("ANN", ml_preds['ann']),
        ("Isolation Forest", ml_preds['isolation_forest'])
    ]:
        pred_val = m_info.get('prediction', 'SAFE')
        conf = m_info.get('confidence', 0.8)
        db.add(ModelPrediction(
            scan_id=scan_record.id,
            model_name=m_name,
            prediction=pred_val,
            confidence=conf
        ))

    # Record threat & alert if score/severity demands it
    if threat_res['severity'] in ["MEDIUM", "HIGH", "CRITICAL"]:
        threat = Threat(
            application_id=app.id,
            threat_type=threat_res['threat_type'],
            severity=threat_res['severity'],
            description=threat_res['description'],
            status="ACTIVE"
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)

        alert = Alert(
            threat_id=threat.id,
            message=f"Threat Detected in {app_name}: {threat_res['threat_type']} ({ensemble_res['final_classification']})",
            severity=threat_res['severity'],
            resolved=False
        )
        db.add(alert)
        db.commit()

        # Feed event into real-time monitoring
        monitoring_service_instance.add_event(
            package_name=package_name,
            event_type="SECURITY_SCAN_ALERT",
            severity=threat_res['severity'],
            risk_score=ensemble_res['final_risk_score'],
            description=f"Scan completed: {ensemble_res['final_classification']} ({threat_res['threat_type']})"
        )

    db.commit()

    unified_risk_res = calculate_unified_risk_score(
        app_risk_score=ensemble_res['final_risk_score'],
        permission_risk_score=static_res['static_score'],
        behavior_risk_score=behavioral_res['behavioral_score']
    )


    return {
        "scan_id": scan_record.id,
        "package_name": package_name,
        "app_name": app_name,
        "scan_time": scan_record.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
        "static_analysis": static_res,
        "dynamic_analysis": dynamic_res,
        "behavioral_analysis": behavioral_res,
        "ai_ml_ensemble": ensemble_res,
        "threat_decision": threat_res,
        "prevention_plan": prevention_res,
        "unified_risk": unified_risk_res
    }
