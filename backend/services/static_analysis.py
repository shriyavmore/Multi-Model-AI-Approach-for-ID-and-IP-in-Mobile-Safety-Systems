from sqlalchemy.orm import Session
from backend.database.models import MaliciousHash
from backend.services.unified_risk_engine import generate_explainable_risk_factors, map_risk_level

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 25,
    "android.permission.READ_SMS": 20,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.ACCESS_FINE_LOCATION": 15,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.RECORD_AUDIO": 15,
    "android.permission.CAMERA": 15,
    "android.permission.READ_CONTACTS": 15,
    "android.permission.WRITE_CONTACTS": 15,
    "android.permission.READ_EXTERNAL_STORAGE": 10,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.BIND_DEVICE_ADMIN": 35,
    "android.permission.RECEIVE_BOOT_COMPLETED": 15,
    "android.permission.SYSTEM_ALERT_WINDOW": 30,
    "android.permission.REQUEST_INSTALL_PACKAGES": 30,
}

SUSPICIOUS_COMBINATIONS = [
    ({"android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"}, "Requests location + microphone + SMS permissions"),
    ({"android.permission.BIND_DEVICE_ADMIN", "android.permission.SYSTEM_ALERT_WINDOW"}, "Requests Device Administrator and System Overlay permissions (Overlay Trojan Pattern)"),
    ({"android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.SEND_SMS"}, "Auto-starts at boot and possesses SMS sending permissions (SMS Spyware Pattern)"),
    ({"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_EXTERNAL_STORAGE"}, "Requests permission to install external APK packages from storage (Dropper Pattern)"),
]

def analyze_static_features(app_data: dict, db: Session = None):
    """
    Performs static analysis on application metadata, permission patterns, and signature hash lookup.
    """
    apk_hash = app_data.get("apk_hash", "").lower()
    permissions = list(app_data.get("permissions", []))
    perm_set = set(permissions)
    min_sdk = app_data.get("min_sdk", 21)
    target_sdk = app_data.get("target_sdk", 33)

    findings = []
    suspicious_combos_detected = []
    signature_match = False
    malware_name = None

    # 1. Signature/Hash Check against Malicious Database
    if db is not None and apk_hash:
        matched = db.query(MaliciousHash).filter(MaliciousHash.apk_hash == apk_hash).first()
        if matched:
            signature_match = True
            malware_name = matched.malware_name
            findings.append(f"CRITICAL: Application matches known malicious hash ({malware_name})")

    # If static signature match is known malware hash directly provided in data
    if not signature_match and app_data.get("is_known_malware_hash", False):
        signature_match = True
        malware_name = app_data.get("malware_family", "Generic.Malware.Hash")
        findings.append(f"CRITICAL: Application matches known malicious hash signature ({malware_name})")

    # 2. Permission Risk Calculation
    perm_risk = 0
    for perm in perm_set:
        if perm in DANGEROUS_PERMISSIONS:
            perm_risk += DANGEROUS_PERMISSIONS[perm]

    # 3. Suspicious Combinations
    for combo_set, reason in SUSPICIOUS_COMBINATIONS:
        if combo_set.issubset(perm_set):
            perm_risk += 25
            findings.append(f"SUSPICIOUS COMBINATION: {reason}")
            suspicious_combos_detected.append(reason)

    # 4. Target & Min SDK Warnings
    if min_sdk < 21:
        perm_risk += 15
        findings.append(f"SDK WARNING: Targeted Minimum SDK ({min_sdk}) bypasses modern runtime permission security checks.")

    # Calculate Static Score (0-100)
    if signature_match:
        static_score = 100
    else:
        static_score = min(100, perm_risk)

    risk_level = map_risk_level(static_score)

    if not findings:
        findings.append("No critical static permission anomalies or known malware signatures detected.")

    dangerous_count = sum(1 for p in perm_set if p in DANGEROUS_PERMISSIONS)
    explainability = generate_explainable_risk_factors(
        permissions=permissions,
        dangerous_count=dangerous_count,
        suspicious_combos=suspicious_combos_detected,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        is_known_malware=signature_match,
        malware_name=malware_name
    )

    return {
        "static_score": static_score,
        "risk_level": risk_level,
        "signature_match": signature_match,
        "malware_name": malware_name,
        "dangerous_permissions_count": dangerous_count,
        "total_permissions_count": len(permissions),
        "findings": findings,
        "risk_factors": explainability["risk_factors"],
        "recommendation": explainability["recommendation"]
    }
