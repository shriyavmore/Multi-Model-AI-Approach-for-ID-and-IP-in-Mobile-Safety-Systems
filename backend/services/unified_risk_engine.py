"""
Unified Risk Engine for IntDetect Mobile Security IDPS.
Correlates application risk, permission risk, behavioral telemetry,
network security indicators, and room/environmental security signals
into an explainable unified security risk score (0-100).
"""

def map_risk_level(score: float) -> str:
    """
    Standard normalized risk mapping:
    0–30:   LOW
    31–60:  MEDIUM
    61–80:  HIGH
    81–100: CRITICAL
    """
    if score >= 81:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_unified_risk_score(
    app_risk_score: float = 0,
    permission_risk_score: float = 0,
    behavior_risk_score: float = 0,
    network_risk_score: float = 0,
    room_risk_score: float = 0,
    weights: dict = None
) -> dict:
    """
    Calculates unified risk score across all observable security layers.
    """
    if weights is None:
        weights = {
            "app": 0.40,
            "perm": 0.25,
            "behavior": 0.15,
            "network": 0.10,
            "room": 0.10
        }

    # Weight normalization
    total_w = sum(weights.values())
    w_app = weights.get("app", 0.40) / total_w
    w_perm = weights.get("perm", 0.25) / total_w
    w_behavior = weights.get("behavior", 0.15) / total_w
    w_network = weights.get("network", 0.10) / total_w
    w_room = weights.get("room", 0.10) / total_w

    raw_score = (
        (app_risk_score * w_app) +
        (permission_risk_score * w_perm) +
        (behavior_risk_score * w_behavior) +
        (network_risk_score * w_network) +
        (room_risk_score * w_room)
    )

    unified_score = int(min(100, max(0, round(raw_score))))
    risk_level = map_risk_level(unified_score)

    return {
        "unified_risk_score": unified_score,
        "risk_level": risk_level,
        "breakdown": {
            "application_risk": app_risk_score,
            "permission_risk": permission_risk_score,
            "behavior_risk": behavior_risk_score,
            "network_risk": network_risk_score,
            "room_risk": room_risk_score
        },
        "weights": weights
    }


def generate_explainable_risk_factors(
    permissions: list,
    dangerous_count: int,
    suspicious_combos: list,
    min_sdk: int,
    target_sdk: int,
    is_known_malware: bool = False,
    malware_name: str = None
) -> dict:
    """
    Generates human-readable, explainable risk factors & recommendations for an application.
    """
    risk_factors = []
    recommendation = "No immediate user action required."

    if is_known_malware and malware_name:
        risk_factors.append(f"⛔ CRITICAL: Matches known malware signature ({malware_name})")
        recommendation = "Uninstall immediately. Do not launch or supply credentials."
        return {
            "risk_factors": risk_factors,
            "recommendation": recommendation
        }

    # Observable permissions
    sensitive_map = {
        "android.permission.SEND_SMS": "SMS Exfiltration / Premium SMS",
        "android.permission.READ_SMS": "SMS Reading",
        "android.permission.ACCESS_FINE_LOCATION": "Precise GPS Location Tracking",
        "android.permission.RECORD_AUDIO": "Microphone Audio Recording",
        "android.permission.CAMERA": "Camera Capture",
        "android.permission.READ_CONTACTS": "Address Book Exfiltration",
        "android.permission.BIND_DEVICE_ADMIN": "Device Administrator Authority",
        "android.permission.SYSTEM_ALERT_WINDOW": "Screen Overlay Drawing (Phishing / Ransomware)",
        "android.permission.REQUEST_INSTALL_PACKAGES": "External APK Dropper Permission",
        "android.permission.RECEIVE_BOOT_COMPLETED": "Persistent Boot Auto-Start"
    }

    for p in permissions:
        if p in sensitive_map:
            risk_factors.append(f"⚠ {p.replace('android.permission.', '')}: {sensitive_map[p]}")

    for combo in suspicious_combos:
        risk_factors.append(f"⚡ Unusual combination: {combo}")

    if min_sdk < 23:
        risk_factors.append(f"⚠ Legacy Min SDK target ({min_sdk}): May bypass runtime permission prompts")

    if dangerous_count >= 5:
        risk_factors.append(f"⚠ Excessive dangerous permissions ({dangerous_count} requested)")

    if len(risk_factors) == 0:
        risk_factors.append("✓ Standard application profile with no high-risk permission abuses detected.")
        recommendation = "Application appears safe for standard routine use."
    elif dangerous_count >= 4 or len(suspicious_combos) > 0:
        recommendation = "Review application permissions in System Settings or uninstall if untrusted."
    else:
        recommendation = "Exercise caution if application asks for sensitive runtime permissions unexpectedly."

    return {
        "risk_factors": risk_factors,
        "recommendation": recommendation
    }
