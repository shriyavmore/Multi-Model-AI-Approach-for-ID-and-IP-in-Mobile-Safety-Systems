"""
Network Security Analysis Service for IntDetect.
Monitors observable network attributes (Wi-Fi transport, encryption type,
internet validation, public/guest status) and computes network security risk.
"""

from backend.services.unified_risk_engine import map_risk_level

def analyze_network_security(network_info: dict) -> dict:
    """
    Evaluates observable network security indicators.
    Phrased explicitly as 'Potentially suspicious network' or 'Network security risk detected'.
    """
    ssid = network_info.get("ssid", "Unknown_WiFi")
    bssid = network_info.get("bssid", "00:00:00:00:00:00")
    transport = network_info.get("transport_type", "Wi-Fi")
    security_type = network_info.get("security_type", "WPA2").upper()
    is_validated = network_info.get("is_validated", True)
    is_public_guest = network_info.get("is_public_guest", False)

    risk_score = 0
    findings = []
    recommendation = "Network is encrypted and validated. Standard activity safe."

    # 1. Encryption & Security Type Check
    if security_type in ["OPEN", "NONE", "WEP"]:
        risk_score += 55
        findings.append(f"⚠ Open / Weakly Secured Wi-Fi Network ({security_type}): Traffic is unencrypted and vulnerable to eavesdropping/interception.")
    elif security_type == "WPA2":
        risk_score += 15
        findings.append("✓ WPA2 Security Protocol: Encrypted wireless transport.")
    elif security_type == "WPA3":
        risk_score += 5
        findings.append("✓ WPA3 Security Protocol: High security modern encryption.")

    # 2. Public / Guest Network Indicator
    ssid_lower = ssid.lower()
    if is_public_guest or any(kw in ssid_lower for kw in ["guest", "hotel", "airport", "coffee", "public", "free"]):
        is_public_guest = True
        risk_score += 25
        findings.append("⚠ Guest/Public Network Detected: Shared local network with untrusted client devices.")

    # 3. Internet Validation / Captive Portal Check
    if not is_validated:
        risk_score += 25
        findings.append("⚠ Internet Connectivity Unvalidated / Captive Portal: Traffic may be intercepted or redirected.")

    # 4. Unknown BSSID / Suspicious SSID
    if "fake" in ssid_lower or "free_wifi" in ssid_lower or "evil" in ssid_lower:
        risk_score += 35
        findings.append("⚠ Suspicious Network SSID Name: High risk of rogue access point / Man-in-the-Middle (MitM) trap.")

    network_risk_score = int(min(100, max(0, risk_score)))
    risk_level = map_risk_level(network_risk_score)

    if risk_level in ["HIGH", "CRITICAL"]:
        recommendation = "Avoid sensitive banking or credential entry on this network. Use trusted VPN if available."
    elif risk_level == "MEDIUM":
        recommendation = "Public network detected. Avoid unencrypted transactions or sensitive data exchange."

    return {
        "ssid": ssid,
        "bssid": bssid,
        "transport_type": transport,
        "security_type": security_type,
        "is_validated": is_validated,
        "is_public_guest": is_public_guest,
        "network_risk_score": network_risk_score,
        "risk_level": risk_level,
        "assessment_label": "Potentially Suspicious Network" if network_risk_score >= 40 else "Trusted / Standard Network",
        "findings": findings,
        "recommendation": recommendation
    }
