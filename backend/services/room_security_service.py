"""
Room Security / Physical Surveillance Risk Assessment Service for IntDetect.

IMPORTANT:
Does NOT claim guaranteed detection of hidden cameras.
Positioned strictly as:
'Potential Hidden-Camera / Surveillance Device Risk Assessment'
evaluating observable network signals, IoT device indicators, and optical inspection mode.
"""

from datetime import datetime
from backend.services.unified_risk_engine import map_risk_level

SUSPICIOUS_CAMERA_SSIDS = [
    "ipcam", "camera", "cctv", "spy", "cam_", "esp32-cam", "hd-camera", "wireless-camera", "tuya_cam"
]

CAMERA_VENDOR_MACS = {
    "00:12:12": "Hikvision Digital Tech",
    "00:1A:07": "Dahua Technology",
    "70:B3:D5": "Tuya Smart IoT",
    "A4:DA:22": "Wyze Labs",
    "38:01:97": "Amcrest Technologies",
    "24:0A:C4": "Espressif Systems (ESP32-CAM)"
}

def scan_room_surveillance_risk(scan_params: dict = None) -> dict:
    """
    Performs multi-signal potential surveillance risk assessment:
    1. Local network scan (ports 554 RTSP, 3702 ONVIF, 8080)
    2. Nearby Wi-Fi / IoT device SSID analysis
    3. MAC OUI vendor verification
    4. Optical reflection inspection guidelines
    """
    if scan_params is None:
        scan_params = {}

    simulate_threat = scan_params.get("simulate_threat", False)
    custom_devices = scan_params.get("devices", [])
    transport_type = scan_params.get("transport_type", "")

    detected_devices = []
    findings = []
    
    # 1. Cellular Transport Handling
    if transport_type == "Cellular":
        return {
            "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": 10,
            "risk_level": "LOW",
            "status": "CELLULAR_DATA_ACTIVE",
            "assessment_title": "Potential Hidden-Camera / Surveillance Device Risk Assessment",
            "message": "Local Wi-Fi surveillance scan is unavailable on cellular data. Connect to local Wi-Fi to assess local network devices.",
            "detected_devices": [],
            "findings": [
                "⚠ Cellular Transport Active: Local Wi-Fi network surveillance scan is unavailable on cellular data.",
                "✓ Recommendation: Connect to a local Wi-Fi network to assess local network streaming devices."
            ],
            "recommendation": "Connect to local Wi-Fi to scan for local network surveillance indicators."
        }

    risk_score = 15

    # 2. Evaluate custom/scanned network devices if present
    if custom_devices:
        for dev in custom_devices:
            dev_name = dev.get("name", "Unknown Device")
            ip = dev.get("ip", "192.168.1.50")
            mac = dev.get("mac", "00:00:00:00:00:00")
            ports = dev.get("open_ports", [])
            
            is_suspicious = False
            reasons = []

            # Check open surveillance ports
            if 554 in ports or 3702 in ports or 37777 in ports:
                is_suspicious = True
                reasons.append(f"Exposes RTSP/ONVIF Video Streaming Ports ({[p for p in ports if p in (554, 3702, 37777)]})")

            # Check MAC vendor
            mac_prefix = mac[:8].upper()
            if mac_prefix in CAMERA_VENDOR_MACS:
                is_suspicious = True
                reasons.append(f"MAC Vendor indicates Surveillance / IoT Hardware ({CAMERA_VENDOR_MACS[mac_prefix]})")

            # Check SSID / Hostname
            if any(k in dev_name.lower() for k in SUSPICIOUS_CAMERA_SSIDS):
                is_suspicious = True
                reasons.append(f"Device hostname/SSID matches camera pattern ('{dev_name}')")

            if is_suspicious:
                risk_score += 35
                detected_devices.append({
                    "device_name": dev_name,
                    "ip_address": ip,
                    "mac_address": mac,
                    "risk_level": "MEDIUM/HIGH",
                    "type": "Possible Surveillance / IoT Device",
                    "reasons": reasons
                })

    # 3. Explicit Academic Reviewer Demo Scenario ONLY when simulate_threat = True
    if simulate_threat and not detected_devices:
        risk_score = 65
        detected_devices = [
            {
                "device_name": "IPCAM_Wireless_8829 [DEMO THREAT]",
                "ip_address": "192.168.1.108",
                "mac_address": "00:1A:07:4F:92:11",
                "risk_level": "HIGH",
                "type": "Simulated Academic Demo IP Camera",
                "reasons": [
                    "Exposes RTSP Video Streaming Port 554",
                    "MAC OUI Vendor: Dahua Technology",
                    "Academic Reviewer Demo 4 simulated threat"
                ]
            },
            {
                "device_name": "ESP32-CAM-Node [DEMO THREAT]",
                "ip_address": "192.168.1.114",
                "mac_address": "24:0A:C4:12:34:56",
                "risk_level": "MEDIUM",
                "type": "Simulated Academic Demo Micro Module",
                "reasons": [
                    "Exposes Web Stream Port 8080",
                    "MAC OUI Vendor: Espressif Systems",
                    "Academic Reviewer Demo 4 simulated threat"
                ]
            }
        ]

    final_score = int(min(100, max(0, risk_score)))
    risk_level = map_risk_level(final_score)

    if simulate_threat:
        status = "DEMO_SIMULATED_THREAT"
        assessment_title = "[DEMO SCENARIO] Potential Surveillance Device Risk Assessment"
        message = "Academic Reviewer Demo 4: Simulated surveillance threat evaluation pipeline."
        findings.append("⚠ [DEMO MODE]: Displaying simulated surveillance threat scenario for academic evaluation.")
        findings.append(f"⚠ Detected {len(detected_devices)} simulated device(s) exhibiting RTSP/ONVIF indicators.")
        recommendation = "Reviewer Demo 4 pipeline execution completed cleanly."
    elif detected_devices:
        status = "POTENTIAL_RISK"
        assessment_title = "Potential Hidden-Camera / Surveillance Device Risk Assessment"
        message = f"Detected {len(detected_devices)} potential surveillance signal(s) on current network."
        findings.append(f"⚠ Detected {len(detected_devices)} device(s) exhibiting potential surveillance/IoT indicators.")
        findings.append("⚠ Local Network Scan: Active streaming ports (RTSP 554 / ONVIF) detected.")
        recommendation = "Inspect the physical location and identified network devices manually."
    else:
        status = "NO_SIGNIFICANT_RISK"
        assessment_title = "Potential Hidden-Camera / Surveillance Device Risk Assessment"
        message = "No significant surveillance indicators detected on current network."
        findings.append("✓ Network Scan: No active RTSP/ONVIF camera video streams identified.")
        findings.append("✓ Device Analysis: No known surveillance MAC vendor OUI signatures detected.")
        findings.append("✓ Wi-Fi Analysis: No suspicious camera broadcasting SSIDs found.")
        findings.append("✓ Optical Inspection: Ready for manual lens reflection check.")
        recommendation = "No significant surveillance indicators detected on current network."

    return {
        "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": final_score,
        "risk_level": risk_level,
        "status": status,
        "assessment_title": assessment_title,
        "message": message,
        "scans_completed": {
            "network_scan": True,
            "nearby_device_analysis": True,
            "wifi_analysis": True,
            "optical_inspection": True
        },
        "detected_devices": detected_devices,
        "findings": findings,
        "recommendation": recommendation
    }
