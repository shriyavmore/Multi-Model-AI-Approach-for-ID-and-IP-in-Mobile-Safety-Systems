def generate_prevention_plan(app_data: dict, threat_result: dict, static_result: dict):
    """
    Generates realistic, Android-compliant prevention actions.
    Distinguishes between direct programmatic actions (alert generation, threat state isolation, network sandbox rules)
    and Android system-restricted actions requiring guided user workflows (uninstall intent, permission revocation).
    """
    pkg_name = app_data.get("package_name", "com.example.app")
    app_name = app_data.get("app_name", "Target App")
    severity = threat_result.get("severity", "LOW")

    actions = []
    guided_steps = []

    if severity in ["CRITICAL", "HIGH"]:
        # Direct Action 1: Threat Isolation in IDPS Database
        actions.append({
            "action_type": "ISOLATE_APPLICATION",
            "status": "EXECUTED",
            "description": f"Application '{app_name}' status set to QUARANTINED in IDPS registry."
        })

        # Direct Action 2: Local Network Sandbox Block (Simulated Local VPN/Firewall filter)
        actions.append({
            "action_type": "BLOCK_NETWORK_TRAFFIC",
            "status": "ACTIVE_SIMULATION",
            "description": f"Outbound socket traffic blocked for package '{pkg_name}' via IDPS Local Firewall Sandbox."
        })

        # Guided Action 1: Package Manager Uninstall Intent
        guided_steps.append({
            "step": 1,
            "title": "Uninstall Application",
            "action": "LAUNCH_UNINSTALL_INTENT",
            "target": f"package:{pkg_name}",
            "instruction": f"Click 'Uninstall' to open Android OS package manager screen for '{app_name}' and confirm removal."
        })

        # Guided Action 2: Revoke Sensitive Permissions
        guided_steps.append({
            "step": 2,
            "title": "Revoke Dangerous Permissions",
            "action": "OPEN_APP_SETTINGS",
            "target": f"package:{pkg_name}",
            "instruction": "Navigate to System Settings -> Apps -> " + app_name + " -> Permissions and revoke SMS, Location, and Camera access."
        })

    elif severity == "MEDIUM":
        actions.append({
            "action_type": "ENABLE_STRICT_MONITORING",
            "status": "EXECUTED",
            "description": f"Real-time dynamic monitoring elevated to HIGH FREQUENCY for package '{pkg_name}'."
        })
        guided_steps.append({
            "step": 1,
            "title": "Review Permissions",
            "action": "OPEN_APP_SETTINGS",
            "target": f"package:{pkg_name}",
            "instruction": f"Review requested background permissions for '{app_name}' in Android Settings."
        })

    else:
        actions.append({
            "action_type": "ALLOW_MONITORED",
            "status": "EXECUTED",
            "description": f"Application '{app_name}' permitted under standard background monitoring."
        })

    return {
        "package_name": pkg_name,
        "severity": severity,
        "prevention_status": "ACTION_REQUIRED" if severity in ["CRITICAL", "HIGH"] else "MONITORING",
        "programmatic_actions": actions,
        "guided_user_workflow": guided_steps,
        "android_security_model_note": "Due to Android security sandbox restrictions, third-party security apps cannot silently uninstall apps or alter OS permissions without explicit user authorization via System Settings."
    }
