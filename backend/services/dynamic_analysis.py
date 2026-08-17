def analyze_dynamic_telemetry(dynamic_data: dict):
    """
    Safe dynamic analysis sandbox prototype.
    Evaluates network activity indicators, background execution, and suspicious runtime API calls.
    Explicitly labels whether telemetry originates from live device APIs or controlled sandbox simulation.
    """
    is_simulated = dynamic_data.get("is_simulated", True)
    network_connections = dynamic_data.get("network_connections_count", 0)
    bg_freq = dynamic_data.get("background_exec_frequency", 0.0)
    suspicious_apis = dynamic_data.get("suspicious_api_calls_count", 0)
    exfil_kb = dynamic_data.get("data_exfil_volume_kb", 0.0)

    score = 0
    indicators = []

    # Network analysis
    if network_connections > 20:
        score += 30
        indicators.append(f"High network volume: {network_connections} active remote socket connections detected.")
    elif network_connections > 8:
        score += 15
        indicators.append(f"Moderate network connections ({network_connections}) in short timeframe.")

    # Data exfiltration
    if exfil_kb > 2000.0:
        score += 35
        indicators.append(f"High data transmission volume ({exfil_kb:.1f} KB exfiltrated to external hosts).")
    elif exfil_kb > 500.0:
        score += 15
        indicators.append(f"Elevated data exfiltration ({exfil_kb:.1f} KB transferred).")

    # Background execution
    if bg_freq > 6.0:
        score += 25
        indicators.append(f"Excessive background execution rate ({bg_freq:.1f} tasks/min without foreground service).")

    # Suspicious API execution
    if suspicious_apis > 5:
        score += 30
        indicators.append(f"Frequent invocation of sensitive APIs ({suspicious_apis} dynamic class loading / shell execution calls).")

    dynamic_score = min(100, score)

    return {
        "dynamic_score": dynamic_score,
        "is_simulated": is_simulated,
        "telemetry_source": "Controlled Sandbox Simulation Pipeline" if is_simulated else "Live Android Runtime Telemetry",
        "network_connections": network_connections,
        "data_exfiltered_kb": exfil_kb,
        "background_execution_freq": bg_freq,
        "suspicious_api_calls": suspicious_apis,
        "dynamic_indicators": indicators if indicators else ["Normal runtime execution profile observed."]
    }
