import time
import random
from datetime import datetime

class RealTimeMonitoringService:
    def __init__(self):
        self.is_monitoring = True
        self.events_buffer = []
        self.max_buffer_size = 50
        self._init_sample_events()

    def _init_sample_events(self):
        sample_apps = [
            ("com.whatsapp", "NETWORK_ACTIVITY", "LOW", 12, "Normal encrypted media sync connection established."),
            ("com.google.android.youtube", "API_ACCESS", "LOW", 8, "Background video buffer cache refreshed."),
            ("com.spyware.stealthtracker", "DATA_EXFILTRATION", "CRITICAL", 92, "Unauthorized SMS database read and remote POST to unknown C2 server (192.168.1.105)."),
            ("com.fakebank.loginpay", "OVERLAY_ATTEMPT", "HIGH", 85, "System Alert Window overlay drawn over banking app target."),
            ("com.cleaner.speedbooster", "BACKGROUND_EXECUTION", "MEDIUM", 65, "Repeated background wake-lock service spawned without active notification.")
        ]

        for pkg, evt_type, sev, score, desc in sample_apps:
            event = {
                "id": len(self.events_buffer) + 1,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "package_name": pkg,
                "event_type": evt_type,
                "severity": sev,
                "risk_score": score,
                "description": desc
            }
            self.events_buffer.append(event)

    def start_monitoring(self):
        self.is_monitoring = True
        return {"status": "RUNNING", "message": "Real-time security monitoring service started."}

    def stop_monitoring(self):
        self.is_monitoring = False
        return {"status": "STOPPED", "message": "Real-time security monitoring service paused."}

    def get_status(self):
        return {
            "status": "RUNNING" if self.is_monitoring else "STOPPED",
            "active_monitored_apps": 24,
            "total_events_logged": len(self.events_buffer),
            "threat_events_count": sum(1 for e in self.events_buffer if e["severity"] in ["HIGH", "CRITICAL"]),
            "last_event_time": self.events_buffer[-1]["timestamp"] if self.events_buffer else None
        }

    def get_recent_events(self, limit=20):
        return self.events_buffer[-limit:][::-1]

    def add_event(self, package_name, event_type, severity, risk_score, description):
        event = {
            "id": len(self.events_buffer) + 1,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "package_name": package_name,
            "event_type": event_type,
            "severity": severity,
            "risk_score": risk_score,
            "description": description
        }
        self.events_buffer.append(event)
        if len(self.events_buffer) > self.max_buffer_size:
            self.events_buffer.pop(0)
        return event

monitoring_service_instance = RealTimeMonitoringService()
