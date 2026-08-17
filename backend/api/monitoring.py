from fastapi import APIRouter
from backend.services.monitoring_service import monitoring_service_instance

router = APIRouter(prefix="/api/monitoring", tags=["Real-Time Security Monitoring"])

@router.get("/status")
def get_monitoring_status():
    return monitoring_service_instance.get_status()

@router.post("/start")
def start_monitoring():
    return monitoring_service_instance.start_monitoring()

@router.post("/stop")
def stop_monitoring():
    return monitoring_service_instance.stop_monitoring()

@router.get("/events")
def get_monitoring_events(limit: int = 20):
    return monitoring_service_instance.get_recent_events(limit=limit)
