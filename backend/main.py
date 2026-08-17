import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Ensure project root in python path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database.db import engine, Base, SessionLocal
from backend.database.models import MaliciousHash
from backend.api import scan, apps, threats, alerts, reports, monitoring, ml, demo, network, room_security

# Create database tables automatically
Base.metadata.create_all(bind=engine)

# Seed default malicious hashes if missing
def seed_malicious_hashes():
    db = SessionLocal()
    try:
        count = db.query(MaliciousHash).count()
        if count == 0:
            default_hashes = [
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Trojan.AndroidOS.Joker.A", "CRITICAL"),
                ("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "Spyware.AndroidOS.Pegasus.B", "CRITICAL"),
                ("4f8a91b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c", "Ransomware.AndroidOS.WannaLocker.C", "CRITICAL"),
                ("a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", "Adware.AndroidOS.HiddenAds.D", "HIGH"),
                ("9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0", "Banker.AndroidOS.Anatsa.E", "CRITICAL")
            ]
            for h_val, m_name, sev in default_hashes:
                db.add(MaliciousHash(apk_hash=h_val, malware_name=m_name, severity=sev))
            db.commit()
            print("[DATABASE SEED] Seeded default malware hashes into database.")
    except Exception as e:
        print(f"[DATABASE SEED ERROR] {e}")
    finally:
        db.close()

seed_malicious_hashes()

app = FastAPI(
    title="Mobile Intrusion Detection and Prevention System (IDPS) API",
    description="Multi-Model AI Approach for Mobile Malware Detection, Anomaly Detection, Static/Dynamic Analysis & Prevention",
    version="1.0.0"
)

cors_origins_env = os.getenv("CORS_ORIGINS")
if cors_origins_env:
    origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
else:
    # Default allowed origins for local development and testing
    origins = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(scan.router)
app.include_router(apps.router)
app.include_router(threats.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(monitoring.router)
app.include_router(ml.router)
app.include_router(demo.router)
app.include_router(network.router)
app.include_router(room_security.router)


# Mount Web Dashboard Frontend
web_dashboard_dir = os.path.join(BASE_DIR, "web-dashboard")
if os.path.exists(web_dashboard_dir):
    app.mount("/static", StaticFiles(directory=web_dashboard_dir), name="static")

@app.get("/")
def read_root():
    index_path = os.path.join(web_dashboard_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "status": "ONLINE",
        "system": "Mobile Intrusion Detection and Prevention System (IDPS)",
        "docs_url": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
