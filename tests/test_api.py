from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_api_root():
    response = client.get("/")
    assert response.status_code == 200

def test_demo_scenarios_api():
    response = client.get("/api/demo/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 3

def test_run_demo_scenario_scan():
    response = client.post("/api/demo/run/demo_3_malicious")
    assert response.status_code == 200
    data = response.json()
    assert data["ai_ml_ensemble"]["final_classification"] == "MALICIOUS"
    assert data["ai_ml_ensemble"]["final_risk_score"] >= 80

def test_get_apps_api():
    response = client.get("/api/apps")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_ml_performance_api():
    response = client.get("/api/ml/performance")
    assert response.status_code == 200
    data = response.json()
    assert "Random Forest" in data
    assert "SVM" in data
    assert "ANN" in data
    assert "Isolation Forest" in data

def test_network_api():
    response = client.get("/api/v1/network/status")
    assert response.status_code == 200
    data = response.json()
    assert "ssid" in data
    assert "risk_level" in data

def test_room_security_api():
    response = client.post("/api/v1/room-security/scan", json={"simulate_threat": False})
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "status" in data
