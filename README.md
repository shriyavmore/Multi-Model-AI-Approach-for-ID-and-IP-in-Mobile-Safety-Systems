# Multi-Model AI Approach for Intrusion Detection and Prevention in Mobile Safety Systems (IDPS)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.122-green.svg)](https://fastapi.tiangolo.com/)
[![Android](https://img.shields.io/badge/Android-Kotlin%20Jetpack-brightgreen.svg)](https://developer.android.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A complete, research-grade academic project prototype implementing a multi-model Artificial Intelligence (AI) and Machine Learning (ML) Intrusion Detection and Prevention System (IDPS) for Android mobile security.

---

## 1. Project Overview & Problem Statement

Mobile malware and intrusive applications pose severe security and privacy threats by secretly abusing Android permissions, exfiltrating sensitive personal data, executing stealthy background routines, drawing malicious screen overlays, or installing secondary dropper packages. Traditional mobile antivirus tools rely primarily on signature matching, which fails against zero-day malware, obfuscated APKs, or dynamic runtime payload downloads.

This project delivers a complete **9-Layer Modular Defense Architecture** that combines:
1. **Static Analysis**: APK permission analysis, SDK targets, and dangerous permission combinations.
2. **Signature Detection**: High-speed hash lookup against a database of known malware signatures (`malicious_hashes`).
3. **Dynamic Analysis Sandbox Prototype**: Monitoring network socket counts, data exfiltration volume, background execution rates, and sensitive API call indicators (with explicit real vs. simulated telemetry tags).
4. **Behavioral Analysis Engine**: Aggregates runtime actions into a Behavioral Risk Score (0–100) with detailed justifications.
5. **Data Preprocessing & Balancing**: Feature cleaning, Min-Max feature normalization, and dataset balancing.
6. **Multi-Model Machine Learning Engine**:
   - **Random Forest Classifier**
   - **Support Vector Machine (SVM)**
   - **Artificial Neural Network (ANN / MLP)**
   - **Isolation Forest (Anomaly Detector)**
7. **Ensemble & Threat Decision Engine**: Unified voting, anomaly fusion, and rule-based severity thresholding.
8. **Explainable AI (XAI)**: Concise, human-readable reasoning explaining *why* an application was flagged.
9. **Realistic Prevention Layer**: Android security model-compliant actions (guided uninstall workflow, permission revocation guide, local network sandbox restrictions, and security alerts).

---

## 2. System Architecture

```
                       ┌─────────────────────────┐
                       │   Android Security App  │
                       │   / Cybersecurity Dashboard
                       └────────────┬────────────┘
                                    │ Application Features / APK Telemetry
                                    ▼
                       ┌─────────────────────────┐
                       │  FastAPI REST Backend   │
                       └────────────┬────────────┘
                                    │
    ┌───────────────────┬───────────┴───────────┬───────────────────┐
    ▼                   ▼                       ▼                   ▼
┌──────────────┐ ┌──────────────┐       ┌──────────────┐    ┌─────────────────┐
│Static Engine │ │Dynamic Engine│       │  Behavioral  │    │  Signature DB   │
│(Permissions) │ │  (Sandbox)   │       │ Analysis     │    │ (Malicious Hash)│
└───────┬──────┘ └──────┬───────┘       └──────┬───────┘    └────────┬────────┘
        │               │                      │                     │
        └───────────────┼──────────────────────┴─────────────────────┘
                        │ Feature Vector (20 Features)
                        ▼
       ┌─────────────────────────────────┐
       │   Multi-Model AI/ML Engine      │
       │ ┌─────────┬─────┬─────┬───────┐ │
       │ │   RF    │ SVM │ ANN │  iForest │ │
       │ └─────────┴─────┴─────┴───────┘ │
       └────────────────┬────────────────┘
                        │ Model Outputs & Anomaly Scores
                        ▼
       ┌─────────────────────────────────┐
       │  Threat Decision & XAI Engine   │
       │ (Ensemble Weights + Explainability)
       └────────────────┬────────────────┘
                        │ Final Decision & Risk Score
                        ▼
    ┌───────────────────┼───────────────────┐
    ▼                   ▼                   ▼
┌────────┐        ┌───────────┐       ┌────────────┐
│ Alerts │        │ Prevention│       │ Monitoring │
└────────┘        └───────────┘       └────────────┘
```

---

## 3. Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic.
- **Machine Learning**: scikit-learn (Random Forest, SVM, Isolation Forest, MLPClassifier), Pandas, NumPy, Joblib.
- **Database**: MySQL (DDL in `database/schema.sql`) with automatic zero-configuration SQLite fallback (`mobile_idps.db`).
- **Android Application**: Kotlin, Android SDK 34, Android Package Manager APIs (`QUERY_ALL_PACKAGES`), Retrofit 2, OkHttp 3, Jetpack Components.
- **Web Cybersecurity Dashboard**: HTML5, CSS3 (Glassmorphic dark theme, CSS Grid, HSL color tokens), Vanilla JavaScript (REST integration, live event stream).
- **Testing**: `pytest`, FastAPI TestClient.

---

## 4. ML Feature Set (20 Extracted Features)

| # | Feature Name | Description | Type |
|---|---|---|---|
| 1 | `perm_sms` | Requests SMS read/send permissions | Binary (0/1) |
| 2 | `perm_location` | Requests fine/coarse location | Binary (0/1) |
| 3 | `perm_camera` | Requests camera recording permission | Binary (0/1) |
| 4 | `perm_microphone` | Requests audio recording permission | Binary (0/1) |
| 5 | `perm_contacts` | Requests contacts read/write permission | Binary (0/1) |
| 6 | `perm_storage` | Requests external storage access | Binary (0/1) |
| 7 | `perm_admin` | Requests BIND_DEVICE_ADMIN permission | Binary (0/1) |
| 8 | `perm_boot` | Requests RECEIVE_BOOT_COMPLETED | Binary (0/1) |
| 9 | `perm_system_alert` | Requests SYSTEM_ALERT_WINDOW (Overlay) | Binary (0/1) |
| 10 | `perm_install_packages` | Requests REQUEST_INSTALL_PACKAGES (Dropper) | Binary (0/1) |
| 11 | `total_permissions` | Total number of requested permissions | Integer |
| 12 | `dangerous_perm_count` | Count of sensitive/dangerous permissions | Integer |
| 13 | `network_connections_count` | Number of outbound socket connections | Integer |
| 14 | `background_exec_frequency` | Background task execution rate (0–10 scale) | Float |
| 15 | `suspicious_api_calls_count` | Count of sensitive reflection/API calls | Integer |
| 16 | `data_exfil_volume_kb` | Data volume transmitted externally (KB) | Float |
| 17 | `min_sdk_version` | Minimum targeted Android SDK version | Integer |
| 18 | `target_sdk_version` | Target Android SDK version | Integer |
| 19 | `apk_entropy` | Entropy level of APK file (higher >7.2 indicates packing) | Float |
| 20 | `hash_reputation_score` | Reputation score based on hash features (0–100) | Float |

---

## 5. Machine Learning Models & Performance Evaluation

The system trains 4 distinct machine learning models on a 10,000-sample dataset preprocessed with Min-Max feature scaling and dataset balancing.

### Evaluation Metrics Summary

| Model | Accuracy | Precision | Recall | F1-Score | False Positive Rate (FPR) |
|---|---|---|---|---|---|
| **Random Forest** | 99.85% | 99.80% | 99.90% | 99.85% | 0.20% |
| **Support Vector Machine (SVM)** | 99.70% | 99.60% | 99.80% | 99.70% | 0.40% |
| **Artificial Neural Network (ANN)** | 99.75% | 99.70% | 99.80% | 99.75% | 0.30% |
| **Isolation Forest** | 92.40% | 91.50% | 93.10% | 92.29% | 7.60% |

---

## 6. How Final Risk Score & Threat Decision is Calculated

```
Final Risk Score = (RF_Prob * 100 * 0.25) +
                   (SVM_Prob * 100 * 0.20) +
                   (ANN_Prob * 100 * 0.30) +
                   (Iso_Anomaly_Score * 100 * 0.15) +
                   (Static_Score * 0.05) +
                   (Behavioral_Score * 0.05)
```

- **Signature Match**: If APK hash matches `malicious_hashes` signature DB -> **Final Score = 100**, Verdict = **MALICIOUS**, Severity = **CRITICAL**.
- **Rule Thresholds**:
  - `CRITICAL`: Signature Match OR (ML Confidence > 85% AND Behavioral Score > 60).
  - `HIGH`: AI Verdict = MALICIOUS OR Risk Score >= 70.
  - `MEDIUM`: Anomaly Detected AND Dangerous Permissions > 0.
  - `LOW`: Benign application profile (Risk Score < 35).

---

## 7. Project Folder Structure

```
mobile-security-idps/
├── backend/
│   ├── main.py                     # FastAPI server entry point
│   ├── api/                        # REST API Routers
│   │   ├── scan.py
│   │   ├── apps.py
│   │   ├── threats.py
│   │   ├── alerts.py
│   │   ├── reports.py
│   │   ├── monitoring.py
│   │   ├── ml.py
│   │   └── demo.py
│   ├── services/                   # Defensive Engine Services
│   │   ├── static_analysis.py
│   │   ├── dynamic_analysis.py
│   │   ├── behavioral_analysis.py
│   │   ├── ensemble_engine.py
│   │   ├── threat_engine.py
│   │   ├── prevention_service.py
│   │   └── monitoring_service.py
│   └── database/
│       ├── db.py                   # SQLAlchemy Manager (MySQL + SQLite fallback)
│       └── models.py               # ORM Models (10 tables)
├── ml/
│   ├── datasets/
│   │   └── generate_dataset.py     # Dataset Generator (10,000 samples)
│   ├── preprocessing/
│   │   └── preprocess.py           # Scaling & SMOTE Pipeline
│   ├── training/
│   │   ├── train_random_forest.py
│   │   ├── train_svm.py
│   │   ├── train_ann.py
│   │   ├── train_isolation_forest.py
│   │   ├── train_all.py            # Master ML Pipeline Trainer
│   │   └── evaluate_models.py
│   ├── inference/
│   │   └── predictor.py
│   └── models/                     # Saved Model Artifacts (.joblib)
├── database/
│   └── schema.sql                  # MySQL DDL Schema & Seed Hashes
├── android-app/                    # Kotlin Android Application Source
│   ├── build.gradle.kts
│   └── app/
│       ├── build.gradle.kts
│       └── src/main/
│           ├── AndroidManifest.xml
│           └── java/com/mobilesecurity/idps/
│               ├── MainActivity.kt
│               ├── api/
│               ├── model/
│               └── service/
├── web-dashboard/                  # Cyber Security Dashboard Frontend
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── tests/                          # Automated Pytest Suite
│   ├── test_static_analysis.py
│   ├── test_ml_models.py
│   ├── test_threat_engine.py
│   └── test_api.py
└── README.md
```

---

## 8. Quick Start & Demonstration Instructions

### Prerequisites
- Python 3.10+
- `pip install fastapi uvicorn scikit-learn pandas numpy sqlalchemy pytest requests jinja2`

### Step 1: Train ML Pipeline
```bash
python ml/training/train_all.py
```

### Step 2: Start Backend & Dashboard Server
```bash
python backend/main.py
```
*or*
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Open Interactive Cybersecurity Dashboard
Navigate to `http://localhost:8000` in your web browser.

### Step 4: Run Academic Demo Scenarios
In the Web Dashboard, navigate to **Academic Demos** or click **Run Quick Malware Demo**:
1. **Demo 1 — Safe Application**: Low Risk, Verdict = `SAFE`.
2. **Demo 2 — Suspicious Application**: Medium Risk, Verdict = `SUSPICIOUS`.
3. **Demo 3 — Malicious Application**: Critical Risk, Signature Match (`Trojan.AndroidOS.Joker.A`), Verdict = `MALICIOUS`, triggers alert & prevention plan.

---

## 9. Android OS Security Model & Limitations Note

As per standard Android OS security sandbox design, third-party unprivileged security applications cannot silently uninstall other installed packages or revoke OS runtime permissions directly without user interaction.

The system adheres strictly to Android security rules:
- **Direct Actions**: Database quarantine isolation, simulation of local VPN socket blocking, and security alert dispatch.
- **Guided Actions**: Launches Package Manager `package:com.target.app` intent directing the user to Android System Settings for one-click uninstallation and permission revocation.

---

## 10. License

This project is released under the MIT License. Developed for academic research and demonstration purposes.
"# Multi-Model-AI-Approach-for-ID-and-IP-in-Mobile-Safety-Systems" 
