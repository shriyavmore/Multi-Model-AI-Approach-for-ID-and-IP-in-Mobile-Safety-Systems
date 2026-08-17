from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from .db import Base

class FinalClassificationEnum(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

class SeverityEnum(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatStatusEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String(255), unique=True, nullable=False, index=True)
    app_name = Column(String(150), nullable=False)
    version = Column(String(50), default="1.0.0")
    apk_hash = Column(String(64), nullable=False, index=True)
    installed_at = Column(DateTime, default=datetime.utcnow)

    permissions = relationship("Permission", back_populates="application", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="application", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="application", cascade="all, delete-orphan")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    permission_name = Column(String(255), nullable=False)

    application = relationship("Application", back_populates="permissions")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    scan_time = Column(DateTime, default=datetime.utcnow)
    static_score = Column(Integer, nullable=False)
    dynamic_score = Column(Integer, nullable=False)
    behavioral_score = Column(Integer, nullable=False)
    final_score = Column(Integer, nullable=False)
    final_classification = Column(String(50), nullable=False) # SAFE, SUSPICIOUS, MALICIOUS

    application = relationship("Application", back_populates="scans")
    predictions = relationship("ModelPrediction", back_populates="scan", cascade="all, delete-orphan")

class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    model_name = Column(String(50), nullable=False) # Random Forest, SVM, ANN, Isolation Forest
    prediction = Column(String(50), nullable=False) # SAFE, MALICIOUS, ANOMALY
    confidence = Column(Float, nullable=False)

    scan = relationship("Scan", back_populates="predictions")

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="ACTIVE") # ACTIVE, MITIGATED, RESOLVED

    application = relationship("Application", back_populates="threats")
    alerts = relationship("Alert", back_populates="threat", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    message = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)

    threat = relationship("Threat", back_populates="alerts")

class MaliciousHash(Base):
    __tablename__ = "malicious_hashes"

    id = Column(Integer, primary_key=True, index=True)
    apk_hash = Column(String(64), unique=True, nullable=False, index=True)
    malware_name = Column(String(150), nullable=False)
    severity = Column(String(50), default="CRITICAL")
    added_at = Column(DateTime, default=datetime.utcnow)

class NetworkScan(Base):
    __tablename__ = "network_scans"

    id = Column(Integer, primary_key=True, index=True)
    ssid = Column(String(150), nullable=False)
    bssid = Column(String(100), default="00:00:00:00:00:00")
    transport_type = Column(String(50), default="Wi-Fi") # Wi-Fi, Cellular, Ethernet
    security_type = Column(String(50), default="WPA2") # WPA3, WPA2, Open/None, WEP
    is_validated = Column(Boolean, default=True)
    is_public_guest = Column(Boolean, default=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    findings_json = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)

class RoomSecurityScan(Base):
    __tablename__ = "room_security_scans"

    id = Column(Integer, primary_key=True, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(100), nullable=False) # NO_SIGNIFICANT_RISK, POTENTIAL_RISK, SUSPICIOUS
    detected_devices_json = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
