-- Database Schema for Mobile Intrusion Detection & Prevention System (IDPS)
-- Database Engine: MySQL

CREATE DATABASE IF NOT EXISTS mobile_idps;
USE mobile_idps;

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Applications Table
CREATE TABLE IF NOT EXISTS applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    package_name VARCHAR(255) UNIQUE NOT NULL,
    app_name VARCHAR(150) NOT NULL,
    version VARCHAR(50) DEFAULT '1.0.0',
    apk_hash VARCHAR(64) NOT NULL,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permissions Table
CREATE TABLE IF NOT EXISTS permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    permission_name VARCHAR(255) NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Scans Table
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    static_score INT NOT NULL,
    dynamic_score INT NOT NULL,
    behavioral_score INT NOT NULL,
    final_score INT NOT NULL,
    final_classification ENUM('SAFE', 'SUSPICIOUS', 'MALICIOUS') NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Model Predictions Table
CREATE TABLE IF NOT EXISTS model_predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    model_name VARCHAR(50) NOT NULL,
    prediction VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Threats Table
CREATE TABLE IF NOT EXISTS threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    description TEXT NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('ACTIVE', 'MITIGATED', 'RESOLVED', 'IGNORED') DEFAULT 'ACTIVE',
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    threat_id INT NOT NULL,
    message VARCHAR(255) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE
);

-- Malicious Hashes Table (Signature Database)
CREATE TABLE IF NOT EXISTS malicious_hashes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    apk_hash VARCHAR(64) UNIQUE NOT NULL,
    malware_name VARCHAR(150) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'CRITICAL',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Initial Seed Data for Malicious Hashes
INSERT INTO malicious_hashes (apk_hash, malware_name, severity) VALUES
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Trojan.AndroidOS.Joker.A', 'CRITICAL'),
('8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Spyware.AndroidOS.Pegasus.B', 'CRITICAL'),
('4f8a91b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c', 'Ransomware.AndroidOS.WannaLocker.C', 'CRITICAL'),
('a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e', 'Adware.AndroidOS.HiddenAds.D', 'HIGH'),
('9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0', 'Banker.AndroidOS.Anatsa.E', 'CRITICAL')
ON DUPLICATE KEY UPDATE malware_name=VALUES(malware_name);
