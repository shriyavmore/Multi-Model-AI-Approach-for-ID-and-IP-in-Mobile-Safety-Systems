import pytest
from ml.inference.predictor import MLPredictor

@pytest.fixture
def predictor():
    return MLPredictor()

def test_safe_sample_inference(predictor):
    safe_features = {
        'perm_sms': 0, 'perm_location': 0, 'perm_camera': 0, 'perm_microphone': 0,
        'perm_contacts': 0, 'perm_storage': 1, 'perm_admin': 0, 'perm_boot': 0,
        'perm_system_alert': 0, 'perm_install_packages': 0, 'total_permissions': 4,
        'dangerous_perm_count': 0, 'network_connections_count': 2,
        'background_exec_frequency': 0.5, 'suspicious_api_calls_count': 0,
        'data_exfil_volume_kb': 50.0, 'min_sdk_version': 26, 'target_sdk_version': 33,
        'apk_entropy': 5.6, 'hash_reputation_score': 95.0
    }
    preds = predictor.predict(safe_features)
    assert preds['random_forest']['prediction'] in ['SAFE', 'MALICIOUS']
    assert preds['svm']['prediction'] in ['SAFE', 'MALICIOUS']
    assert preds['ann']['prediction'] in ['SAFE', 'MALICIOUS']
    assert 'is_anomaly' in preds['isolation_forest']

def test_malicious_sample_inference(predictor):
    malware_features = {
        'perm_sms': 1, 'perm_location': 1, 'perm_camera': 1, 'perm_microphone': 1,
        'perm_contacts': 1, 'perm_storage': 1, 'perm_admin': 1, 'perm_boot': 1,
        'perm_system_alert': 1, 'perm_install_packages': 1, 'total_permissions': 35,
        'dangerous_perm_count': 14, 'network_connections_count': 45,
        'background_exec_frequency': 9.2, 'suspicious_api_calls_count': 18,
        'data_exfil_volume_kb': 15000.0, 'min_sdk_version': 19, 'target_sdk_version': 28,
        'apk_entropy': 7.8, 'hash_reputation_score': 10.0
    }
    preds = predictor.predict(malware_features)
    assert preds['random_forest']['prediction'] == 'MALICIOUS'
    assert preds['svm']['prediction'] == 'MALICIOUS'
    assert preds['ann']['prediction'] == 'MALICIOUS'
