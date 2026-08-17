import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

FEATURE_COLUMNS = [
    'perm_sms', 'perm_location', 'perm_camera', 'perm_microphone',
    'perm_contacts', 'perm_storage', 'perm_admin', 'perm_boot',
    'perm_system_alert', 'perm_install_packages', 'total_permissions',
    'dangerous_perm_count', 'network_connections_count',
    'background_exec_frequency', 'suspicious_api_calls_count',
    'data_exfil_volume_kb', 'min_sdk_version', 'target_sdk_version',
    'apk_entropy', 'hash_reputation_score'
]

TARGET_COLUMN = 'is_malicious'

def preprocess_and_balance_dataset(csv_path, test_size=0.2, save_scaler_dir=None):
    """
    Cleans data, normalizes using Min-Max Scaler, balances dataset with SMOTE/oversampling,
    and returns train/test splits.
    """
    df = pd.read_csv(csv_path)

    # 1. Cleaning
    df = df.drop_duplicates().dropna()

    X = df[FEATURE_COLUMNS].copy()
    y = df[TARGET_COLUMN].copy()

    # 2. Min-Max Normalization
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURE_COLUMNS)

    # Save fitted scaler for inference pipeline
    if save_scaler_dir is None:
        save_scaler_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(save_scaler_dir, exist_ok=True)
    scaler_path = os.path.join(save_scaler_dir, "scaler.joblib")
    joblib.dump(scaler, scaler_path)
    print(f"[PREPROCESSING] MinMaxScaler saved to {scaler_path}")

    # 3. Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled_df, y, test_size=test_size, random_state=42, stratify=y
    )

    # 4. Balancing with SMOTE / OverSampling fallback
    try:
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(random_state=42)
        X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
        print("[PREPROCESSING] Dataset balanced using SMOTE.")
    except Exception:
        # Fallback to simple random oversampling if imblearn isn't installed
        safe_idx = y_train[y_train == 0].index
        malware_idx = y_train[y_train == 1].index
        max_len = max(len(safe_idx), len(malware_idx))

        safe_res = y_train.loc[safe_idx].sample(max_len, replace=True, random_state=42)
        malware_res = y_train.loc[malware_idx].sample(max_len, replace=True, random_state=42)
        
        y_train_res = pd.concat([safe_res, malware_res])
        X_train_res = X_train.loc[y_train_res.index]
        print("[PREPROCESSING] Dataset balanced using Random Resampling fallback.")

    return X_train_res, X_test, y_train_res, y_test, scaler

def load_scaler(model_dir=None):
    if model_dir is None:
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    scaler_path = os.path.join(model_dir, "scaler.joblib")
    if os.path.exists(scaler_path):
        return joblib.load(scaler_path)
    return None
