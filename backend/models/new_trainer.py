"""
Training module for the new network_threat_dataset.xlsx (14 features).
Replaces the old NSL-KDD 41-feature pipeline.
"""
import logging
import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from backend import state

logger = logging.getLogger("soc.new_trainer")

# ── Column mapping from new dataset → internal names ────────────────────────
COL_MAP = {
    "protocol_type":        "protocol_type",
    "service_type":         "service",
    "connection_flag":      "flag",
    "duration_s":           "duration",
    "failed_logins":        "num_failed_logins",
    "src_bytes":            "src_bytes",
    "dst_bytes":            "dst_bytes",
    "logged_in":            "logged_in",
    "root_shell":           "root_shell",
    "count":                "count",
    "srv_count":            "srv_count",
    "error_rate_syn_flood": "serror_rate",
    "dst_host_count":       "dst_host_count",
    "threat_level":         "threat_level",
}

# The 13 input features (in order) that the model expects
NEW_FEATURES = [
    "protocol_type", "service", "flag", "duration",
    "num_failed_logins", "src_bytes", "dst_bytes",
    "logged_in", "root_shell",
    "count", "srv_count", "serror_rate", "dst_host_count",
]


def train_new_model(xlsx_path: str, model_dir: str):
    """Train a RandomForest on network_threat_dataset.xlsx and persist to model_dir."""
    logger.info("Loading new dataset from: %s", xlsx_path)
    df = pd.read_excel(xlsx_path)
    df.rename(columns=COL_MAP, inplace=True)
    logger.info("Dataset loaded: %s rows, %s cols", *df.shape)

    # ── Encode categoricals with LabelEncoder ───────────────────────────────
    encoders = {}
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        logger.info("  %s classes: %s", col, dict(zip(le.classes_, le.transform(le.classes_))))

    # Encode binary YES/NO → 1/0
    for col in ["logged_in", "root_shell"]:
        df[col] = df[col].map({"YES": 1, "NO": 0}).fillna(0).astype(int)

    # ── Encode target ───────────────────────────────────────────────────────
    threat_le = LabelEncoder()
    df["threat_level"] = threat_le.fit_transform(df["threat_level"])
    logger.info("  threat classes: %s", dict(zip(threat_le.classes_, threat_le.transform(threat_le.classes_))))

    X = df[NEW_FEATURES]
    y = df["threat_level"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # ── Random Forest ───────────────────────────────────────────────────────
    logger.info("Training RandomForest on new dataset...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_s, y_train)
    acc = accuracy_score(y_test, rf.predict(X_test_s))
    logger.info("  Accuracy: %.2f%%", acc * 100)

    # ── Isolation Forest ────────────────────────────────────────────────────
    logger.info("Training Isolation Forest...")
    iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_train_s)

    # ── Persist everything ──────────────────────────────────────────────────
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(rf,         os.path.join(model_dir, "new_model.pkl"))
    joblib.dump(scaler,     os.path.join(model_dir, "new_scaler.pkl"))
    joblib.dump(threat_le,  os.path.join(model_dir, "new_threat_le.pkl"))
    joblib.dump(encoders,   os.path.join(model_dir, "new_encoders.pkl"))
    joblib.dump(iso,        os.path.join(model_dir, "new_isolation.pkl"))
    logger.info("All new models saved to %s", model_dir)

    # ── Write into state so predict route can use them immediately ──────────
    state.NEW_MODEL       = rf
    state.NEW_SCALER      = scaler
    state.NEW_THREAT_LE   = threat_le
    state.NEW_ENCODERS    = encoders
    state.NEW_ISOLATION   = iso
    state.NEW_FEATURES    = NEW_FEATURES

    return acc


def load_new_model(model_dir: str) -> bool:
    """Load previously trained new-dataset models from disk. Returns True if OK."""
    paths = {
        "model":     os.path.join(model_dir, "new_model.pkl"),
        "scaler":    os.path.join(model_dir, "new_scaler.pkl"),
        "threat_le": os.path.join(model_dir, "new_threat_le.pkl"),
        "encoders":  os.path.join(model_dir, "new_encoders.pkl"),
        "isolation": os.path.join(model_dir, "new_isolation.pkl"),
    }
    if not all(os.path.exists(p) for p in paths.values()):
        return False

    state.NEW_MODEL       = joblib.load(paths["model"])
    state.NEW_SCALER      = joblib.load(paths["scaler"])
    state.NEW_THREAT_LE   = joblib.load(paths["threat_le"])
    state.NEW_ENCODERS    = joblib.load(paths["encoders"])
    state.NEW_ISOLATION   = joblib.load(paths["isolation"])
    state.NEW_FEATURES    = NEW_FEATURES
    logger.info("New-dataset models loaded from cache.")
    return True
