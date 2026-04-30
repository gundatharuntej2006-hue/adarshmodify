"""Flask application factory.

Importing `create_app` and calling it builds a fully-wired app:
  1. Boots logging + config (via `backend.config`)
  2. Loads or trains all ML models
  3. Registers every blueprint
"""
import logging

import joblib
from flask import Flask
from flask_cors import CORS

from backend.live_feed import socketio, background_thread

# Importing config first runs load_dotenv() and configures logging.
from backend import state
from backend.config import (
    ALLOWED_ORIGINS,
    DATASET_PATH,
    FORCE_RETRAIN,
    LABEL_ENCODER_PATH,
    SCALER_PATH,
    THREAT_MODEL_PATH,
)
from backend.models import cache as model_cache
from backend.models.trainer import train_all_models
from backend.routes.aria import bp as aria_bp
from backend.routes.explain import bp as explain_bp
from backend.routes.meta import bp as meta_bp
from backend.routes.predict import bp as predict_bp
from backend.routes.reports import bp as reports_bp

logger = logging.getLogger("soc.app")


def _load_threat_pipeline():
    """Load the legacy threat-level RF, scaler, and label encoder from .pkl files.
    If any file is missing, regenerate them from the dataset automatically.
    """
    import os
    if not (os.path.exists(THREAT_MODEL_PATH) and
            os.path.exists(SCALER_PATH) and
            os.path.exists(LABEL_ENCODER_PATH)):
        logger.warning("Legacy .pkl files missing — regenerating from dataset...")
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        from backend.constants import DATASET_COLUMNS, FEATURES, map_threat
        df = pd.read_csv(DATASET_PATH, header=None, names=DATASET_COLUMNS)
        df.drop("difficulty", axis=1, inplace=True)
        df["threat_level"] = df["label"].apply(map_threat)
        df.drop("label", axis=1, inplace=True)
        # Use LabelEncoder for categoricals — same approach as trainer.py
        # This produces alphabetical encoding: icmp=0,tcp=1,udp=2 / SF=9,S0=5 etc.
        for col_name in ["protocol_type", "service", "flag"]:
            col_le = LabelEncoder()
            df[col_name] = col_le.fit_transform(df[col_name])
        le = LabelEncoder()
        df["threat_level"] = le.fit_transform(df["threat_level"])
        X = df[FEATURES]
        y = df["threat_level"]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = RandomForestClassifier(n_estimators=30, random_state=42, n_jobs=-1)
        model.fit(X_scaled, y)
        joblib.dump(model,  THREAT_MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(le,     LABEL_ENCODER_PATH)
        logger.info("Legacy pipeline regenerated and saved.")

    state.threat_model  = joblib.load(THREAT_MODEL_PATH)
    state.threat_scaler = joblib.load(SCALER_PATH)
    state.threat_le     = joblib.load(LABEL_ENCODER_PATH)


def _ensure_models_ready():
    """Load model cache if available, otherwise train from the dataset."""
    try:
        if FORCE_RETRAIN or not model_cache.try_load(DATASET_PATH):
            train_all_models(DATASET_PATH)
            model_cache.save(DATASET_PATH)
    except Exception as e:
        logger.exception("ERROR loading metrics")
        state.METRICS = {"error": str(e)}


def create_app():
    """Build and return the Flask app."""
    app = Flask(__name__)
    CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=False)

    # Optional UBA blueprint — only loads if SQLAlchemy is installed.
    try:
        from backend.uba import setup_uba
        setup_uba(app)
    except ImportError as e:
        logger.warning("UBA module could not be loaded. Ensure sqlalchemy is installed. %s", e)

    _load_threat_pipeline()
    _ensure_models_ready()

    # ── Train/load the NEW 13-feature model (network_threat_dataset.xlsx) ──
    import os
    from backend.models.new_trainer import train_new_model, load_new_model
    NEW_DATASET = os.path.join(os.path.dirname(__file__), "network_threat_dataset.xlsx")
    MODEL_DIR   = os.path.dirname(os.path.dirname(__file__))  # project root
    if os.path.exists(NEW_DATASET):
        if not load_new_model(MODEL_DIR):
            logger.info("Training NEW model from network_threat_dataset.xlsx...")
            acc = train_new_model(NEW_DATASET, MODEL_DIR)
            logger.info("NEW model trained — accuracy: %.2f%%", acc * 100)
        else:
            logger.info("NEW model loaded from cache.")
    else:
        logger.warning("network_threat_dataset.xlsx not found at %s", NEW_DATASET)

    app.register_blueprint(predict_bp)
    app.register_blueprint(explain_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(aria_bp)
    app.register_blueprint(meta_bp)

    from backend.routes.email_report import bp as email_report_bp
    app.register_blueprint(email_report_bp)

    socketio.init_app(app)
    socketio.start_background_task(background_thread)

    return app

