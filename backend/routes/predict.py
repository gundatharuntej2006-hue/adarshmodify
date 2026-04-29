"""Single-input and batch threat prediction endpoints."""
import json
import logging

import pandas as pd
from flask import Blueprint, current_app, jsonify, request

from backend import state
from backend.constants import FEATURES
from backend.models.inference import check_anomaly, compute_shap_values, compute_shap_xai
import random
import time
from threading import Thread

from backend.services.geo import geolocate_attack
from backend.live_feed import socketio

logger = logging.getLogger("soc.predict")

bp = Blueprint("predict", __name__)


@bp.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        row = {f: data.get(f, 0) for f in FEATURES}
        df2 = pd.DataFrame([row])
        scaled = state.threat_scaler.transform(df2)
        pred = state.threat_model.predict(scaled)[0]
        proba = state.threat_model.predict_proba(scaled)[0].tolist()
        threat = state.threat_le.inverse_transform([pred])[0]
        conf = float(max(proba))
        classes = state.threat_le.classes_.tolist()

        response = {
            "threat":        threat,
            "confidence":    round(conf * 100, 2),
            "probabilities": {cls: round(float(p) * 100, 2) for cls, p in zip(classes, proba)},
        }

        if state.ATTACK_MODEL is not None and state.ATTACK_SCALER is not None and state.ATTACK_LE is not None:
            try:
                atk_scaled = state.ATTACK_SCALER.transform(df2)
                atk_pred = state.ATTACK_MODEL.predict(atk_scaled)[0]
                atk_proba = state.ATTACK_MODEL.predict_proba(atk_scaled)[0].tolist()
                atk_type = state.ATTACK_LE.inverse_transform([atk_pred])[0]
                atk_classes = state.ATTACK_LE.classes_.tolist()
                response["attack_type"] = atk_type
                response["attack_probabilities"] = {
                    cls: round(float(p) * 100, 2) for cls, p in zip(atk_classes, atk_proba)
                }
            except Exception as atk_e:
                logger.error("Attack classification error: %s", atk_e)
                response["attack_type"] = "Unknown"
                response["attack_probabilities"] = {}

        shap_vals = compute_shap_values(df2)
        if shap_vals is not None:
            response["shap_values"] = shap_vals

        response["xai"] = compute_shap_xai(df2)

        is_anomalous, anomaly_score = check_anomaly(df2)
        response["is_anomalous"] = is_anomalous
        response["anomaly_score"] = anomaly_score

        geo = geolocate_attack(response.get("attack_type", "Normal"))
        if geo:
            response["location"] = geo

        def simulate_attacks(base_response):
            time.sleep(1)
            num_attacks = random.randint(5, 10)
            for _ in range(num_attacks):
                time.sleep(0.5)
                conf_variance = random.uniform(-5, 5)
                new_conf = max(0.0, min(100.0, base_response.get("confidence", 0) + conf_variance))
                
                simulated_event = {
                    "threat": base_response.get("threat", "LOW"),
                    "attack_type": base_response.get("attack_type", "Normal"),
                    "confidence": new_conf,
                    "location": {
                        "lat": random.uniform(-60, 60),
                        "lng": random.uniform(-180, 180),
                        "country": "Simulated",
                        "city": "Unknown"
                    },
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    "is_anomalous": base_response.get("is_anomalous", False),
                    "anomaly_score": base_response.get("anomaly_score", 0.0)
                }
                socketio.emit("live_threat", simulated_event)
                
        Thread(target=simulate_attacks, args=(response,)).start()

        return current_app.response_class(json.dumps(response), mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/predict-batch", methods=["POST"])
def predict_batch():
    """Batch predict from uploaded CSV."""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file provided", "data": None}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"success": False, "error": "No file selected", "data": None}), 400

        try:
            df_batch = pd.read_csv(file)
        except Exception:
            file.seek(0)
            df_batch = pd.read_csv(file, header=None, names=FEATURES)

        results = []
        attack_counts = {}
        threat_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for idx, row_data in df_batch.iterrows():
            row = {f: float(row_data.get(f, 0)) if f in row_data.index else 0 for f in FEATURES}
            df_single = pd.DataFrame([row])

            try:
                scaled = state.threat_scaler.transform(df_single)
                pred = state.threat_model.predict(scaled)[0]
                proba = state.threat_model.predict_proba(scaled)[0].tolist()
                threat = state.threat_le.inverse_transform([pred])[0]
                conf = round(float(max(proba)) * 100, 2)

                atk_type = "Unknown"
                if state.ATTACK_MODEL and state.ATTACK_SCALER and state.ATTACK_LE:
                    atk_scaled = state.ATTACK_SCALER.transform(df_single)
                    atk_pred = state.ATTACK_MODEL.predict(atk_scaled)[0]
                    atk_type = state.ATTACK_LE.inverse_transform([atk_pred])[0]

                is_anom, anom_score = check_anomaly(df_single)

                results.append({
                    "index":         int(idx),
                    "threat":        threat,
                    "confidence":    conf,
                    "attack_type":   atk_type,
                    "is_anomalous":  is_anom,
                    "anomaly_score": anom_score,
                    "probability":   round(float(max(proba)) * 100, 2),
                })

                attack_counts[atk_type] = attack_counts.get(atk_type, 0) + 1
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
            except Exception as row_err:
                results.append({
                    "index":       int(idx),
                    "threat":      "ERROR",
                    "confidence":  0,
                    "attack_type": "Error",
                    "error":       str(row_err),
                })

        return jsonify({
            "success": True,
            "data": {
                "total":             len(results),
                "results":           results,
                "attack_breakdown":  attack_counts,
                "threat_breakdown":  threat_counts,
            },
            "error": None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "data": None}), 500
