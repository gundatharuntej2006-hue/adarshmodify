"""Single-input and batch threat prediction endpoints.

Uses the NEW 13-feature model trained on network_threat_dataset.xlsx.
"""
import json
import logging

import numpy as np
import pandas as pd
from flask import Blueprint, current_app, jsonify, request

from backend import state
from backend.services.geo import geolocate_attack

logger = logging.getLogger("soc.predict")

bp = Blueprint("predict", __name__)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _safe_int(val, default=0):
    """Convert YES/NO/True/False/1/0 to int."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip().upper()
    if s in ("YES", "TRUE", "1", "ON"):
        return 1
    if s in ("NO", "FALSE", "0", "OFF", ""):
        return 0
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return default


def _safe_float(val, default=0.0):
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _encode_categorical(val, encoder, default_class=None):
    """Encode a categorical value using the LabelEncoder from training.
    Accepts both the original string and pre-encoded int.
    """
    if isinstance(val, (int, float)):
        v = int(val)
        # Already an encoded int — validate it's in range
        if 0 <= v < len(encoder.classes_):
            return v
        return 0

    s = str(val).strip()
    # Try exact match first
    if s in encoder.classes_:
        return int(encoder.transform([s])[0])
    # Try case-insensitive match
    for cls in encoder.classes_:
        if cls.upper() == s.upper():
            return int(encoder.transform([cls])[0])
    # Try partial match (e.g. "SF" matches "SF (Normal)")
    for cls in encoder.classes_:
        if s.upper() in cls.upper() or cls.upper() in s.upper():
            return int(encoder.transform([cls])[0])
    # Default
    if default_class and default_class in encoder.classes_:
        return int(encoder.transform([default_class])[0])
    return 0


# ── Main predict endpoint ──────────────────────────────────────────────────

@bp.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True) or {}

        # Check if new model is loaded
        if not hasattr(state, 'NEW_MODEL') or state.NEW_MODEL is None:
            return jsonify({"error": "Model not loaded yet. Restart the backend."}), 503

        encoders = state.NEW_ENCODERS

        # ── Encode categorical fields using training encoders ──
        proto_enc = _encode_categorical(
            data.get("protocol_type", "TCP"), encoders["protocol_type"], "TCP")
        svc_enc = _encode_categorical(
            data.get("service", "HTTP"), encoders["service"], "HTTP")
        flag_enc = _encode_categorical(
            data.get("flag", "SF (Normal)"), encoders["flag"], "SF (Normal)")

        # ── Build 13-feature row in exact training order ──
        row = {
            "protocol_type":    proto_enc,
            "service":          svc_enc,
            "flag":             flag_enc,
            "duration":         _safe_float(data.get("duration", 0)),
            "num_failed_logins": _safe_float(data.get("num_failed_logins", 0)),
            "src_bytes":        _safe_float(data.get("src_bytes", 0)),
            "dst_bytes":        _safe_float(data.get("dst_bytes", 0)),
            "logged_in":        float(_safe_int(data.get("logged_in", 0))),
            "root_shell":       float(_safe_int(data.get("root_shell", 0))),
            "count":            _safe_float(data.get("count", 0)),
            "srv_count":        _safe_float(data.get("srv_count", 0)),
            "serror_rate":      _safe_float(data.get("serror_rate", 0)),
            "dst_host_count":   _safe_float(data.get("dst_host_count", 0)),
        }

        df = pd.DataFrame([row])[state.NEW_FEATURES]  # ensure column order
        scaled = state.NEW_SCALER.transform(df)

        pred_idx = state.NEW_MODEL.predict(scaled)[0]
        proba = state.NEW_MODEL.predict_proba(scaled)[0].tolist()
        threat = state.NEW_THREAT_LE.inverse_transform([pred_idx])[0]
        conf = float(max(proba))
        classes = state.NEW_THREAT_LE.classes_.tolist()

        logger.info(
            "proto=%s flag=%s root_shell=%.0f count=%.0f serror=%.2f → %s (%.1f%%)",
            data.get("protocol_type"), data.get("flag"),
            row["root_shell"], row["count"], row["serror_rate"],
            threat, conf * 100,
        )

        # Build probability dict
        probabilities = {cls: round(float(p) * 100, 2) for cls, p in zip(classes, proba)}

        # ── Rule-based safety override ──────────────────────────────────────
        root_shell    = row["root_shell"]
        failed_logins = row["num_failed_logins"]
        serror_rate   = row["serror_rate"]
        count_val     = row["count"]

        rule_override = None
        attack_type = "Normal"

        if root_shell >= 1:
            rule_override = "HIGH"
            attack_type = "U2R"
        elif failed_logins >= 5:
            rule_override = "HIGH"
            attack_type = "R2L"
        elif serror_rate >= 0.5 and count_val > 50:
            rule_override = "HIGH"
            attack_type = "DoS"
        elif serror_rate >= 0.3 or count_val > 200:
            if threat == "LOW":
                rule_override = "MEDIUM"
                attack_type = "Probe"

        final_threat = rule_override if rule_override else threat

        # Determine attack type from threat level if no rule matched
        if attack_type == "Normal" and final_threat != "LOW":
            if final_threat == "MEDIUM":
                attack_type = "Probe"
            elif final_threat == "HIGH":
                attack_type = "DoS"

        # ── Anomaly detection ──────────────────────────────────────────────
        is_anomalous = False
        anomaly_score = 0.0
        if hasattr(state, 'NEW_ISOLATION') and state.NEW_ISOLATION is not None:
            try:
                anomaly_score = float(state.NEW_ISOLATION.decision_function(scaled)[0])
                is_anomalous = state.NEW_ISOLATION.predict(scaled)[0] == -1
            except Exception:
                pass

        # ── Build response ─────────────────────────────────────────────────
        response = {
            "threat":         final_threat,
            "confidence":     round(conf * 100, 2),
            "probabilities":  probabilities,
            "attack_type":    attack_type,
            "attack_probabilities": {
                "Normal": probabilities.get("LOW", 0),
                "DoS":    probabilities.get("HIGH", 0) * 0.4,
                "Probe":  probabilities.get("MEDIUM", 0),
                "R2L":    probabilities.get("HIGH", 0) * 0.3,
                "U2R":    probabilities.get("HIGH", 0) * 0.3,
            },
            "is_anomalous":   is_anomalous,
            "anomaly_score":  round(anomaly_score, 4),
            "feature_debug": {
                "protocol_raw":       data.get("protocol_type"),
                "protocol_encoded":   proto_enc,
                "flag_raw":           data.get("flag"),
                "flag_encoded":       flag_enc,
                "root_shell_raw":     data.get("root_shell"),
                "root_shell_encoded": int(row["root_shell"]),
                "logged_in_raw":      data.get("logged_in"),
                "logged_in_encoded":  int(row["logged_in"]),
                "serror_rate":        row["serror_rate"],
                "count":              row["count"],
                "model":              "network_threat_dataset (13 features)",
            },
        }

        # Geolocation
        geo = geolocate_attack(attack_type)
        if geo:
            response["location"] = geo

        return current_app.response_class(
            json.dumps(response), mimetype="application/json")

    except Exception as e:
        import traceback
        logger.error("Predict error: %s", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# ── Debug endpoint ──────────────────────────────────────────────────────────

@bp.route("/debug", methods=["POST"])
def debug_input():
    """Echo raw input for inspection."""
    try:
        data = request.get_json(force=True)
        print("\n========== DEBUG RAW INPUT ==========")
        for k, v in (data or {}).items():
            print(f"  {k}: {repr(v)} (type: {type(v).__name__})")
        print("=====================================\n")

        # Show encoder classes if available
        if hasattr(state, 'NEW_ENCODERS') and state.NEW_ENCODERS:
            print("Available encoder classes:")
            for name, enc in state.NEW_ENCODERS.items():
                print(f"  {name}: {list(enc.classes_)}")

        return jsonify({"received": data, "count": len(data or {})})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Batch predict ───────────────────────────────────────────────────────────

@bp.route("/predict-batch", methods=["POST"])
def predict_batch():
    """Batch predict from uploaded CSV/Excel."""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file provided", "data": None}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"success": False, "error": "No file selected", "data": None}), 400

        # Read file
        fname = file.filename.lower()
        if fname.endswith(".xlsx") or fname.endswith(".xls"):
            df_batch = pd.read_excel(file)
        else:
            try:
                df_batch = pd.read_csv(file)
            except Exception:
                file.seek(0)
                df_batch = pd.read_csv(file, header=None)

        results = []
        threat_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for idx, row_data in df_batch.iterrows():
            try:
                row_dict = row_data.to_dict()
                # Simulate a POST to predict for each row
                features = {}
                for old_name, new_name in {
                    "protocol_type": "protocol_type",
                    "service_type": "service",
                    "connection_flag": "flag",
                    "duration_s": "duration",
                    "failed_logins": "num_failed_logins",
                    "src_bytes": "src_bytes",
                    "dst_bytes": "dst_bytes",
                    "logged_in": "logged_in",
                    "root_shell": "root_shell",
                    "count": "count",
                    "srv_count": "srv_count",
                    "error_rate_syn_flood": "serror_rate",
                    "dst_host_count": "dst_host_count",
                }.items():
                    features[new_name] = row_dict.get(old_name, row_dict.get(new_name, 0))

                encoders = state.NEW_ENCODERS
                row = {
                    "protocol_type":     _encode_categorical(features.get("protocol_type", "TCP"), encoders["protocol_type"], "TCP"),
                    "service":           _encode_categorical(features.get("service", "HTTP"), encoders["service"], "HTTP"),
                    "flag":              _encode_categorical(features.get("flag", "SF (Normal)"), encoders["flag"], "SF (Normal)"),
                    "duration":          _safe_float(features.get("duration", 0)),
                    "num_failed_logins": _safe_float(features.get("num_failed_logins", 0)),
                    "src_bytes":         _safe_float(features.get("src_bytes", 0)),
                    "dst_bytes":         _safe_float(features.get("dst_bytes", 0)),
                    "logged_in":         float(_safe_int(features.get("logged_in", 0))),
                    "root_shell":        float(_safe_int(features.get("root_shell", 0))),
                    "count":             _safe_float(features.get("count", 0)),
                    "srv_count":         _safe_float(features.get("srv_count", 0)),
                    "serror_rate":       _safe_float(features.get("serror_rate", 0)),
                    "dst_host_count":    _safe_float(features.get("dst_host_count", 0)),
                }

                df_row = pd.DataFrame([row])[state.NEW_FEATURES]
                scaled = state.NEW_SCALER.transform(df_row)
                pred_idx = state.NEW_MODEL.predict(scaled)[0]
                proba = state.NEW_MODEL.predict_proba(scaled)[0]
                threat = state.NEW_THREAT_LE.inverse_transform([pred_idx])[0]
                conf = round(float(max(proba)) * 100, 2)

                is_anom = False
                anom_score = 0.0
                if hasattr(state, 'NEW_ISOLATION') and state.NEW_ISOLATION:
                    anom_score = float(state.NEW_ISOLATION.decision_function(scaled)[0])
                    is_anom = state.NEW_ISOLATION.predict(scaled)[0] == -1

                results.append({
                    "index": int(idx),
                    "threat": threat,
                    "confidence": conf,
                    "attack_type": "Normal" if threat == "LOW" else ("DoS" if threat == "HIGH" else "Probe"),
                    "is_anomalous": is_anom,
                    "anomaly_score": round(anom_score, 4),
                    "probability": conf,
                })
                threat_counts[threat] = threat_counts.get(threat, 0) + 1

            except Exception as row_err:
                results.append({
                    "index": int(idx),
                    "threat": "ERROR",
                    "confidence": 0,
                    "attack_type": "Error",
                    "error": str(row_err),
                })

        return jsonify({
            "success": True,
            "data": {
                "total": len(results),
                "results": results,
                "attack_breakdown": {},
                "threat_breakdown": threat_counts,
            },
            "error": None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "data": None}), 500
