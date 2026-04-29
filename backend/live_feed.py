import time
import random
import pandas as pd
from flask_socketio import SocketIO
from backend import state
from backend.constants import FEATURES

socketio = SocketIO(cors_allowed_origins="*")

feed_active = False

def background_thread():
    """Background task that runs the live threat feed."""
    global feed_active
    while True:
        time.sleep(3)
        if feed_active and state.SAMPLE_CONNECTIONS and len(state.SAMPLE_CONNECTIONS) > 0:
            # Pick a random sample connection
            sample = random.choice(state.SAMPLE_CONNECTIONS)
            
            # Predict
            try:
                row = {f: sample.get(f, 0) for f in FEATURES}
                df_single = pd.DataFrame([row])
                
                scaled = state.threat_scaler.transform(df_single)
                pred = state.threat_model.predict(scaled)[0]
                proba = state.threat_model.predict_proba(scaled)[0].tolist()
                threat = state.threat_le.inverse_transform([pred])[0]
                conf = float(max(proba))
                
                atk_type = "Unknown"
                if state.ATTACK_MODEL and state.ATTACK_SCALER and state.ATTACK_LE:
                    atk_scaled = state.ATTACK_SCALER.transform(df_single)
                    atk_pred = state.ATTACK_MODEL.predict(atk_scaled)[0]
                    atk_type = state.ATTACK_LE.inverse_transform([atk_pred])[0]
                
                payload = {
                    "threat": threat,
                    "confidence": round(conf * 100, 2),
                    "attack_type": atk_type
                }
                socketio.emit('live_threat', payload)
            except Exception as e:
                print(f"Error in live feed: {e}")

@socketio.on('connect')
def test_connect():
    pass

@socketio.on('start_feed')
def handle_start_feed():
    global feed_active
    feed_active = True

@socketio.on('stop_feed')
def handle_stop_feed():
    global feed_active
    feed_active = False
