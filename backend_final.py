"""Thin entry point — kept at top level so existing start scripts work unchanged.

The real app lives in `backend/`. This file just builds and runs it.
"""
from backend.app import create_app
from backend.config import FLASK_DEBUG, HOST, PORT
from backend.live_feed import socketio

app = create_app()


if __name__ == "__main__":
    socketio.run(app, debug=FLASK_DEBUG, port=PORT, host=HOST, allow_unsafe_werkzeug=True)
