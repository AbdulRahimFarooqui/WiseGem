"""
WiseGem AI — Backend API
Handles: License activation/validation, device binding, user data via Firebase
Deploy to: Railway (with PostgreSQL plugin)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pg8000.native
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
CORS(app, origins=["chrome-extension://*", "https://wisegem.ai"])

# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# Firebase Init
# Reads service account JSON from env var safely
# ─────────────────────────────────────────────
try:
    cred_json = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    if cred_json and cred_json.strip():  # Added a check to make sure it's not empty
        cred_dict = json.loads(cred_json)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        print("✅ Firebase connected via JSON environment variable")
    else:
        # If the variable doesn't exist, safely fall back without crashing
        print("ℹ️ GOOGLE_APPLICATION_CREDENTIALS_JSON not found. Initializing fallback...")
        firebase_admin.initialize_app()   
        print("✅ Firebase connected (Fallback/Local Dev mode)")
    db_firestore = firestore.client()
except Exception as e:
    print(f"⚠️ Firebase not configured or failed to initialize: {e}")
    db_firestore = None

# ─────────────────────────────────────────────
# PostgreSQL — reads DATABASE_URL set by Railway
# ─────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(
        os.environ["DATABASE_URL"],
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    conn.autocommit = False
    return conn

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key         TEXT PRIMARY KEY,
            plan        TEXT DEFAULT 'basic',
            max_devices INTEGER DEFAULT 1,
            created_at  TEXT,
            expires_at  TEXT,
            status      TEXT DEFAULT 'active',
            email       TEXT,
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id           SERIAL PRIMARY KEY,
            license_key  TEXT,
            device_id    TEXT,
            device_name  TEXT,
            activated_at TEXT,
            last_seen    TEXT,
            UNIQUE (license_key, device_id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          SERIAL PRIMARY KEY,
            license_key TEXT,
            device_id   TEXT,
            token       TEXT UNIQUE,
            created_at  TEXT,
            expires_at  TEXT,
            revoked     INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database initialized")

init_db()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def generate_session_token(license_key: str, device_id: str) -> str:
    raw = f"{license_key}:{device_id}:{secrets.token_hex(16)}"
    return hashlib.sha256(raw.encode()).hexdigest()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token:
            return jsonify({"error": "No token provided"}), 401

        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE token=%s AND revoked=0", (token,))
        session = cur.fetchone()
        cur.close(); conn.close()

        if not session:
            return jsonify({"error": "Invalid token"}), 401
        if session["expires_at"] and datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
            return jsonify({"error": "Session expired"}), 401

        request.license_key = session["license_key"]
        request.device_id   = session["device_id"]
        return f(*args, **kwargs)
    return decorated

ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-this-secret")

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# LICENSE ROUTES
# ─────────────────────────────────────────────

@app.route("/api/license/activate", methods=["POST"])
def activate_license():
    data        = request.get_json()
    license_key = (data.get("license_key") or "").strip().upper()
    device_id   = data.get("device_id", "")
    device_name = data.get("device_name", "Unknown Device")

    if not license_key or not device_id:
        return jsonify({"success": False, "error": "Missing license_key or device_id"}), 400

    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT * FROM licenses WHERE key=%s", (license_key,))
    license = cur.fetchone()

    if not license:
        cur.close(); conn.close()
        return jsonify({"success": False, "error": "Invalid license key"}), 404

    if license["status"] == "revoked":
        cur.close(); conn.close()
        return jsonify({"success": False, "error": "This license has been revoked"}), 403

    if license["expires_at"]:
        if datetime.fromisoformat(license["expires_at"]) < datetime.utcnow():
            cur.execute("UPDATE licenses SET status='expired' WHERE key=%s", (license_key,))
            conn.commit()
            cur.close(); conn.close()
            return jsonify({"success": False, "error": "License has expired"}), 403

    # Check if device already registered
    cur.execute("SELECT * FROM devices WHERE license_key=%s AND device_id=%s", (license_key, device_id))
    existing_device = cur.fetchone()

    if not existing_device:
        cur.execute("SELECT COUNT(*) as c FROM devices WHERE license_key=%s", (license_key,))
        device_count = cur.fetchone()["c"]

        if device_count >= license["max_devices"]:
            cur.execute("SELECT device_name, activated_at FROM devices WHERE license_key=%s", (license_key,))
            devices = cur.fetchall()
            cur.close(); conn.close()
            return jsonify({
                "success": False,
                "error": f"Maximum devices ({license['max_devices']}) reached for this license.",
                "registered_devices": [dict(d) for d in devices]
            }), 403

        cur.execute(
            "INSERT INTO devices (license_key, device_id, device_name, activated_at, last_seen) VALUES (%s,%s,%s,%s,%s)",
            (license_key, device_id, device_name, datetime.utcnow().isoformat(), datetime.utcnow().isoformat())
        )
    else:
        cur.execute(
            "UPDATE devices SET last_seen=%s WHERE license_key=%s AND device_id=%s",
            (datetime.utcnow().isoformat(), license_key, device_id)
        )

    token   = generate_session_token(license_key, device_id)
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    cur.execute(
        "INSERT INTO sessions (license_key, device_id, token, created_at, expires_at) VALUES (%s,%s,%s,%s,%s)",
        (license_key, device_id, token, datetime.utcnow().isoformat(), expires)
    )
    conn.commit()
    cur.close(); conn.close()

    return jsonify({
        "success": True,
        "token": token,
        "expires_at": expires,
        "plan": license["plan"],
        "max_devices": license["max_devices"]
    })


@app.route("/api/license/validate", methods=["POST"])
def validate_license():
    token = request.get_json().get("token")
    if not token:
        return jsonify({"valid": False}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT s.*, l.status, l.plan FROM sessions s "
        "JOIN licenses l ON s.license_key = l.key "
        "WHERE s.token=%s AND s.revoked=0",
        (token,)
    )
    session = cur.fetchone()

    if not session:
        cur.close(); conn.close()
        return jsonify({"valid": False, "reason": "invalid_token"})

    if session["expires_at"] and datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
        cur.close(); conn.close()
        return jsonify({"valid": False, "reason": "session_expired"})

    if session["status"] != "active":
        cur.close(); conn.close()
        return jsonify({"valid": False, "reason": "license_" + session["status"]})

    new_expiry = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    cur.execute("UPDATE sessions SET expires_at=%s WHERE token=%s", (new_expiry, token))
    cur.execute(
        "UPDATE devices SET last_seen=%s WHERE license_key=%s AND device_id=%s",
        (datetime.utcnow().isoformat(), session["license_key"], session["device_id"])
    )
    conn.commit()
    cur.close(); conn.close()

    return jsonify({"valid": True, "plan": session["plan"]})


@app.route("/api/license/deactivate", methods=["POST"])
@token_required
def deactivate_device():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM devices WHERE license_key=%s AND device_id=%s", (request.license_key, request.device_id))
    cur.execute("UPDATE sessions SET revoked=1 WHERE license_key=%s AND device_id=%s", (request.license_key, request.device_id))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"success": True, "message": "Device deactivated. You can now activate on another device."})


# ─────────────────────────────────────────────
# USER DATA ROUTES (Firebase-backed)
# ─────────────────────────────────────────────

@app.route("/api/user/link-google", methods=["POST"])
@token_required
def link_google_account():
    data         = request.get_json()
    google_uid   = data.get("google_uid")
    google_email = data.get("google_email")

    if not google_uid:
        return jsonify({"success": False, "error": "Missing google_uid"}), 400

    if db_firestore:
        db_firestore.collection("users").document(google_uid).set({
            "license_key": request.license_key,
            "email":       google_email,
            "linked_at":   firestore.SERVER_TIMESTAMP,
            "plan":        "basic"
        }, merge=True)

    return jsonify({"success": True})


@app.route("/api/user/save-session", methods=["POST"])
@token_required
def save_session_data():
    data       = request.get_json()
    google_uid = data.get("google_uid")

    if not google_uid or not db_firestore:
        return jsonify({"success": False, "error": "Missing google_uid or Firebase not configured"}), 400

    db_firestore.collection("users").document(google_uid).collection("sessions").add({
        "license_key":      request.license_key,
        "timestamp":        firestore.SERVER_TIMESTAMP,
        "child_name":       data.get("child_name", "Child"),
        "duration_seconds": data.get("duration_seconds", 0),
        "ai_interactions":  data.get("ai_interactions", []),
        "topics_explored":  data.get("topics_explored", []),
        "cognitive_score":  data.get("cognitive_score", 0),
        "words_learned":    data.get("words_learned", []),
        "questions_asked":  data.get("questions_asked", 0),
    })

    return jsonify({"success": True})


@app.route("/api/user/data/<google_uid>", methods=["GET"])
@token_required
def get_user_data(google_uid):
    if not db_firestore:
        return jsonify({"error": "Firebase not configured"}), 500

    sessions = []
    for doc in db_firestore.collection("users").document(google_uid)\
            .collection("sessions")\
            .order_by("timestamp", direction=firestore.Query.DESCENDING)\
            .limit(50).stream():
        s = doc.to_dict()
        if s.get("timestamp"):
            s["timestamp"] = s["timestamp"].isoformat()
        sessions.append(s)

    return jsonify({"success": True, "sessions": sessions})


# ─────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────

@app.route("/api/admin/create-license", methods=["POST"])
@admin_required
def create_license():
    data       = request.get_json()
    plan       = data.get("plan", "basic")
    max_devs   = {"basic": 1, "pro": 2, "family": 5}.get(plan, 1)
    email      = data.get("email", "")
    notes      = data.get("notes", "")
    days_valid = data.get("days_valid")

    # Accept an explicit key (from local manager) or generate one
    key = (data.get("license_key") or "").strip().upper()
    if not key:
        parts = [secrets.token_hex(2).upper() for _ in range(3)]
        key   = f"WISE-{parts[0]}-{parts[1]}-{parts[2]}"

    expires = None
    if days_valid:
        expires = (datetime.utcnow() + timedelta(days=int(days_valid))).isoformat()

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO licenses (key, plan, max_devices, created_at, expires_at, email, notes) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (key) DO NOTHING",
        (key, plan, max_devs, datetime.utcnow().isoformat(), expires, email, notes)
    )
    conn.commit()
    cur.close(); conn.close()

    return jsonify({"success": True, "key": key, "plan": plan, "max_devices": max_devs, "expires_at": expires})


@app.route("/api/admin/revoke-license", methods=["POST"])
@admin_required
def revoke_license():
    key  = request.get_json().get("license_key", "").upper()
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE licenses SET status='revoked' WHERE key=%s", (key,))
    cur.execute("UPDATE sessions SET revoked=1 WHERE license_key=%s", (key,))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/licenses", methods=["GET"])
@admin_required
def list_licenses():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
    licenses = cur.fetchall()
    result = []
    for lic in licenses:
        lic_dict = dict(lic)
        cur.execute("SELECT device_name, activated_at, last_seen FROM devices WHERE license_key=%s", (lic["key"],))
        lic_dict["devices"] = [dict(d) for d in cur.fetchall()]
        result.append(lic_dict)
    cur.close(); conn.close()
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port, debug=False)
