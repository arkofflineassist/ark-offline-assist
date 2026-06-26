"""
ARK Rejoin Bot — License Server
================================
Deploy this to Railway.app (or any Python host).

SETUP:
  1. pip install flask
  2. Set environment variables:
       LICENSE_SECRET   — a long random string you keep private (used to sign keys)
       ADMIN_TOKEN      — a separate secret for the /admin endpoints
  3. Run: python license_server.py

ENDPOINTS:
  POST /validate        — called by the bot to check a license key
  POST /admin/create    — create a new license key (admin only)
  POST /admin/revoke    — revoke a license key (admin only)
  GET  /admin/list      — list all keys (admin only)
"""

import os
import hmac
import hashlib
import sqlite3
import secrets
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Config (set as environment variables on Railway) ──
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "change-this-secret-before-deploying")
ADMIN_TOKEN    = os.environ.get("ADMIN_TOKEN",    "change-this-admin-token")
DB_PATH        = os.environ.get("DB_PATH", "licenses.db")

# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key         TEXT PRIMARY KEY,
                email       TEXT,
                created_at  TEXT,
                expires_at  TEXT,
                revoked     INTEGER DEFAULT 0,
                last_seen   TEXT,
                notes       TEXT
            )
        """)
        db.commit()


# ─────────────────────────────────────────────
#  KEY SIGNING
#  Keys are: <random_id>.<hmac_signature>
#  The HMAC prevents forgery — only your server
#  can produce valid signatures.
# ─────────────────────────────────────────────

def sign_key(key_id: str) -> str:
    sig = hmac.new(
        LICENSE_SECRET.encode(),
        key_id.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    return f"{key_id}.{sig}"


def verify_key_signature(full_key: str) -> tuple[bool, str]:
    """Returns (is_valid, key_id)."""
    parts = full_key.strip().split(".")
    if len(parts) != 2:
        return False, ""
    key_id, provided_sig = parts
    expected_sig = hmac.new(
        LICENSE_SECRET.encode(),
        key_id.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    if not hmac.compare_digest(expected_sig, provided_sig):
        return False, ""
    return True, key_id


# ─────────────────────────────────────────────
#  AUTH HELPER
# ─────────────────────────────────────────────

def require_admin():
    token = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Unauthorized"}), 401
    return None


# ─────────────────────────────────────────────
#  ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    """
    Body: {"key": "XXXX.YYYY"}
    Returns:
      {"status": "valid",   "expires_at": "2025-12-31", "email": "..."}
      {"status": "invalid", "reason": "..."}
      {"status": "expired", "expires_at": "..."}
      {"status": "revoked"}
    """
    data = request.get_json(silent=True) or {}
    full_key = data.get("key", "").strip()

    if not full_key:
        return jsonify({"status": "invalid", "reason": "No key provided"}), 400

    ok, key_id = verify_key_signature(full_key)
    if not ok:
        return jsonify({"status": "invalid", "reason": "Key signature invalid"}), 200

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM licenses WHERE key = ?", (full_key,)
        ).fetchone()

    if not row:
        return jsonify({"status": "invalid", "reason": "Key not found"}), 200

    if row["revoked"]:
        return jsonify({"status": "revoked"}), 200

    expires = datetime.datetime.fromisoformat(row["expires_at"])
    if datetime.datetime.utcnow() > expires:
        return jsonify({
            "status":     "expired",
            "expires_at": row["expires_at"],
        }), 200

    # Update last_seen
    with get_db() as db:
        db.execute(
            "UPDATE licenses SET last_seen = ? WHERE key = ?",
            (datetime.datetime.utcnow().isoformat(), full_key)
        )
        db.commit()

    return jsonify({
        "status":     "valid",
        "expires_at": row["expires_at"],
        "email":      row["email"],
    }), 200


@app.route("/admin/create", methods=["POST"])
def admin_create():
    """
    Headers: X-Admin-Token: <ADMIN_TOKEN>
    Body: {"email": "user@example.com", "days": 30, "notes": "optional"}
    Returns: {"key": "XXXX.YYYY", "expires_at": "..."}
    """
    err = require_admin()
    if err: return err

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    days  = int(data.get("days", 30))
    notes = data.get("notes", "")

    if not email:
        return jsonify({"error": "email required"}), 400

    key_id   = secrets.token_hex(8).upper()
    full_key = sign_key(key_id)
    expires  = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()
    created  = datetime.datetime.utcnow().isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO licenses (key, email, created_at, expires_at, notes) VALUES (?,?,?,?,?)",
            (full_key, email, created, expires, notes)
        )
        db.commit()

    return jsonify({
        "key":        full_key,
        "email":      email,
        "expires_at": expires,
        "days":       days,
    }), 201


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    """
    Headers: X-Admin-Token: <ADMIN_TOKEN>
    Body: {"key": "XXXX.YYYY"}
    """
    err = require_admin()
    if err: return err

    data     = request.get_json(silent=True) or {}
    full_key = data.get("key", "").strip()

    with get_db() as db:
        cur = db.execute(
            "UPDATE licenses SET revoked = 1 WHERE key = ?", (full_key,)
        )
        db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Key not found"}), 404

    return jsonify({"status": "revoked", "key": full_key}), 200


@app.route("/admin/extend", methods=["POST"])
def admin_extend():
    """
    Headers: X-Admin-Token: <ADMIN_TOKEN>
    Body: {"key": "XXXX.YYYY", "days": 30}
    Extends expiry by N days from today.
    """
    err = require_admin()
    if err: return err

    data     = request.get_json(silent=True) or {}
    full_key = data.get("key", "").strip()
    days     = int(data.get("days", 30))
    new_exp  = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()

    with get_db() as db:
        cur = db.execute(
            "UPDATE licenses SET expires_at = ?, revoked = 0 WHERE key = ?",
            (new_exp, full_key)
        )
        db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "Key not found"}), 404

    return jsonify({"status": "extended", "key": full_key, "new_expires_at": new_exp}), 200


@app.route("/admin/list", methods=["GET"])
def admin_list():
    """
    Headers: X-Admin-Token: <ADMIN_TOKEN>
    Returns all license records.
    """
    err = require_admin()
    if err: return err

    with get_db() as db:
        rows = db.execute(
            "SELECT key, email, created_at, expires_at, revoked, last_seen, notes "
            "FROM licenses ORDER BY created_at DESC"
        ).fetchall()

    return jsonify([dict(r) for r in rows]), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ─────────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"License server running on port {port}")
    app.run(host="0.0.0.0", port=port)
