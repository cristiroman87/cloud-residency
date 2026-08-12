from __future__ import annotations

import getpass
import grp
import json
import os
import pwd
import stat
from functools import wraps

import boto3
import psycopg
from psycopg.rows import dict_row

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-change-me-now",
)
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get(
    "SESSION_COOKIE_SAMESITE",
    "Lax",
)
app.config["SESSION_COOKIE_HTTPONLY"] = True

CORS(
    app,
    supports_credentials=True,
    origins=[r"http://.*:5000"],
)


# ============================================================
# PostgreSQL / RDS configuration
# ============================================================

DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "cloudresidency")
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]


# ============================================================
# PostgreSQL database connection
#
# Uses the EC2 instance role to retrieve the RDS-managed
# database credentials from AWS Secrets Manager.
# ============================================================

def get_db():
    client = boto3.client(
    "secretsmanager",
    region_name="eu-north-1",
)

    response = client.get_secret_value(
        SecretId=DB_SECRET_ARN
    )

    secret = json.loads(response["SecretString"])

    conn = psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=secret["username"],
        password=secret["password"],
        row_factory=dict_row,
    )

    return conn


# ============================================================
# Initialize application database
#
# Creates the users table if it does not already exist and
# ensures the initial admin account exists.
# ============================================================

def init_db() -> None:
    conn = get_db()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """
    )

    admin_username = os.environ.get(
        "APP3_ADMIN_USER",
        "admin",
    )
    admin_password = os.environ.get(
        "APP3_ADMIN_PASSWORD",
        "adminpass1",
    )

    existing_admin = conn.execute(
        "SELECT id FROM users WHERE username = %s",
        (admin_username,),
    ).fetchone()

    if not existing_admin:
        conn.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role
            )
            VALUES (%s, %s, %s)
            """,
            (
                admin_username,
                generate_password_hash(admin_password),
                "admin",
            ),
        )

    conn.commit()
    conn.close()


# ============================================================
# Authentication helpers
# ============================================================

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "login_required"}), 401

        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "login_required"}), 401

        if session.get("role") != "admin":
            return jsonify({"error": "admin_required"}), 403

        return fn(*args, **kwargs)

    return wrapper


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db()

    user = conn.execute(
        "SELECT id, username, role FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()

    conn.close()

    return user


# ============================================================
# Existing container / Linux identity demonstration
# ============================================================

def perm_string(path: str) -> str:
    mode = os.stat(path).st_mode
    return stat.filemode(mode)


@app.get("/api/users")
def users():
    username = getpass.getuser()

    try:
        pw = pwd.getpwnam(username)

        passwd_entry = {
            "pw_name": pw.pw_name,
            "pw_passwd": pw.pw_passwd,
            "pw_uid": pw.pw_uid,
            "pw_gid": pw.pw_gid,
            "pw_gecos": pw.pw_gecos,
            "pw_dir": pw.pw_dir,
            "pw_shell": pw.pw_shell,
        }

    except KeyError:
        passwd_entry = {
            "error": f"Could not find passwd entry for {username}"
        }

    return jsonify(
        {
            "current_user": username,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "passwd_entry": passwd_entry,
        }
    )


@app.get("/api/groups")
def groups():
    username = getpass.getuser()
    user_info = pwd.getpwnam(username)

    primary_group = grp.getgrgid(
        user_info.pw_gid
    ).gr_name

    all_groups = []

    for g in grp.getgrall():
        if username in g.gr_mem or g.gr_gid == user_info.pw_gid:
            all_groups.append(g.gr_name)

    return jsonify(
        {
            "current_user": username,
            "primary_group": primary_group,
            "all_groups": sorted(set(all_groups)),
        }
    )


@app.get("/api/permissions")
def permissions():
    files = [
        "app.py",
        "app2.py",
        "app3.py",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
    ]

    results = []

    for name in files:
        if os.path.exists(name):
            st = os.stat(name)

            results.append(
                {
                    "name": name,
                    "owner": pwd.getpwuid(st.st_uid).pw_name,
                    "group": grp.getgrgid(st.st_gid).gr_name,
                    "permissions": perm_string(name),
                }
            )

        else:
            results.append(
                {
                    "name": name,
                    "error": "not found",
                }
            )

    return jsonify({"files": results})


@app.get("/api/env")
def env():
    keys = [
        "USER",
        "HOME",
        "PATH",
        "SHELL",
        "VIRTUAL_ENV",
        "APP2_URL",
        "APP3_URL",
    ]

    return jsonify(
        {
            key: os.environ.get(key, "")
            for key in keys
        }
    )


# ============================================================
# Authentication API
# ============================================================

@app.post("/api/signup")
def signup():
    data = request.get_json(force=True)

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if len(username) < 3:
        return jsonify(
            {"error": "username_too_short"}
        ), 400

    if len(password) < 8:
        return jsonify(
            {"error": "password_too_short"}
        ), 400

    password_hash = generate_password_hash(password)

    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role
            )
            VALUES (%s, %s, %s)
            """,
            (
                username,
                password_hash,
                "user",
            ),
        )

        conn.commit()

    except psycopg.IntegrityError:
        conn.rollback()
        conn.close()

        return jsonify(
            {"error": "username_taken"}
        ), 409

    conn.close()

    return jsonify(
        {
            "ok": True,
            "message": "account_created",
        }
    ), 201


@app.post("/api/login")
def login():
    data = request.get_json(force=True)

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()

    user = conn.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            role
        FROM users
        WHERE username = %s
        """,
        (username,),
    ).fetchone()

    conn.close()

    if not user or not check_password_hash(
        user["password_hash"],
        password,
    ):
        return jsonify(
            {"error": "invalid_credentials"}
        ), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return jsonify(
        {
            "ok": True,
            "message": "logged_in",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }
    )


@app.post("/api/logout")
def logout():
    session.clear()

    return jsonify(
        {
            "ok": True,
            "message": "logged_out",
        }
    )


@app.get("/api/me")
@login_required
def me():
    user = current_user()

    if not user:
        session.clear()

        return jsonify(
            {"error": "not_authenticated"}
        ), 401

    return jsonify(
        {
            "ok": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }
    )


@app.get("/api/admin")
@admin_required
def admin_area():
    user = current_user()

    return jsonify(
        {
            "ok": True,
            "message": "welcome_admin",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }
    )


@app.get("/api/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "app3",
        }
    )

############################################################
# Readiness check
#
# /api/health answers:
# "Is the App3 Flask process alive?"
#
# /api/ready answers:
# "Can App3 actually connect to and query PostgreSQL?"
#
# SELECT 1 is deliberately tiny. We don't care about
# application data here; we only want to prove that the
# database dependency is usable.
############################################################

@app.get("/api/ready")
def ready():
    try:
        conn = get_db()

        conn.execute(
            "SELECT 1"
        ).fetchone()

        conn.close()

        return jsonify(
            {
                "ok": True,
                "service": "app3",
                "database": "ready",
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "service": "app3",
                "database": "unavailable",
                "error": str(exc),
            }
        ), 503 	

# ============================================================
# Application entry point
# ============================================================

if __name__ == "__main__":
    init_db()
    app.run(
        host="0.0.0.0",
        port=5002,
        debug=False,
    )