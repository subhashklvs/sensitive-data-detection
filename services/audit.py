import os
import sqlite3
import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit.db")

def init_db():
    """Initializes the SQLite audit database and creates tables if they don't exist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create audit_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                file_name TEXT,
                file_type TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                findings_count INTEGER,
                details TEXT
            )
        """)

        # Alter audit_logs to add username column if it doesn't exist
        cursor.execute("PRAGMA table_info(audit_logs)")
        columns = [col[1] for col in cursor.fetchall()]
        if "username" not in columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN username TEXT")
            logger.info("Added username column to audit_logs table.")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Audit database initialized successfully at {DB_PATH}.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

import hashlib
import secrets

def generate_salt(length: int = 16) -> str:
    """Generates a random hex salt."""
    return secrets.token_hex(length)

def hash_password(password: str, salt: str) -> str:
    """Hashes a password with the salt using PBKDF2 SHA-256."""
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    h = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return h.hex()

def create_user(username: str, email: str, password: str) -> dict:
    """Registers a new user in the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        created_at = datetime.utcnow().isoformat() + "Z"
        
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (username.strip(), email.strip().lower(), pwd_hash, salt, created_at))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"User created successfully: {username}")
        return {
            "id": user_id,
            "username": username.strip(),
            "email": email.strip().lower(),
            "created_at": created_at
        }
    except sqlite3.IntegrityError as e:
        logger.error(f"Failed to create user {username}: Username or email already exists.")
        raise ValueError("Username or email already exists.")
    except Exception as e:
        logger.error(f"Failed to create user {username}: {e}")
        raise e

def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticates a user by username or email. Returns user dict if successful, else None."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM users WHERE username = ? OR email = ?
        """, (username.strip(), username.strip().lower()))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        user = dict(row)
        salt = user["salt"]
        stored_hash = user["password_hash"]
        
        # Verify hash
        computed_hash = hash_password(password, salt)
        if computed_hash == stored_hash:
            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        return None
    except Exception as e:
        logger.error(f"Authentication error for {username}: {e}")
        return None

def get_user_by_id(user_id: int) -> Optional[dict]:
    """Fetches user details by user ID."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Failed to fetch user by id {user_id}: {e}")
        return None



def log_event(
    action: str,
    file_name: str = None,
    file_type: str = None,
    risk_level: str = None,
    risk_score: int = None,
    findings_count: int = None,
    details: str = None,
    username: str = None
):
    """Inserts a new event log entry into the audit database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, action, file_name, file_type, risk_level, risk_score, findings_count, details, username)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, action, file_name, file_type, risk_level, risk_score, findings_count, details, username))
        
        conn.commit()
        conn.close()
        logger.info(f"Audit log recorded: {action} on {file_name or 'N/A'} for user {username or 'N/A'}")
    except Exception as e:
        logger.error(f"Failed to log event: {e}")

def get_logs(limit: int = 100, username: str = None) -> list[dict]:
    """Retrieves the latest audit logs from the database, ordered by newest first. Filters by username if provided."""
    logs = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if username:
            cursor.execute("SELECT * FROM audit_logs WHERE username = ? ORDER BY id DESC LIMIT ?", (username, limit))
        else:
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            
        rows = cursor.fetchall()
        
        for r in rows:
            logs.append(dict(r))
            
        conn.close()
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}")
        
    return logs
