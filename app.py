"""
ShieldAudit AI - Streamlit Entry Point
This file is the pure Streamlit application. It has NO FastAPI imports
so that Streamlit's ASGI auto-discovery never triggers.
All API logic is handled via the Streamlit Custom Component bridge below.
"""
import os
import base64
import json
import hmac
import hashlib
import time
import logging
from typing import Optional

import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Import backend services (no FastAPI here)
from services.parser import parse_pdf, parse_txt, parse_csv
from services.detector import detect_sensitive_data
from services.compliance import generate_compliance_report
from services.masker import mask_document_text
from services.audit import (
    init_db, log_event, get_logs,
    create_user, authenticate_user, get_user_by_id
)

# ── JWT helpers ──────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "shieldaudit-super-secret-key-12345")
TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
os.makedirs(TEMP_DIR, exist_ok=True)


def create_token(user_id: int, username: str) -> str:
    payload = {"user_id": user_id, "username": username, "exp": time.time() + 86400 * 7}
    payload_json = json.dumps(payload)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{payload_b64}.{sig_b64}"


def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        expected_sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None
        missing_padding = len(payload_b64) % 4
        if missing_padding:
            payload_b64 += "=" * (4 - missing_padding)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        payload = json.loads(payload_json)
        if time.time() > payload["exp"]:
            return None
        return payload
    except Exception:
        return None


# ── Streamlit page setup ─────────────────────────────────────────────────────
init_db()

st.set_page_config(
    page_title="ShieldAudit AI - Sensitive Data Detection & Compliance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
    <style>
        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
        footer {visibility: hidden;}
        .block-container {
            padding-top: 0rem;
            padding-bottom: 0rem;
            padding-left: 0rem;
            padding-right: 0rem;
            max-width: 100%;
        }
        iframe {
            border: none !important;
            width: 100% !important;
            height: 100vh !important;
        }
    </style>
""", unsafe_allow_html=True)

# ── Declare the Custom Component pointing at our static/ directory ────────────
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
shieldaudit_app = components.declare_component("shieldaudit_app", path=static_dir)

# Initialise session state
if "last_response" not in st.session_state:
    st.session_state.last_response = None

# Render component; pass any pending response back into the iframe
req = shieldaudit_app(last_response=st.session_state.last_response, key="main_app")

# ── Request dispatcher ────────────────────────────────────────────────────────
if req and isinstance(req, dict) and req.get("type") == "request":
    req_id  = req["requestId"]
    url     = req["url"]
    headers = req.get("headers") or {}
    body    = req.get("body")

    def get_auth_user(hdrs):
        auth_header = hdrs.get("Authorization") or hdrs.get("authorization") or ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            p = verify_token(token)
            if p:
                return p["username"], p
        return None, None

    status   = 200
    res_body = {}

    try:
        # ── Auth ─────────────────────────────────────────────────────────────
        if url == "/api/auth/login":
            bd = json.loads(body) if isinstance(body, str) else body
            user = authenticate_user(bd["username"], bd["password"])
            if not user:
                res_body, status = {"detail": "Invalid username/email or password."}, 401
            else:
                token = create_token(user["id"], user["username"])
                res_body = {"token": token, "user": user}

        elif url == "/api/auth/register":
            bd = json.loads(body) if isinstance(body, str) else body
            user = create_user(bd["username"], bd["email"], bd["password"])
            token = create_token(user["id"], user["username"])
            res_body = {"token": token, "user": user}

        elif url == "/api/auth/me":
            username, payload = get_auth_user(headers)
            if not username:
                res_body, status = {"detail": "Authentication required."}, 401
            else:
                user = get_user_by_id(payload["user_id"])
                res_body = user if user else {"detail": "User not found."}
                status   = 200 if user else 404

        # ── Upload ───────────────────────────────────────────────────────────
        elif url == "/api/upload":
            username, payload = get_auth_user(headers)
            if not username:
                res_body, status = {"detail": "Authentication required."}, 401
            else:
                file_info = body.get("file") if isinstance(body, dict) else None
                if not file_info:
                    res_body, status = {"detail": "No file provided."}, 400
                else:
                    filename = file_info["filename"]
                    ext      = os.path.splitext(filename)[1].lower()
                    if ext not in [".pdf", ".txt", ".csv"]:
                        res_body, status = {"detail": f"Unsupported file type: {ext}"}, 400
                    else:
                        temp_path = os.path.join(TEMP_DIR, filename)
                        try:
                            with open(temp_path, "wb") as f:
                                f.write(base64.b64decode(file_info["data"]))

                            resolved_api_key = os.getenv("GROQ_API_KEY")
                            if resolved_api_key == "YOUR_GROQ_API_KEY_HERE":
                                resolved_api_key = None

                            structured_data = None
                            if ext == ".pdf":
                                text = parse_pdf(temp_path, groq_api_key=resolved_api_key)
                            elif ext == ".txt":
                                text = parse_txt(temp_path)
                            else:
                                text, structured_data = parse_csv(temp_path)

                            findings          = detect_sensitive_data(text, api_key=resolved_api_key)
                            compliance_report = generate_compliance_report(text, findings, api_key=resolved_api_key)
                            redacted_text     = mask_document_text(text, findings)

                            log_event(
                                action="DOCUMENT_UPLOAD",
                                file_name=filename, file_type=ext,
                                risk_level=compliance_report["risk_level"],
                                risk_score=compliance_report["risk_score"],
                                findings_count=len(findings),
                                details=f"File Size: {os.path.getsize(temp_path)} bytes.",
                                username=username
                            )
                            res_body = {
                                "file_name": filename, "file_type": ext,
                                "text": text, "structured_data": structured_data,
                                "findings": findings,
                                "compliance_report": compliance_report,
                                "redacted_text": redacted_text
                            }
                        finally:
                            if os.path.exists(temp_path):
                                os.remove(temp_path)

        # ── Chat ─────────────────────────────────────────────────────────────
        elif url == "/api/chat":
            username, _ = get_auth_user(headers)
            if not username:
                res_body, status = {"detail": "Authentication required."}, 401
            else:
                from services.rag import answer_document_query
                bd = json.loads(body) if isinstance(body, str) else body
                resolved_api_key = os.getenv("GROQ_API_KEY")
                if resolved_api_key == "YOUR_GROQ_API_KEY_HERE":
                    resolved_api_key = None
                answer = answer_document_query(
                    document_text=bd["document_text"],
                    query=bd["query"],
                    chat_history=bd.get("chat_history", []),
                    api_key=resolved_api_key
                )
                log_event(action="Q&A_QUERY",
                          details=f"User Query: '{bd['query'][:100]}...'",
                          username=username)
                res_body = {"answer": answer}

        # ── Redact ───────────────────────────────────────────────────────────
        elif url == "/api/redact":
            username, _ = get_auth_user(headers)
            if not username:
                res_body, status = {"detail": "Authentication required."}, 401
            else:
                bd = json.loads(body) if isinstance(body, str) else body
                masked_text = mask_document_text(bd["document_text"], bd["findings"])
                log_event(action="REDACT_DOCUMENT",
                          findings_count=len(bd["findings"]),
                          details=f"Redacted {len(bd['findings'])} items.",
                          username=username)
                res_body = {"redacted_text": masked_text}

        # ── Logs ─────────────────────────────────────────────────────────────
        elif url == "/api/logs":
            username, _ = get_auth_user(headers)
            if not username:
                res_body, status = {"detail": "Authentication required."}, 401
            else:
                logs = get_logs(limit=100, username=username)
                res_body = {"logs": logs}

        else:
            res_body, status = {"detail": f"Route {url} not found."}, 404

    except ValueError as e:
        res_body, status = {"detail": str(e)}, 400
    except Exception as e:
        logger.error(f"Bridge error [{url}]: {e}", exc_info=True)
        res_body, status = {"detail": str(e)}, 500

    st.session_state.last_response = {
        "type":      "response",
        "requestId": req_id,
        "status":    status,
        "headers":   {"Content-Type": "application/json"},
        "body":      res_body
    }
    st.rerun()
