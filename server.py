"""
ShieldAudit AI - FastAPI Server
Run standalone with: uvicorn server:app --host 0.0.0.0 --port 8000
This file is NOT used by Streamlit Community Cloud.
"""
import os
import shutil
import logging
import hmac
import base64
import time
import json
import hashlib
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

from services.parser import parse_pdf, parse_txt, parse_csv
from services.detector import detect_sensitive_data
from services.compliance import generate_compliance_report
from services.masker import mask_document_text
from services.audit import (
    init_db, log_event, get_logs,
    create_user, authenticate_user, get_user_by_id
)

# ── Config ───────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "shieldaudit-super-secret-key-12345")
TEMP_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
os.makedirs(TEMP_DIR, exist_ok=True)

# ── JWT helpers ──────────────────────────────────────────────────────────────
def create_token(user_id: int, username: str) -> str:
    payload = {"user_id": user_id, "username": username, "exp": time.time() + 86400 * 7}
    payload_json = json.dumps(payload)
    payload_b64  = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    sig          = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
    sig_b64      = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{payload_b64}.{sig_b64}"


def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        expected_sig     = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
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


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    token   = authorization.split(" ", 1)[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return payload

# ── Request models ────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    document_text: str
    query: str
    chat_history: Optional[List[dict]] = []
    api_key: Optional[str] = None

class RedactRequest(BaseModel):
    document_text: str
    findings: List[dict]

# ── Lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    logger.info("Application startup: Audit DB initialized.")
    yield

# ── Router ────────────────────────────────────────────────────────────────────
router = APIRouter()

@router.post("/api/auth/register")
async def register(req: UserRegister):
    try:
        user  = create_user(req.username, req.email, req.password)
        token = create_token(user["id"], user["username"])
        return {"token": token, "user": user}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to create user account.")

@router.post("/api/auth/login")
async def login(req: UserLogin):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")
    token = create_token(user["id"], user["username"])
    return {"token": token, "user": user}

@router.get("/api/auth/me")
async def get_me(authorization: Optional[str] = Header(None)):
    payload = await get_current_user(authorization)
    user    = get_user_by_id(payload["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

@router.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    payload  = await get_current_user(authorization)
    username = payload["username"]
    filename = file.filename
    ext      = os.path.splitext(filename)[1].lower()

    if ext not in [".pdf", ".txt", ".csv"]:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}.")

    temp_path = os.path.join(TEMP_DIR, filename)
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail="Internal server error saving file.")

    resolved_api_key = os.getenv("GROQ_API_KEY")
    if resolved_api_key == "YOUR_GROQ_API_KEY_HERE":
        resolved_api_key = None

    try:
        structured_data = None
        if ext == ".pdf":
            text = parse_pdf(temp_path, groq_api_key=resolved_api_key)
        elif ext == ".txt":
            text = parse_txt(temp_path)
        else:
            text, structured_data = parse_csv(temp_path)

        if not text.strip():
            raise HTTPException(status_code=422, detail="No readable text extracted.")

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
        return {
            "file_name": filename, "file_type": ext,
            "text": text, "structured_data": structured_data,
            "findings": findings, "compliance_report": compliance_report,
            "redacted_text": redacted_text
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing {filename}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temp file: {e}")

@router.post("/api/chat")
async def chat_with_document(req: ChatRequest, authorization: Optional[str] = Header(None)):
    payload  = await get_current_user(authorization)
    username = payload["username"]
    resolved_api_key = os.getenv("GROQ_API_KEY")
    if resolved_api_key == "YOUR_GROQ_API_KEY_HERE":
        resolved_api_key = None
    from services.rag import answer_document_query
    try:
        answer = answer_document_query(
            document_text=req.document_text,
            query=req.query,
            chat_history=req.chat_history,
            api_key=resolved_api_key
        )
        log_event(action="Q&A_QUERY",
                  details=f"User Query: '{req.query[:100]}...'",
                  username=username)
        return {"answer": answer}
    except Exception as e:
        logger.error(f"Error during Q&A: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/redact")
async def redact_content(req: RedactRequest, authorization: Optional[str] = Header(None)):
    payload  = await get_current_user(authorization)
    username = payload["username"]
    try:
        masked_text = mask_document_text(req.document_text, req.findings)
        log_event(action="REDACT_DOCUMENT",
                  findings_count=len(req.findings),
                  details=f"Redacted {len(req.findings)} items.",
                  username=username)
        return {"redacted_text": masked_text}
    except Exception as e:
        logger.error(f"Error during redaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/logs")
async def get_audit_logs(authorization: Optional[str] = Header(None)):
    payload  = await get_current_user(authorization)
    username = payload["username"]
    try:
        logs = get_logs(limit=100, username=username)
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "sensitive-data-detection-assistant"}

@router.get("/")
def read_index():
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Static frontend files missing."}

# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Sensitive Data Detection & Compliance Assistant",
    description="AI-powered tool to parse, detect, redact, and run compliance audits on sensitive files.",
    version="1.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)

static_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")
