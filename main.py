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
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Import services
from services.parser import parse_pdf, parse_txt, parse_csv
from services.detector import detect_sensitive_data
from services.compliance import generate_compliance_report
from services.masker import mask_document_text
from services.audit import (
    init_db, log_event, get_logs,
    create_user, authenticate_user, get_user_by_id
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Application startup: Audit DB initialized.")
    yield

app = FastAPI(
    title="Sensitive Data Detection & Compliance Assistant",
    description="AI-powered tool to parse, detect, redact, and run compliance audits on sensitive files.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure temp directory exists
TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
os.makedirs(TEMP_DIR, exist_ok=True)

# Database initialization is handled by lifespan event

# JWT Token Helpers
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "shieldaudit-super-secret-key-12345")

def create_token(user_id: int, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": time.time() + 86400 * 7 # 7 days
    }
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
        
        # Verify signature
        expected_sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
        
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None
            
        # Decode payload
        missing_padding = len(payload_b64) % 4
        if missing_padding:
            payload_b64 += '=' * (4 - missing_padding)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        payload = json.loads(payload_json)
        
        if time.time() > payload["exp"]:
            return None
            
        return payload
    except Exception:
        return None

async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required. Please log in.")
    token = authorization.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    return payload

# Request Models
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

# Authentication Endpoints

@app.post("/api/auth/register")
async def register(req: UserRegister):
    try:
        user = create_user(req.username, req.email, req.password)
        token = create_token(user["id"], user["username"])
        return {"token": token, "user": user}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to create user account.")

@app.post("/api/auth/login")
async def login(req: UserLogin):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")
    token = create_token(user["id"], user["username"])
    return {"token": token, "user": user}

@app.get("/api/auth/me")
async def get_me(authorization: Optional[str] = Header(None)):
    payload = await get_current_user(authorization)
    user = get_user_by_id(payload["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

# Core API Endpoints

@app.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    """
    Handles PDF, TXT, or CSV upload. Extracts text, runs hybrid sensitive data detection,
    performs compliance risk assessment, generates a redacted text version, and logs the event.
    """
    payload = await get_current_user(authorization)
    username = payload["username"]
    
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in [".pdf", ".txt", ".csv"]:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}. Only PDF, TXT, and CSV are allowed.")

    # Save to temp location
    temp_path = os.path.join(TEMP_DIR, filename)
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail="Internal server error saving file.")

    # Always use the backend GROQ_API_KEY
    resolved_api_key = os.getenv("GROQ_API_KEY")
    if resolved_api_key == "YOUR_GROQ_API_KEY_HERE":
        resolved_api_key = None

    try:
        # 1. Parse content based on type
        structured_data = None
        if ext == ".pdf":
            text = parse_pdf(temp_path, groq_api_key=resolved_api_key)
        elif ext == ".txt":
            text = parse_txt(temp_path)
        elif ext == ".csv":
            text, structured_data = parse_csv(temp_path)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format.")

        if not text.strip():
            raise HTTPException(status_code=422, detail="No readable text could be extracted from the document.")

        # 2. Run hybrid sensitive data detection
        findings = detect_sensitive_data(text, api_key=resolved_api_key)
        
        # 3. Generate compliance assessment and risk classification
        compliance_report = generate_compliance_report(text, findings, api_key=resolved_api_key)
        
        # 4. Generate redacted text
        redacted_text = mask_document_text(text, findings)

        # 5. Log the upload event to SQLite
        log_event(
            action="DOCUMENT_UPLOAD",
            file_name=filename,
            file_type=ext,
            risk_level=compliance_report["risk_level"],
            risk_score=compliance_report["risk_score"],
            findings_count=len(findings),
            details=f"File Size: {os.path.getsize(temp_path)} bytes. Characters extracted: {len(text)}.",
            username=username
        )

        return {
            "file_name": filename,
            "file_type": ext,
            "text": text,
            "structured_data": structured_data,
            "findings": findings,
            "compliance_report": compliance_report,
            "redacted_text": redacted_text
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error processing file {filename}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing document: {str(e)}")
    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temp file {temp_path}: {e}")

@app.post("/api/chat")
async def chat_with_document(req: ChatRequest, authorization: Optional[str] = Header(None)):
    """
    Asks a question about the document text. Utilizes Groq API with document context.
    """
    payload = await get_current_user(authorization)
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
        
        # Log chat query in audit
        log_event(
            action="Q&A_QUERY",
            details=f"User Query: '{req.query[:100]}...'",
            username=username
        )
        
        return {"answer": answer}
    except Exception as e:
        logger.error(f"Error during Q&A: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/redact")
async def redact_content(req: RedactRequest, authorization: Optional[str] = Header(None)):
    """
    Direct endpoint to redact document text based on a custom/provided list of findings.
    """
    payload = await get_current_user(authorization)
    username = payload["username"]

    try:
        masked_text = mask_document_text(req.document_text, req.findings)
        
        # Log redaction event
        log_event(
            action="REDACT_DOCUMENT",
            findings_count=len(req.findings),
            details=f"Redacted {len(req.findings)} items from text.",
            username=username
        )
        
        return {"redacted_text": masked_text}
    except Exception as e:
        logger.error(f"Error during redaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_audit_logs(authorization: Optional[str] = Header(None)):
    """
    Fetches the security audit logs from SQLite database.
    """
    payload = await get_current_user(authorization)
    username = payload["username"]
    try:
        logs = get_logs(limit=100, username=username)
        return {"logs": logs}
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
def health_check():
    """
    Health check status endpoint.
    """
    return {"status": "healthy", "service": "sensitive-data-detection-assistant"}

# Serve SPA Frontend
@app.get("/")
def read_index():
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Welcome. The static frontend files are missing under /static folder."}

# Mount static directory to serve CSS, JS, etc.
static_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")
