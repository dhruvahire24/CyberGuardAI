import os
import csv
import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pydantic import BaseModel, Field
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cyberguard.auth.dependencies import get_current_user
from cyberguard.auth.router import router as auth_router
from cyberguard.core.config import get_cors_origins, settings
from cyberguard.db import dispose_database, initialize_database

# Try importing the Google GenAI SDK
try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[Error] google-genai library is not installed. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

CSV_FILE = "scan_history.csv"
client = None
logger = logging.getLogger("cyberguard")


class RequestSizeLimitMiddleware:
    def __init__(self, app, max_body_size: int = 256 * 1024):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or not scope.get("path", "").startswith("/api/")
            or scope.get("method") not in ("POST", "PUT", "PATCH")
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_size:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Request body is too large."},
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_body_size:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large."},
                )
                await response(scope, receive, send)
                return
            more_body = message.get("more_body", False)

        body_sent = False

        async def replay_body():
            nonlocal body_sent
            if body_sent:
                return {"type": "http.disconnect"}
            body_sent = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)


class SecurityHeadersMiddleware:
    def __init__(self, app, enable_hsts: bool = False):
        self.app = app
        self.headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"strict-origin-when-cross-origin"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
            (
                b"content-security-policy",
                b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            ),
        ]
        if enable_hsts:
            self.headers.append(
                (b"strict-transport-security", b"max-age=31536000")
            )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_with_headers(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                existing_headers = {key.lower() for key, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    (key, value) for key, value in self.headers if key not in existing_headers
                ]
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            if response_started:
                raise
            logger.error("Unhandled application error")
            response = JSONResponse(
                status_code=500,
                content={"detail": "An internal server error occurred."},
            )
            await response(scope, receive, send_with_headers)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        initialize_database()
        yield
    finally:
        dispose_database()


# Initialize FastAPI App
app = FastAPI(title="CyberGuard AI API", version="1.0.0", lifespan=lifespan)

app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(
    SecurityHeadersMiddleware,
    enable_hsts=settings.is_production,
)
app.include_router(auth_router)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(_request: Request, _exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid request input."})

# --- Pydantic Data Schemas for API Requests/Outputs ---

class SafetyAnalysis(BaseModel):
    risk_score: int = Field(description="Risk score between 1 and 10, where 1 is completely safe and 10 is a severe threat.")
    verdict: str = Field(description="Verdict label: 'Safe', 'Suspicious', or 'Malicious'.")
    reasoning: str = Field(description="Detailed analysis explaining the risk score and verdict.")
    recommendations: list[str] = Field(description="List of actionable recommendations.")

class PhishingAnalysis(BaseModel):
    risk_score: int = Field(description="Risk score between 1 and 10, where 1 is safe and 10 is phishing.")
    verdict: str = Field(description="Verdict label: 'Safe', 'Suspicious', or 'Phishing'.")
    phishing_indicators: list[str] = Field(description="List of phishing indicators found in the email.")
    reasoning: str = Field(description="Detailed explanation of findings.")
    recommendations: list[str] = Field(description="Recommendations for the user.")

class CybersecurityTip(BaseModel):
    topic: str = Field(description="Security topic.")
    headline: str = Field(description="Key headline.")
    explanation: str = Field(description="Why this matters.")
    action_items: list[str] = Field(description="Steps to take.")

class URLScanRequest(BaseModel):
    url: str = Field(max_length=2048)

class EmailScanRequest(BaseModel):
    content: str = Field(max_length=50000)

class TipRequest(BaseModel):
    topic: str = Field(max_length=500)


# --- Client Lazy Loading Utility ---

def get_gemini_client() -> genai.Client:
    global client
    if client is not None:
        return client
        
    api_key = settings.get_gemini_api_key()
    
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="GEMINI_API_KEY is not configured."
        )
        
    try:
        client = genai.Client(api_key=api_key)
        return client
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to initialize the AI service."
        ) from None


# --- CSV Logging Function ---

def log_to_csv(scan_type: str, target: str, risk_score: str, verdict: str, analysis: str):
    file_exists = os.path.exists(CSV_FILE)
    clean_target = target.replace("\n", " ").strip()
    if len(clean_target) > 100:
        clean_target = clean_target[:97] + "..."
        
    clean_analysis = analysis.replace("\n", " ").strip()
    if len(clean_analysis) > 200:
        clean_analysis = clean_analysis[:197] + "..."

    try:
        with open(CSV_FILE, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Scan Type", "Input/Target", "Risk Score", "Verdict", "Summary Analysis"])
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                scan_type,
                clean_target,
                risk_score,
                verdict,
                clean_analysis
            ])
    except Exception:
        logger.warning("Failed to write scan history.")


# --- API Endpoint Routing ---

@app.post(
    "/api/scan/url",
    response_model=SafetyAnalysis,
    dependencies=[Depends(get_current_user)],
)
def api_scan_url(req: URLScanRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
        
    gemini_client = get_gemini_client()
    
    prompt = f"""
    Analyze the following URL for cybersecurity risks, potential phishing signs, malware distribution, suspicious domains, and general threat indicators:
    URL: {url}
    
    Analyze the URL string itself, common phishing patterns, typical typosquatting tricks, known top-level domains associated with malicious activity, and domain structuring.
    Provide a risk score from 1 (completely safe) to 10 (high threat/malicious), a verdict, detailed reasoning, and recommendations.
    """
    
    try:
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=SafetyAnalysis,
            ),
        )
        analysis = SafetyAnalysis.model_validate_json(response.text)
        log_to_csv("URL", url, str(analysis.risk_score), analysis.verdict, analysis.reasoning)
        return analysis
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gemini API scan failed. Please try again.",
        ) from None


@app.post(
    "/api/scan/email",
    response_model=PhishingAnalysis,
    dependencies=[Depends(get_current_user)],
)
def api_scan_email(req: EmailScanRequest):
    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")
        
    gemini_client = get_gemini_client()
    
    prompt = f"""
    Analyze the following email content (subject and/or body) for phishing indicators, social engineering attempts, credential harvesting, malicious links, urgent call-to-actions, or suspicious sender behavior flags:
    
    Email Content:
    \"\"\"
    {content}
    \"\"\"
    
    Identify specific phishing indicators, give a risk score from 1 (safe) to 10 (obvious phishing/highly malicious), a verdict, detailed reasoning, and recommendations.
    """
    
    try:
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=PhishingAnalysis,
            ),
        )
        analysis = PhishingAnalysis.model_validate_json(response.text)
        log_to_csv("Email", content, str(analysis.risk_score), analysis.verdict, analysis.reasoning)
        return analysis
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gemini API scan failed. Please try again.",
        ) from None


@app.post(
    "/api/scan/tip",
    response_model=CybersecurityTip,
    dependencies=[Depends(get_current_user)],
)
def api_scan_tip(req: TipRequest):
    topic = req.topic.strip()
    gemini_client = get_gemini_client()
    
    prompt = f"""
    Generate actionable, high-quality cybersecurity tips and recommendations.
    Topic request: {topic if topic else 'General cybersecurity best practices'}
    
    Return a structured tip containing the topic, a headline, a detailed explanation of why it matters, and a list of actionable items the user can take immediately to secure themselves.
    """
    
    try:
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=CybersecurityTip,
            ),
        )
        tip = CybersecurityTip.model_validate_json(response.text)
        log_to_csv("Tips", tip.topic, "N/A", "N/A", tip.headline + ": " + tip.explanation)
        return tip
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gemini API tips failed. Please try again.",
        ) from None


@app.get("/api/history", dependencies=[Depends(get_current_user)])
def api_get_history():
    if not os.path.exists(CSV_FILE):
        return []
        
    logs = []
    try:
        with open(CSV_FILE, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return []
            for row in reader:
                if len(row) < 6:
                    continue
                logs.append({
                    "timestamp": row[0],
                    "scan_type": row[1],
                    "input": row[2],
                    "risk_score": row[3],
                    "verdict": row[4],
                    "analysis": row[5]
                })
        # Return newest scans first
        return logs[::-1]
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to read scan history.",
        ) from None


@app.get("/api/stats", dependencies=[Depends(get_current_user)])
def api_get_stats():
    if not os.path.exists(CSV_FILE):
        return {
            "total_scans": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "threat_count": 0,
            "average_risk": 0.0
        }
        
    total = 0
    safe = 0
    suspicious = 0
    threats = 0
    risk_scores = []
    
    try:
        with open(CSV_FILE, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None) # skip header
            for row in reader:
                if len(row) < 6:
                    continue
                total += 1
                verdict = row[4]
                risk = row[3]
                
                if verdict in ("Safe", "Safe Email"):
                    safe += 1
                elif verdict == "Suspicious":
                    suspicious += 1
                elif verdict in ("Malicious", "Phishing"):
                    threats += 1
                    
                if risk != "N/A":
                    try:
                        risk_scores.append(int(risk))
                    except ValueError:
                        pass
                        
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0
        return {
            "total_scans": total,
            "safe_count": safe,
            "suspicious_count": suspicious,
            "threat_count": threats,
            "average_risk": avg_risk
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to calculate scan statistics.",
        ) from None


# --- Static Directory Setup & Server Catch-All ---

# Ensure static directory exists
os.makedirs("static", exist_ok=True)

# Mount Static assets directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Catch-all page route to serve index.html at root
@app.get("/")
def get_index():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "CyberGuard AI Server Running. index.html is missing in static/."}


# --- Optional CLI starter entrypoint ---

if __name__ == "__main__":
    import uvicorn
    # Automatically reload server for developer ease
    uvicorn.run("CyberGuardAI:app", host="127.0.0.1", port=8000, reload=True)
