import io
import os
import re
import sys
import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types
from pypdf import PdfReader

# Explicitly load local .env if present
load_dotenv()

import uuid
from fastapi.staticfiles import StaticFiles

# Determine project base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Ensure uploads directory exists
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads", "evidence")
os.makedirs(UPLOADS_DIR, exist_ok=True)

from ml_pipeline.url_features import extract_url_features
from ml_pipeline.domain_analysis import (
    evaluate_url_security,
    normalize_url,
    extract_domain_info,
    detect_brand_impersonation,
    BRAND_CATALOG
)

app = FastAPI(
    title="NetArmor AI API",
    description="Multi-Vector Phishing & Cyber Threat Detection System"
)

# Enable CORS for Chrome Extension and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static uploads directory
app.mount("/uploads", StaticFiles(directory=os.path.join(BASE_DIR, "uploads")), name="uploads")

# Knowledge base for NetArmor AI Assistant
NETARMOR_KNOWLEDGE = """
You are 'ArmorBot', the virtual cybersecurity AI assistant for the NetArmor AI platform.
NetArmor AI is an automated phishing website and cyber threat detection system built as a BCA Minor Project.

Key Technical Modules:
1. Website URL Scanner: Inspects lexical and structural vectors including '@' symbols, raw IP hosts, deep subdomain levels, suspicious keywords, and protocol security (HTTPS).
2. Email Content NLP Scanner: Uses TF-IDF Vectorization and an XGBoost Classifier trained to flag manipulative phrasing, scam urgency, and credential harvesting.
3. Message / Smishing Scanner: Inspects SMS and social media text for mobile phishing triggers and embedded redirect links.
4. Document Threat Scanner: Analyzes uploaded PDFs for malicious embedded JavaScript triggers and phishing URLs.
5. Google Chrome Extension (Manifest V3): Provides real-time page URL evaluation and email threat inspection in the browser.
6. Project Team: Manish Pradhan (Lead, Backend & Integration), Sriyasri Rajguru (ML & NLP Pipeline), Suvam Nahak (Frontend & Chrome Extension).

Your Role:
- Answer user questions politely, clearly, and concisely.
- Explain how the detection heuristics work.
- Provide actionable cybersecurity advice on recognizing social engineering and zero-day scams.
"""

# Absolute paths to trained model artifacts
VECTORIZER_PATH = os.path.join(BASE_DIR, "ml_pipeline", "saved_models", "tfidf_vectorizer.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "ml_pipeline", "saved_models", "email_model.pkl")
URL_MODEL_PATH = os.path.join(BASE_DIR, "ml_pipeline", "saved_models", "url_model.pkl")

# Cached model references to eliminate reload latency
_email_model = None
_vectorizer = None
_url_model = None

def get_url_model():
    global _url_model
    if _url_model is None and os.path.exists(URL_MODEL_PATH):
        try:
            _url_model = joblib.load(URL_MODEL_PATH)
        except Exception as e:
            print(f"Warning: Failed to load URL model from {URL_MODEL_PATH}: {e}")
    return _url_model

def get_email_model_and_vectorizer():
    global _email_model, _vectorizer
    if _vectorizer is None and os.path.exists(VECTORIZER_PATH):
        try:
            _vectorizer = joblib.load(VECTORIZER_PATH)
        except Exception as e:
            print(f"Warning: Failed to load TF-IDF vectorizer from {VECTORIZER_PATH}: {e}")
    if _email_model is None and os.path.exists(MODEL_PATH):
        try:
            _email_model = joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"Warning: Failed to load Email model from {MODEL_PATH}: {e}")
    return _vectorizer, _email_model

# Request Schemas
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str

class MessageRequest(BaseModel):
    message: str

class ChatRequest(BaseModel):
    message: str

@app.get("/")
@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "system": "NetArmor AI Backend",
        "project": "Automated Phishing Website & Email Detection System",
        "version": "2.4"
    }

# -------------------------------------------------------------
# Domain Whitelist & Security Heuristics
# -------------------------------------------------------------
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
    "yahoo.com", "reddit.com", "amazon.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "netflix.com", "github.com",
    "stackoverflow.com", "cloudflare.com", "bing.com", "office.com", "live.com",
    "gmail.com", "outlook.com", "dropbox.com", "whatsapp.com", "telegram.org"
}

def extract_root_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.netloc or "").split(":")[0].lower()
    if "@" in host:
        host = host.split("@")[-1]
    return host

def is_trusted_legitimate_domain(url: str) -> bool:
    """
    Public Suffix List-aware verification for authoritative domains.
    Guarantees that a brand appearing in a subdomain (e.g. google.com.example.com)
    is NOT recognized as legitimate Google domain.
    """
    if not url or "@" in url:
        return False
    try:
        norm = normalize_url(url)
        if norm["has_at_symbol"]:
            return False
        info = extract_domain_info(norm)
        if info["is_ip"]:
            return False
        reg_dom = info["registered_domain"].lower()
        if not reg_dom:
            return False
        if reg_dom in TRUSTED_DOMAINS:
            return True
        for b_data in BRAND_CATALOG.values():
            if reg_dom in b_data["official_registered_domains"]:
                return True
        return False
    except Exception:
        return False

def heuristic_email_score(text: str) -> tuple[float, list[str]]:
    text_lower = text.lower()
    score = 5.0
    flags = []
    
    urgency_triggers = ["immediate action", "account suspended", "urgent", "24 hours", "unauthorized access", "terminate your account"]
    credential_triggers = ["verify your password", "confirm your identity", "click the link below", "login immediately", "update payment"]
    financial_triggers = ["lottery winner", "cryptocurrency prize", "wire transfer", "claim your refund", "won a gift card"]
    
    matched_urgency = [t for t in urgency_triggers if t in text_lower]
    matched_cred = [t for t in credential_triggers if t in text_lower]
    matched_fin = [t for t in financial_triggers if t in text_lower]
    
    if matched_urgency:
        score += 35
        flags.append(f"Urgency pressure tactics detected ({', '.join(matched_urgency[:2])}).")
    if matched_cred:
        score += 45
        flags.append("Credential or identity harvesting phrases detected.")
    if matched_fin:
        score += 30
        flags.append("Financial scam / fraudulent reward triggers detected.")
        
    return min(score, 98.0), flags

# -------------------------------------------------------------
# 1. URL Structural & Lexical Scanner Endpoint (Using url_model.pkl + PSL Brand Engine)
# -------------------------------------------------------------
@app.post("/api/predict-url")
def predict_url(payload: URLRequest):
    """
    URL Machine Learning (XGBoost) + PSL Domain Analysis + Brand Impersonation Scanner.
    Synthesizes model probability with explainable structural indicators and brand intelligence.
    """
    if not payload.url or payload.url.strip() == "":
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    clean_url = payload.url.strip()

    # 1. Extract feature vector for ML model
    features = extract_url_features(clean_url)
    raw = features[0] if (isinstance(features, list) and isinstance(features[0], list)) else features

    # 2. Model Inference
    url_model = get_url_model()
    model_prob = None
    if url_model is not None:
        try:
            prob = url_model.predict_proba([raw])[0][1] * 100
            model_prob = round(float(prob), 2)
        except Exception as e:
            print(f"Inference error with URL model: {e}")
            model_prob = None

    # 3. Comprehensive Domain, Brand Impersonation & Structural Assessment
    try:
        result = evaluate_url_security(clean_url, ml_model_probability=model_prob)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        print(f"URL analysis error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid URL structure: {e}")

    return result

# -------------------------------------------------------------
# 2. Email NLP Semantic Scanner Endpoint
# -------------------------------------------------------------
@app.post("/api/predict-email")
def predict_email(payload: EmailRequest):
    """Email NLP TF-IDF + XGBoost prediction endpoint with resilient heuristic fallback."""
    if not payload.text or payload.text.strip() == "":
        raise HTTPException(status_code=400, detail="Email body text cannot be empty.")

    spam_prob = None
    vectorizer, email_model = get_email_model_and_vectorizer()
    if vectorizer is not None and email_model is not None:
        try:
            transformed_vector = vectorizer.transform([payload.text])
            probabilities = email_model.predict_proba(transformed_vector)[0]
            spam_prob = round(float(probabilities[1]) * 100, 2)
        except Exception as e:
            print(f"Warning: Model inference failed for email, using heuristic fallback: {e}")
            spam_prob = None

    if spam_prob is None:
        heuristic_score, _ = heuristic_email_score(payload.text)
        spam_prob = round(heuristic_score, 2)

    verdict = "Phishing / Spam" if spam_prob >= 50.0 else "Safe / Legitimate"

    return {
        "risk_percentage": spam_prob,
        "verdict": verdict
    }

# -------------------------------------------------------------
# 3. SMS & Social Media Message Scanner Endpoint
# -------------------------------------------------------------
@app.post("/api/predict-message")
def predict_message(payload: MessageRequest):
    """Inspects SMS and social media text for smishing triggers and embedded links."""
    text = payload.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")

    url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*)"
    extracted_urls = re.findall(url_pattern, text)

    nlp_prob = 10.0
    vectorizer, email_model = get_email_model_and_vectorizer()
    if vectorizer is not None and email_model is not None:
        try:
            transformed = vectorizer.transform([text])
            nlp_prob = float(email_model.predict_proba(transformed)[0][1] * 100)
        except Exception as e:
            print(f"Warning: Model inference failed for message: {e}")
            nlp_prob = 10.0

    flags = []
    smishing_patterns = [r"\botp\b", r"\bkyc\b", r"\bblocked\b", r"\bwin\b", r"\bprize\b", r"\brefund\b", r"\burgent\b", r"\bverify\b"]
    matched_patterns = [p.replace(r"\b", "") for p in smishing_patterns if re.search(p, text, re.IGNORECASE)]
    
    if matched_patterns:
        flags.append(f"Smishing trigger keywords detected: {', '.join(matched_patterns)}")
    if extracted_urls:
        flags.append(f"Detected {len(extracted_urls)} embedded short/redirect link(s).")
    if nlp_prob >= 50.0:
        flags.append(f"NLP model identified social engineering phrasing ({nlp_prob:.1f}% confidence).")

    calculated_score = nlp_prob
    if matched_patterns and extracted_urls:
        calculated_score = max(nlp_prob, 78.0)
    elif matched_patterns:
        calculated_score = max(nlp_prob, 55.0)

    final_score = round(min(calculated_score, 99.0), 2)
    verdict = "Phishing / Smishing Threat" if final_score >= 50.0 else "Clean / Low Risk"

    return {
        "risk_percentage": final_score,
        "verdict": verdict,
        "extracted_urls": extracted_urls,
        "flags": flags if flags else ["No suspicious smishing vectors detected."]
    }

# -------------------------------------------------------------
# 4. PDF Document Threat Scanner Endpoint
# -------------------------------------------------------------
@app.post("/api/scan-document")
async def scan_document(file: UploadFile = File(...)):
    """Extracts text and inspects embedded links and active scripts inside uploaded PDFs."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF documents are supported.")

    content = await file.read()
    if not content.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="Invalid PDF file format (missing PDF magic header).")

    try:
        reader = PdfReader(io.BytesIO(content))
        extracted_text = ""
        extracted_urls = []
        has_javascript = False

        for page in reader.pages:
            text = page.extract_text() or ""
            extracted_text += text + " "

            if "/Annots" in page:
                try:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        if "/A" in obj and "/URI" in obj["/A"]:
                            extracted_urls.append(obj["/A"]["/URI"])
                except Exception:
                    pass

        try:
            if "/JavaScript" in reader.trailer or "/JS" in reader.trailer:
                has_javascript = True
        except Exception:
            pass
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to parse PDF document. File may be encrypted or corrupted.")

    nlp_score = 0.0
    vectorizer, email_model = get_email_model_and_vectorizer()
    if extracted_text.strip() and vectorizer and email_model:
        try:
            vec = vectorizer.transform([extracted_text])
            nlp_score = float(email_model.predict_proba(vec)[0][1] * 100)
        except Exception as e:
            print(f"Error vectorizing extracted PDF text: {e}")

    flags = []
    if has_javascript:
        flags.append("Active JavaScript stream detected in PDF objects.")
    if extracted_urls:
        flags.append(f"Extracted {len(extracted_urls)} embedded hyperlink(s).")
    if nlp_score >= 50.0:
        flags.append(f"Manipulative social engineering text detected ({nlp_score:.1f}% confidence).")

    final_score = round(min(max(nlp_score, 75.0 if has_javascript else (25.0 if extracted_urls else 10.0)), 99.0), 2)
    verdict = "Suspicious / Malicious Document" if final_score >= 50.0 else "Clean Document"

    return {
        "filename": file.filename,
        "risk_percentage": final_score,
        "verdict": verdict,
        "extracted_urls": extracted_urls,
        "flags": flags if flags else ["No overt malicious indicators discovered."]
    }

# -------------------------------------------------------------
# 5. ArmorBot AI Assistant Chat Endpoint
# -------------------------------------------------------------
@app.post("/api/chat")
def chat_with_assistant(payload: ChatRequest):
    """Interactive AI Assistant endpoint."""
    if not payload.message or payload.message.strip() == "":
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"reply": "ArmorBot notice: GEMINI_API_KEY environment variable is not configured."}

    client = genai.Client(api_key=api_key)
    
    # Try gemini-2.5-flash with fallback to gemini-2.0-flash
    models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    last_error = None

    for model_name in models_to_try:
        try:
            chat = client.chats.create(
                model=model_name,
                config=types.GenerateContentConfig(
                    system_instruction=NETARMOR_KNOWLEDGE,
                    temperature=0.7
                )
            )
            response = chat.send_message(payload.message)
            if response and response.text:
                return {"reply": response.text}
        except Exception as e:
            last_error = e
            print(f"Chatbot failed with model {model_name}: {e}")

    return {"reply": f"ArmorBot is currently unavailable: {str(last_error)}"}

# -------------------------------------------------------------
# 6. Cyber Complaint Evidence File Upload Endpoint
# -------------------------------------------------------------
@app.post("/api/upload-evidence")
async def upload_complaint_evidence(file: UploadFile = File(...)):
    """Upload supporting document, screenshot, or evidence file for a cyber complaint."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    # Validate file extension
    allowed_extensions = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".txt", ".docx", ".csv"}
    _, ext = os.path.splitext(file.filename.lower())
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: PNG, JPG, WEBP, PDF, TXT, DOCX, CSV."
        )

    # Read content and enforce 10MB limit
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum 10MB limit.")

    # Prevent disguised executable files (magic bytes security inspection)
    if content.startswith(b"MZ") or content.startswith(b"\x7fELF"):
        raise HTTPException(status_code=400, detail="Security violation: Executable binary files are strictly prohibited.")

    if ext == ".pdf" and not content.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="Invalid PDF file: Missing %PDF signature.")
    if ext == ".png" and not content.startswith(b"\x89PNG"):
        raise HTTPException(status_code=400, detail="Invalid PNG image: Missing PNG signature.")
    if ext in {".jpg", ".jpeg"} and not content.startswith(b"\xff\xd8"):
        raise HTTPException(status_code=400, detail="Invalid JPEG image: Missing JPEG signature.")

    # Generate sanitized unique filename
    safe_basename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', file.filename)
    unique_filename = f"{uuid.uuid4().hex[:10]}_{safe_basename}"
    destination_path = os.path.join(UPLOADS_DIR, unique_filename)

    with open(destination_path, "wb") as f:
        f.write(content)

    return {
        "status": "success",
        "filename": unique_filename,
        "original_name": file.filename,
        "size_bytes": len(content),
        "url": f"/uploads/evidence/{unique_filename}"
    }