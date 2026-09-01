import io
import os
import re
import sys
import joblib
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from pypdf import PdfReader

# Add project root to sys.path to resolve ml_pipeline imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml_pipeline.url_features import extract_url_features

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

# Initialize Google Gemini Client
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
ai_client = genai.Client(api_key=GEMINI_API_KEY)

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

# Paths to trained model artifacts
VECTORIZER_PATH = os.path.join("ml_pipeline", "saved_models", "tfidf_vectorizer.pkl")
MODEL_PATH = os.path.join("ml_pipeline", "saved_models", "email_model.pkl")

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
def health_check():
    return {
        "status": "online",
        "system": "NetArmor AI Backend",
        "project": "Automated Phishing Website & Email Detection System"
    }

# -------------------------------------------------------------
# 1. URL Structural & Lexical Scanner Endpoint
# -------------------------------------------------------------
@app.post("/api/predict-url")
def predict_url(payload: URLRequest):
    """URL Structural and Lexical Analysis endpoint."""
    if not payload.url or payload.url.strip() == "":
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    features = extract_url_features(payload.url)
    raw = features[0]
    
    score = 10.0
    reasons = []

    if raw[1] == 1:  # Contains '@'
        score += 35
        reasons.append("Contains '@' symbol used in URL obfuscation.")
    if raw[2] == 1:  # IP Address domain
        score += 40
        reasons.append("Uses raw IP address instead of a valid domain name.")
    if raw[3] > 3:   # Deep subdomains
        score += 20
        reasons.append("Abnormal number of subdomains detected.")
    if raw[6] == 1:  # Phishing keyword match
        score += 25
        reasons.append("Contains suspicious credential-harvesting keywords.")
    if raw[5] == 0:  # No HTTPS
        score += 15
        reasons.append("Insecure HTTP protocol.")

    risk_percentage = min(score, 99.0)
    verdict = "Phishing / Malicious" if risk_percentage >= 50.0 else "Safe / Legitimate"

    return {
        "target_url": payload.url,
        "risk_percentage": round(risk_percentage, 2),
        "verdict": verdict,
        "flags": reasons if reasons else ["No high-risk structural anomalies detected."]
    }

# -------------------------------------------------------------
# 2. Email NLP Semantic Scanner Endpoint
# -------------------------------------------------------------
@app.post("/api/predict-email")
def predict_email(payload: EmailRequest):
    """Email NLP TF-IDF + XGBoost prediction endpoint."""
    if not os.path.exists(VECTORIZER_PATH) or not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=500, detail="Model files not found. Run train_email_model.py first.")

    if not payload.text or payload.text.strip() == "":
        raise HTTPException(status_code=400, detail="Email body text cannot be empty.")

    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    transformed_vector = vectorizer.transform([payload.text])
    probabilities = model.predict_proba(transformed_vector)[0]
    spam_prob = round(float(probabilities[1]) * 100, 2)
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

    # 1. Regex Link Extraction
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*)"
    extracted_urls = re.findall(url_pattern, text)

    # 2. NLP Semantic Scoring
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)
    transformed = vectorizer.transform([text])
    nlp_prob = float(model.predict_proba(transformed)[0][1] * 100)

    flags = []

    # 3. Smishing keyword matching
    smishing_patterns = [r"\botp\b", r"\bkyc\b", r"\bblocked\b", r"\bwin\b", r"\bprize\b", r"\brefund\b", r"\burgent\b", r"\bverify\b"]
    matched_patterns = [p.replace(r"\b", "") for p in smishing_patterns if re.search(p, text, re.IGNORECASE)]
    
    if matched_patterns:
        flags.append(f"Smishing trigger keywords detected: {', '.join(matched_patterns)}")
    if extracted_urls:
        flags.append(f"Detected {len(extracted_urls)} embedded short/redirect link(s).")
    if nlp_prob >= 50.0:
        flags.append(f"NLP model identified social engineering phrasing ({nlp_prob:.1f}% confidence).")

    # Combine heuristic and NLP weighting
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
    reader = PdfReader(io.BytesIO(content))

    extracted_text = ""
    extracted_urls = []
    has_javascript = False

    for page in reader.pages:
        text = page.extract_text() or ""
        extracted_text += text + " "

        if "/Annots" in page:
            for annot in page["/Annots"]:
                try:
                    obj = annot.get_object()
                    if "/A" in obj and "/URI" in obj["/A"]:
                        extracted_urls.append(obj["/A"]["/URI"])
                except Exception:
                    continue

    if "/JavaScript" in reader.trailer or "/JS" in reader.trailer:
        has_javascript = True

    nlp_score = 0.0
    if extracted_text.strip() and os.path.exists(VECTORIZER_PATH) and os.path.exists(MODEL_PATH):
        vectorizer = joblib.load(VECTORIZER_PATH)
        model = joblib.load(MODEL_PATH)
        vec = vectorizer.transform([extracted_text])
        nlp_score = float(model.predict_proba(vec)[0][1] * 100)

    flags = []
    if has_javascript:
        flags.append("Active JavaScript stream detected in PDF objects.")
    if extracted_urls:
        flags.append(f"Extracted {len(extracted_urls)} embedded hyper link(s).")
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

    try:
        response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"{NETARMOR_KNOWLEDGE}\n\nUser Question: {payload.message}\nArmorBot Response:"
        )
        return {"reply": response.text}
    except Exception:
        return {"reply": "I'm having trouble connecting right now. Please verify your network connection and API key."}