import os
import sys
import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai

# Load environment variables automatically from root .env
load_dotenv()

# Add project root to sys.path to resolve ml_pipeline imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml_pipeline.url_features import extract_url_features

app = FastAPI(
    title="NetArmor AI API",
    description="Automated Phishing Website & Email Detection System using NLP and XGBoost"
)

# Enable CORS for Chrome Extension and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Google Gemini Client with loaded API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ai_client = genai.Client(api_key=GEMINI_API_KEY)

# Knowledge base for NetArmor AI Assistant
NETARMOR_KNOWLEDGE = """
You are 'ArmorBot', the virtual cybersecurity AI assistant for the NetArmor AI platform.
NetArmor AI is an automated phishing website and email threat detection system built as a BCA Minor Project.

Key Technical Modules:
1. Website URL Scanner: Inspects lexical/structural vectors including '@' symbols, raw IP hosts, deep subdomain levels, suspicious keywords, and protocol security (HTTPS).
2. Email Content NLP Scanner: Uses TF-IDF Vectorization and an XGBoost Classifier trained to flag manipulative phrasing, scam urgency, and credential harvesting.
3. Google Chrome Extension (Manifest V3): Provides real-time page URL evaluation and email threat inspection in the browser.
4. Project Team: Manish Pradhan (Lead, Backend & Integration), Sriyasri Rajguru (ML & NLP Pipeline), Suvam Nahak (Frontend & Chrome Extension).

Your Role:
- Answer user questions politely, clearly, and concisely.
- Explain how the scanners detect phishing links and spam.
- Provide cybersecurity guidance and tips on recognizing social engineering.
"""

# Paths to trained model artifacts
VECTORIZER_PATH = os.path.join("ml_pipeline", "saved_models", "tfidf_vectorizer.pkl")
MODEL_PATH = os.path.join("ml_pipeline", "saved_models", "email_model.pkl")

# Request Schemas
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str

class ChatRequest(BaseModel):
    message: str

@app.get("/")
def health_check():
    return {
        "status": "online",
        "system": "NetArmor AI Backend",
        "project": "Automated Phishing Website & Email Detection System"
    }

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

@app.post("/api/chat")
def chat_with_assistant(payload: ChatRequest):
    """ArmorBot Interactive AI Assistant endpoint."""
    if not payload.message or payload.message.strip() == "":
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    try:
        response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"{NETARMOR_KNOWLEDGE}\n\nUser Question: {payload.message}\nArmorBot Response:"
        )
        return {"reply": response.text}
    except Exception as e:
        return {"reply": "I'm having trouble connecting to my AI service right now. Please verify your API key."}