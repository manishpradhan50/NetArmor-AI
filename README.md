# 🛡️ NetArmor AI
### Automated Phishing Website and Email Detection System Using NLP and Machine Learning

NetArmor AI is a real-time, proactive cybersecurity solution designed to protect users against zero-day phishing links and deceptive spam emails directly within the browser ecosystem.

---

## 👥 Project Team (BCA Minor Project)
* **Manish Pradhan** (`24BCA014`) — Lead & Backend Integration
* **Sriyasri Rajguru** (`24BCA007`) — ML & NLP Pipeline Engineering
* **Suvam Nahak** (`24BCA089`) — Frontend & Chrome Extension Development

---

## 🏗️ System Architecture & Features
* **Email Content NLP Analyzer:** Utilizes TF-IDF vectorization with XGBoost classification to identify urgency triggers, fraudulent phrasing, and credential-harvesting signatures.
* **URL Structural Inspection:** Analyzes lexical patterns, deep subdomain levels, suspicious keywords, and domain anomalies in real time.
* **REST API Backend:** High-performance asynchronous FastAPI service serving model predictions.
* **Browser Integration:** Google Chrome Extension (Manifest V3) for instant link checking and message scanning.
* **Web Dashboard:** Interactive security management and URL/Email diagnosis interface.

---

## 🛠️ Tech Stack & Tools
* **Machine Learning & NLP:** Python, Scikit-Learn, XGBoost, NLTK, TF-IDF Vectorizer
* **Backend:** FastAPI, Uvicorn, Pydantic
* **Frontend:** HTML5, CSS3, Modern JavaScript
* **Browser Extension:** Chrome Extension APIs (Manifest V3)

---

## 🚀 Local Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/manishpradhan50/NetArmor-AI.git
cd NetArmor-AI