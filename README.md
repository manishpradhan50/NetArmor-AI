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
* **Database & Authentication:** Google Firebase (Firebase Auth, Cloud Firestore)
* **Browser Extension:** Chrome Extension APIs (Manifest V3)

---

## 🚀 Local Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/manishpradhan50/NetArmor-AI.git
cd NetArmor-AI
```

### 2. Configure Firebase (Authentication & Cloud Firestore)
1. Go to the [Firebase Console](https://console.firebase.google.com/) and create or select your project.
2. Enable **Authentication** with the **Email/Password** sign-in method.
3. Enable **Cloud Firestore** database (in test or production mode).
4. In Firestore **Rules**, copy and paste the contents from `firestore.rules`.
5. Under **Project settings** > **General** > **Your apps**, register a Web App and copy the `firebaseConfig` object.
6. Paste your credentials into `frontend/firebase-config.js`:
```javascript
const FIREBASE_CONFIG = {
  apiKey: "AIzaSy...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "...",
  appId: "..."
};
```

### 3. Setup Python Backend Environment
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.app:app --reload
```