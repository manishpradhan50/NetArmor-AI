import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier

# Ensure target directory exists for model artifacts
os.makedirs('ml_pipeline/saved_models', exist_ok=True)

# Training dataset sample (NLP TF-IDF + XGBoost pipeline)
data = {
    'text': [
        "Dear customer, your bank account is locked. Click here to verify immediately.",
        "URGENT: Claim your $1,000,000 lottery winnings now by replying with your SSN.",
        "Security Alert: Your password has expired. Update credentials at fake-portal.com",
        "Meeting schedule confirmed for tomorrow morning at 10 AM in conference room B.",
        "Please review the attached quarterly project report before Friday evening.",
        "Let's catch up over lunch to discuss the semester syllabus and presentation slides."
    ],
    'label': [1, 1, 1, 0, 0, 0]  # 1 = Phishing/Spam, 0 = Safe
}

df = pd.DataFrame(data)

# 1. TF-IDF Vectorization for NLP feature extraction
tfidf = TfidfVectorizer(stop_words='english', max_features=5000)
X = tfidf.fit_transform(df['text'])
y = df['label']

# 2. XGBoost Classifier Training
model = XGBClassifier(n_estimators=100, max_depth=5, random_state=42)
model.fit(X, y)

# 3. Export artifacts for backend API serving
joblib.dump(tfidf, 'ml_pipeline/saved_models/tfidf_vectorizer.pkl')
joblib.dump(model, 'ml_pipeline/saved_models/email_model.pkl')

print("✅ Model training complete. Artifacts saved in ml_pipeline/saved_models/")