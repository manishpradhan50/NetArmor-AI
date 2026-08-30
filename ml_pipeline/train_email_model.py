import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

# Ensure target directory exists
os.makedirs('ml_pipeline/saved_models', exist_ok=True)

DATASET_PATH = 'ml_pipeline/Phishing_Email.csv'

# 1. Load and parse the downloaded CSV dataset
if os.path.exists(DATASET_PATH):
    print(f"Loading real dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    
    # Drop rows missing text or label values
    df = df.dropna(subset=['Email Text', 'Email Type'])
    
    # Map 'Phishing Email' / 'Spam' -> 1, and 'Safe Email' -> 0
    df['label'] = df['Email Type'].apply(
        lambda x: 1 if 'phish' in str(x).lower() or 'spam' in str(x).lower() else 0
    )
    
    texts = df['Email Text'].astype(str).tolist()
    labels = df['label'].tolist()
    print(f"Loaded {len(texts)} emails successfully.")
else:
    print(f"Dataset not found at {DATASET_PATH}. Falling back to default baseline...")
    texts = [
        "Dear customer, your bank account is locked. Click here to verify immediately.",
        "URGENT: Claim your $1,000,000 lottery winnings now by replying with your SSN.",
        "Security Alert: Your password has expired. Update credentials at fake-portal.com",
        "Meeting schedule confirmed for tomorrow morning at 10 AM in conference room B.",
        "Please review the attached quarterly project report before Friday evening.",
        "Let's catch up over lunch to discuss the semester syllabus and presentation slides."
    ]
    labels = [1, 1, 1, 0, 0, 0]

# 2. TF-IDF Vectorization for NLP feature extraction
print("Vectorizing email text with TF-IDF...")
tfidf = TfidfVectorizer(
    stop_words='english',
    max_features=5000,
    ngram_range=(1, 2)
)
X = tfidf.fit_transform(texts)
y = labels

# Split into Train and Test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 3. XGBoost Classifier Training
print("Training XGBoost Classifier...")
model = XGBClassifier(n_estimators=100, max_depth=5, random_state=42)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

# 4. Export artifacts for backend API serving
joblib.dump(tfidf, 'ml_pipeline/saved_models/tfidf_vectorizer.pkl')
joblib.dump(model, 'ml_pipeline/saved_models/email_model.pkl')

print("Model training complete. Artifacts saved in ml_pipeline/saved_models/")