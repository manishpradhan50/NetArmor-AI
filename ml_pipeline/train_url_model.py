import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

# Add parent directory to access url_features module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml_pipeline.url_features import extract_url_features

# Ensure destination directories exist
MODEL_DIR = os.path.join("ml_pipeline", "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join("ml_pipeline", "url_dataset.csv")

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Cannot find dataset at {DATASET_PATH}. Verify the file name in ml_pipeline/.")

print(f"Loading URL dataset from {DATASET_PATH}...")
df = pd.read_csv(DATASET_PATH)

# Detect URL and Label column names automatically
url_col = None
label_col = None

for c in df.columns:
    c_clean = str(c).lower().strip()
    if c_clean in ['url', 'domain', 'link', 'webpage']:
        url_col = c
    elif c_clean in ['label', 'status', 'result', 'class', 'target', 'type']:
        label_col = c

if not url_col or not label_col:
    url_col = df.columns[0]
    label_col = df.columns[-1]

print(f"Detected columns -> URL: '{url_col}' | Label: '{label_col}'")

# Drop null values
df = df.dropna(subset=[url_col, label_col])

# Map labels to 1 (phishing/bad) and 0 (safe/legitimate)
def map_label(val):
    val_str = str(val).lower().strip()
    if val_str in ['1', '1.0', 'phishing', 'bad', 'malicious', 'yes', 'true']:
        return 1
    return 0

df['clean_label'] = df[label_col].apply(map_label)

# Optional balancing/sampling if dataset contains over 40,000 rows
if len(df) > 40000:
    print(f"Large dataset detected ({len(df)} rows). Subsampling 30,000 rows for fast feature extraction...")
    phish_subset = df[df['clean_label'] == 1]
    safe_subset = df[df['clean_label'] == 0]
    sample_size = min(len(phish_subset), len(safe_subset), 15000)
    df = pd.concat([
        phish_subset.sample(sample_size, random_state=42),
        safe_subset.sample(sample_size, random_state=42)
    ]).sample(frac=1, random_state=42)

print(f"Extracting numerical features for {len(df)} URLs...")
X = np.array([extract_url_features(str(u)) for u in df[url_col]])
y = df['clean_label'].values

# Stratified 80/20 train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training XGBoost classifier on {len(X_train)} vectors...")
xgb_url = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.08,
    random_state=42,
    eval_metric='logloss'
)
xgb_url.fit(X_train, y_train)

# Model Evaluation
y_pred = xgb_url.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {acc * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

# Export the trained model
out_path = os.path.join(MODEL_DIR, "url_model.pkl")
joblib.dump(xgb_url, out_path)
print(f"URL model artifact successfully saved to: {out_path}")