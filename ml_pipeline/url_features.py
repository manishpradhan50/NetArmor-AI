import re
from urllib.parse import urlparse, unquote

def extract_url_features(url: str) -> list:
    """
    Extract lexical and structural characteristics from a given URL.
    Returns a 7-dimensional feature vector compatible with url_model.pkl.
    """
    if not isinstance(url, str):
        url = str(url or "")
    
    clean_url = url.strip()
    
    # Ensure scheme exists so urlparse doesn't miss the hostname
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    
    features = []
    
    # 1. URL Length
    features.append(len(clean_url))
    
    # 2. Presence of @ symbol
    features.append(1 if "@" in clean_url else 0)
    
    # 3. IP address domain check
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    features.append(1 if re.search(ip_pattern, clean_url) else 0)
    
    # 4. Dot count (subdomain depth)
    features.append(clean_url.count('.'))
    
    # 5. Hyphen count
    features.append(clean_url.count('-'))
    
    # 6. HTTPS scheme check
    features.append(1 if parsed.scheme.lower() == 'https' else 0)
    
    # 7. Suspicious keyword presence
    suspicious_words = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'free']
    url_lower = clean_url.lower()
    features.append(1 if any(word in url_lower for word in suspicious_words) else 0)
    
    return features