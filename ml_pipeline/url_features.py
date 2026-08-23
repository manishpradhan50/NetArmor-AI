import re
from urllib.parse import urlparse

def extract_url_features(url: str) -> list:
    """Extract lexical and structural characteristics from a given URL."""
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. Presence of @ symbol
    features.append(1 if "@" in url else 0)
    
    # 3. IP address domain check
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 4. Dot count (subdomain depth)
    features.append(url.count('.'))
    
    # 5. Hyphen count
    features.append(url.count('-'))
    
    # 6. HTTPS scheme check
    parsed = urlparse(url)
    features.append(1 if parsed.scheme == 'https' else 0)
    
    # 7. Suspicious keyword presence
    suspicious_words = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'free']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
    
    return [features]