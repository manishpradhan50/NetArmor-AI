import re
from urllib.parse import urlparse, unquote

def extract_url_features(url: str) -> list:
    """
    Extract lexical and structural characteristics from a given URL.
    Returns a 7-dimensional feature vector compatible with url_model.pkl.
    Supports percent-encoding normalization so obfuscated tokens are recognized.
    """
    if not isinstance(url, str):
        url = str(url or "")
    
    clean_url = url.strip()
    
    # Safely decode percent-encoding across bounded layers
    decoded_url = clean_url
    for _ in range(4):
        try:
            nxt = unquote(decoded_url, errors="replace")
        except Exception:
            break
        if nxt == decoded_url:
            break
        decoded_url = nxt
    
    # Ensure scheme exists so urlparse doesn't miss the hostname
    parsed = urlparse(decoded_url if "://" in decoded_url else f"http://{decoded_url}")
    
    features = []
    
    # 1. URL Length (preserve length of input URL)
    features.append(len(clean_url))
    
    # 2. Presence of @ symbol (check both raw and decoded)
    features.append(1 if ("@" in clean_url or "@" in decoded_url) else 0)
    
    # 3. IP address domain check (check both raw and decoded)
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    has_ip = bool(re.search(ip_pattern, clean_url) or re.search(ip_pattern, decoded_url))
    features.append(1 if has_ip else 0)
    
    # 4. Dot count (subdomain depth from decoded URL)
    features.append(max(clean_url.count('.'), decoded_url.count('.')))
    
    # 5. Hyphen count
    features.append(max(clean_url.count('-'), decoded_url.count('-')))
    
    # 6. HTTPS scheme check
    features.append(1 if parsed.scheme.lower() == 'https' else 0)
    
    # 7. Suspicious keyword presence (inspect both raw and decoded content)
    suspicious_words = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'free']
    combined_lower = f"{clean_url.lower()} {decoded_url.lower()}"
    features.append(1 if any(word in combined_lower for word in suspicious_words) else 0)
    
    return features