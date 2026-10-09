"""
Domain Analysis & Brand Impersonation Intelligence Engine for NetArmor AI
========================================================================
Provides Public Suffix List (PSL)-aware domain parsing, brand impersonation
detection, typosquatting inspection, structural risk vector assessment, and
multi-factor risk synthesis.
"""

import re
import ipaddress
from urllib.parse import urlsplit, unquote
import tldextract

# ---------------------------------------------------------------------------
# Offline-capable TLDExtract instance (uses bundled PSL snapshot, no network latency)
# ---------------------------------------------------------------------------
_tld_extractor = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None)

# ---------------------------------------------------------------------------
# Authoritative Brand Knowledge Catalog
# ---------------------------------------------------------------------------
BRAND_CATALOG = {
    "Google": {
        "brand_name": "Google",
        "keywords": ["google", "gmail", "googlevideo", "gstatic", "youtube"],
        "official_registered_domains": {
            "google.com", "google.co.uk", "google.co.in", "google.ca", "google.de",
            "google.fr", "google.it", "google.es", "google.co.jp", "google.com.au",
            "google.com.br", "googlevideo.com", "googleusercontent.com", "gstatic.com",
            "youtube.com", "gmail.com", "android.com", "google.org", "goo.gl", "withgoogle.com"
        },
        "typosquats": ["g00gle", "googel", "g0ogle", "goog1e", "googl", "guge"]
    },
    "Microsoft": {
        "brand_name": "Microsoft",
        "keywords": ["microsoft", "office365", "outlook", "live", "bing", "azure", "windows", "onedrive", "sharepoint", "skype"],
        "official_registered_domains": {
            "microsoft.com", "office.com", "live.com", "outlook.com", "bing.com",
            "azure.com", "windows.com", "msn.com", "onedrive.com", "sharepoint.com",
            "skype.com", "microsoftonline.com", "office365.com", "visualstudio.com"
        },
        "typosquats": ["micros0ft", "rnicrosoft", "micosoft", "microsof", "microsft"]
    },
    "PayPal": {
        "brand_name": "PayPal",
        "keywords": ["paypal"],
        "official_registered_domains": {
            "paypal.com", "paypal.me", "paypal-community.com"
        },
        "typosquats": ["paypa1", "paypai", "pay-pal", "pyapal", "paypall", "paypaI"]
    },
    "Amazon": {
        "brand_name": "Amazon",
        "keywords": ["amazon", "primevideo", "aws"],
        "official_registered_domains": {
            "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr",
            "amazon.co.jp", "amazon.ca", "amazon.com.au", "amazon.es", "amazon.it",
            "amazon.com.br", "amazon.nl", "primevideo.com", "aws.amazon.com", "media-amazon.com",
            "amazon.jobs", "a2z.com"
        },
        "typosquats": ["arnazon", "amaz0n", "amazn", "amzon", "amazonn"]
    },
    "Apple": {
        "brand_name": "Apple",
        "keywords": ["apple", "icloud"],
        "official_registered_domains": {
            "apple.com", "icloud.com", "apple-dns.net", "me.com", "itunes.com"
        },
        "typosquats": ["app1e", "aple", "app-le", "applee"]
    },
    "Facebook": {
        "brand_name": "Facebook",
        "keywords": ["facebook", "messenger", "meta"],
        "official_registered_domains": {
            "facebook.com", "fb.com", "messenger.com", "meta.com", "meta.ai", "fbcdn.net"
        },
        "typosquats": ["faceb00k", "facebok", "faceb0k", "facebbok"]
    },
    "Instagram": {
        "brand_name": "Instagram",
        "keywords": ["instagram"],
        "official_registered_domains": {
            "instagram.com", "cdninstagram.com"
        },
        "typosquats": ["1nstagram", "instagrarn", "instgrm", "instgram"]
    },
    "Netflix": {
        "brand_name": "Netflix",
        "keywords": ["netflix"],
        "official_registered_domains": {
            "netflix.com", "nflxext.com", "nflxvideo.net"
        },
        "typosquats": ["netf1ix", "netfllx", "netfix", "netfliix"]
    },
    "LinkedIn": {
        "brand_name": "LinkedIn",
        "keywords": ["linkedin"],
        "official_registered_domains": {
            "linkedin.com", "licdn.com"
        },
        "typosquats": ["linked1n", "linkdin", "linkin"]
    },
    "Twitter": {
        "brand_name": "Twitter / X",
        "keywords": ["twitter"],
        "official_registered_domains": {
            "twitter.com", "x.com", "t.co", "twimg.com"
        },
        "typosquats": ["tw1tter", "twiter", "twittr"]
    },
    "GitHub": {
        "brand_name": "GitHub",
        "keywords": ["github"],
        "official_registered_domains": {
            "github.com", "github.io", "githubassets.com", "githubusercontent.com"
        },
        "typosquats": ["g1thub", "gthub", "githb"]
    },
    "Dropbox": {
        "brand_name": "Dropbox",
        "keywords": ["dropbox"],
        "official_registered_domains": {
            "dropbox.com", "dropboxstatic.com"
        },
        "typosquats": ["dr0pbox", "dropb0x", "dropbx"]
    },
    "WhatsApp": {
        "brand_name": "WhatsApp",
        "keywords": ["whatsapp"],
        "official_registered_domains": {
            "whatsapp.com", "wa.me", "whatsapp.net"
        },
        "typosquats": ["whatsap", "whattsapp", "whatapp"]
    },
    "Telegram": {
        "brand_name": "Telegram",
        "keywords": ["telegram"],
        "official_registered_domains": {
            "telegram.org", "t.me"
        },
        "typosquats": ["telegraam", "telegrm"]
    },
    "Yahoo": {
        "brand_name": "Yahoo",
        "keywords": ["yahoo"],
        "official_registered_domains": {
            "yahoo.com", "ymail.com"
        },
        "typosquats": ["yah00", "yaho"]
    }
}

TRUSTED_AUTHORITY_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org", "wikimedia.org",
    "yahoo.com", "reddit.com", "amazon.com", "amazon.in", "amazon.co.uk", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com", "netflix.com", "github.com",
    "stackoverflow.com", "cloudflare.com", "bing.com", "office.com", "live.com",
    "gmail.com", "outlook.com", "dropbox.com", "whatsapp.com", "telegram.org",
    "mozilla.org", "w3.org", "python.org", "apache.org", "kernel.org"
}

# High-risk TLDs commonly exploited in throwaway phishing infrastructure
SUSPICIOUS_TLDS = {
    "top", "xyz", "fit", "tk", "ml", "ga", "cf", "gq", "work", "buzz", "click",
    "country", "rest", "stream", "gdn", "mom", "casa", "surf", "live"
}

# Sensitive credential harvesting tokens
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "update",
    "banking", "secure", "security", "account", "password", "credential",
    "auth", "authentication", "wallet", "confirm", "recovery", "support"
]

# ---------------------------------------------------------------------------
# URL Normalization & Domain Parsing
# ---------------------------------------------------------------------------
REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_url", "redirect_uri", "next", "url", "return",
    "return_url", "return_to", "dest", "destination", "goto", "target",
    "link", "forward", "r", "u", "to"
}

def safe_decode_multilayer(text: str, max_layers: int = 4) -> dict:
    """
    Safely decode percent-encoded text across bounded layers.
    Prevents infinite loops by capping layers.
    Handles malformed percent-encoding gracefully.
    Detects double-encoding, alphanumeric character obfuscation, and protocol strings.
    """
    if not text or not isinstance(text, str):
        return {
            "original": "",
            "decoded": "",
            "layers": 0,
            "has_encoding": False,
            "double_encoding_detected": False,
            "has_alphanumeric_obfuscation": False,
            "obfuscated_chars": "",
            "has_encoded_protocol": False,
            "history": []
        }

    current = text
    history = [current]
    layers = 0
    has_double = bool(re.search(r'%25[0-9a-fA-F]{2}', text, re.IGNORECASE))
    all_obfuscated_chars = []

    initial_matches = list(re.finditer(r'%([0-9a-fA-F]{2})', text))
    has_encoding = len(initial_matches) > 0

    for m in initial_matches:
        try:
            b_val = int(m.group(1), 16)
            if (48 <= b_val <= 57) or (65 <= b_val <= 90) or (97 <= b_val <= 122):
                all_obfuscated_chars.append(chr(b_val))
        except Exception:
            pass

    for _ in range(max_layers):
        if not re.search(r'%[0-9a-fA-F]{2}', current):
            break
        try:
            nxt = unquote(current, errors="replace")
        except Exception:
            break
        if nxt == current:
            break
        layers += 1
        current = nxt
        history.append(current)

        if re.search(r'%[0-9a-fA-F]{2}', current):
            for m in re.finditer(r'%([0-9a-fA-F]{2})', current):
                try:
                    b_val = int(m.group(1), 16)
                    if (48 <= b_val <= 57) or (65 <= b_val <= 90) or (97 <= b_val <= 122):
                        all_obfuscated_chars.append(chr(b_val))
                except Exception:
                    pass

    if layers >= 2:
        has_double = True

    has_proto = bool(re.search(r'https?%(?:3a|3A)%(?:2f|2F)', text, re.IGNORECASE)) or \
                bool(re.search(r'%68%74%74%70', text, re.IGNORECASE)) or \
                ("://" in current and "://" not in text)

    return {
        "original": text,
        "decoded": current,
        "layers": layers,
        "has_encoding": has_encoding,
        "double_encoding_detected": has_double,
        "has_alphanumeric_obfuscation": len(all_obfuscated_chars) > 0,
        "obfuscated_chars": "".join(all_obfuscated_chars),
        "has_encoded_protocol": has_proto,
        "history": history
    }

def analyze_redirects(query_str: str, base_host: str) -> dict:
    """
    Parse query parameters safely and inspect redirect parameters.
    Detects if redirect target is percent-encoded, external, or targets sensitive paths.
    Recursively inspects destination domain for PSL registered domain, subdomain,
    and brand impersonation.
    """
    default_res = {
        "redirect_detected": False,
        "encoded_redirect_detected": False,
        "param_name": None,
        "raw_destination": None,
        "decoded_destination": None,
        "is_external": False,
        "dest_host": None,
        "destination_domain": None,
        "destination_registered_domain": None,
        "destination_subdomain": None,
        "destination_brand": None,
        "destination_brand_impersonation": False,
        "destination_is_official": False,
        "destination_is_ip": False,
        "destination_brand_details": None,
        "is_encoded": False,
        "sensitive_keywords": []
    }
    if not query_str:
        return default_res

    param_pairs = [p.split("=", 1) for p in query_str.split("&") if p]
    for pair in param_pairs:
        k = pair[0]
        raw_v = pair[1] if len(pair) > 1 else ""
        k_lower = k.lower()
        is_redirect_key = k_lower in REDIRECT_PARAM_NAMES
        has_embedded_url = "://" in raw_v or "%3a%2f%2f" in raw_v.lower() or "%68%74%74%70" in raw_v.lower() or raw_v.startswith(("%2f", "%2F", "/"))

        if is_redirect_key or (has_embedded_url and k_lower not in {"q", "query", "search", "s"}):
            v_analysis = safe_decode_multilayer(raw_v)
            decoded_dest = v_analysis["decoded"]
            is_encoded = v_analysis["has_encoding"]

            is_external = False
            dest_host = None
            dest_path = "/"
            dest_reg_domain = None
            dest_subdomain = ""
            dest_brand = None
            dest_brand_impersonation = False
            dest_is_official = False
            dest_is_ip = False
            dest_brand_details = None

            if decoded_dest.startswith(("http://", "https://", "//")):
                try:
                    url_to_parse = decoded_dest if "://" in decoded_dest else f"http:{decoded_dest}"
                    dest_parts = urlsplit(url_to_parse)
                    t_host = (dest_parts.netloc or "").split(":")[0].lower()
                    dest_path = dest_parts.path or "/"
                    if t_host:
                        dest_host = t_host
                        if t_host != base_host:
                            is_external = True

                        dest_norm = {
                            "hostname": dest_host,
                            "path": dest_path,
                            "raw_url": decoded_dest,
                            "decoded_url": decoded_dest,
                            "scheme": dest_parts.scheme or "http",
                            "port": None,
                            "has_at_symbol": "@" in decoded_dest
                        }
                        dest_domain_info = extract_domain_info(dest_norm)
                        dest_brand_eval = detect_brand_impersonation(dest_domain_info, dest_norm)

                        dest_reg_domain = dest_domain_info["registered_domain"]
                        dest_subdomain = dest_domain_info["subdomain"]
                        dest_is_ip = dest_domain_info["is_ip"]
                        dest_brand = dest_brand_eval["brand"]
                        dest_brand_impersonation = dest_brand_eval["is_impersonation"]
                        dest_is_official = dest_brand_eval["is_official"]
                        dest_brand_details = dest_brand_eval["details"]
                except Exception:
                    pass

            dest_lower = decoded_dest.lower()
            matched_sens = [kw for kw in CREDENTIAL_KEYWORDS if kw in dest_lower]

            return {
                "redirect_detected": True,
                "encoded_redirect_detected": is_encoded,
                "param_name": k,
                "raw_destination": raw_v,
                "decoded_destination": decoded_dest,
                "is_external": is_external,
                "dest_host": dest_host,
                "destination_domain": dest_host,
                "destination_registered_domain": dest_reg_domain,
                "destination_subdomain": dest_subdomain,
                "destination_brand": dest_brand,
                "destination_brand_impersonation": dest_brand_impersonation,
                "destination_is_official": dest_is_official,
                "destination_is_ip": dest_is_ip,
                "destination_brand_details": dest_brand_details,
                "is_encoded": is_encoded,
                "sensitive_keywords": matched_sens
            }

    return default_res

def normalize_url(raw_url: str) -> dict:
    """
    Clean, validate, and normalize input URL into canonical and decoded parts.
    Handles missing schemes, percent encoding, userinfo (@), and port numbers.
    Provides multi-layer safe decoding, encoded character analysis, and redirect inspection.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty or only whitespace.")

    # Determine original scheme or default
    scheme_present = "://" in cleaned
    url_to_parse = cleaned if scheme_present else f"http://{cleaned}"

    try:
        parts = urlsplit(url_to_parse)
    except Exception as e:
        raise ValueError(f"Malformed URL structure: {e}")

    scheme = parts.scheme.lower() if parts.scheme else ("https" if cleaned.startswith("https://") else "http")
    netloc = parts.netloc or ""

    # Handle userinfo obfuscation (e.g. user:pass@host)
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)

    # Extract port if present
    port = None
    host = host_port
    if ":" in host_port:
        try:
            h_temp, p_temp = host_port.rsplit(":", 1)
            if p_temp.isdigit():
                port = int(p_temp)
                host = h_temp
        except Exception:
            pass

    # Decode hostname using safe multi-layer decoding
    host_analysis = safe_decode_multilayer(host)
    clean_host = host_analysis["decoded"].strip().lower().rstrip(".").strip("[]")

    if not clean_host:
        raise ValueError("URL must contain a valid non-empty hostname.")

    # Multi-layer decoding of path, query, and fragment
    raw_path = parts.path or "/"
    raw_query = parts.query or ""
    raw_fragment = parts.fragment or ""

    path_analysis = safe_decode_multilayer(raw_path)
    query_analysis = safe_decode_multilayer(raw_query)
    fragment_analysis = safe_decode_multilayer(raw_fragment)

    decoded_path = path_analysis["decoded"] or "/"
    decoded_query = query_analysis["decoded"]
    decoded_fragment = fragment_analysis["decoded"]

    # Overall encoding metrics across entire URL
    url_analysis = safe_decode_multilayer(cleaned)
    max_layers = max(host_analysis["layers"], path_analysis["layers"], query_analysis["layers"], url_analysis["layers"])
    encoding_detected = (max_layers > 0) or host_analysis["has_encoding"] or path_analysis["has_encoding"] or query_analysis["has_encoding"]
    double_encoding_detected = host_analysis["double_encoding_detected"] or path_analysis["double_encoding_detected"] or query_analysis["double_encoding_detected"] or url_analysis["double_encoding_detected"]

    # Canonical URL (original encoded parts preserved for display)
    canonical_url = f"{scheme}://{clean_host}"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        canonical_url += f":{port}"
    if parts.path:
        canonical_url += parts.path
    if parts.query:
        canonical_url += f"?{parts.query}"
    if parts.fragment:
        canonical_url += f"#{parts.fragment}"

    # Reconstructed Decoded URL
    decoded_url = f"{scheme}://{clean_host}"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        decoded_url += f":{port}"
    decoded_url += decoded_path
    if decoded_query:
        decoded_url += f"?{decoded_query}"
    if decoded_fragment:
        decoded_url += f"#{decoded_fragment}"

    # Analyze redirect parameters
    redirect_info = analyze_redirects(raw_query, clean_host)

    # Determine primary decoded content highlight
    decoded_content = None
    if redirect_info["encoded_redirect_detected"] and redirect_info["decoded_destination"]:
        decoded_content = redirect_info["decoded_destination"]
    elif path_analysis["has_encoding"] and path_analysis["decoded"] != "/":
        decoded_content = path_analysis["decoded"].lstrip("/")
    elif query_analysis["has_encoding"] and query_analysis["decoded"]:
        q_pairs = [p.split("=", 1) for p in query_analysis["decoded"].split("&") if p]
        if q_pairs:
            decoded_content = q_pairs[0][1] if len(q_pairs[0]) > 1 else q_pairs[0][0]
        else:
            decoded_content = query_analysis["decoded"]
    elif encoding_detected:
        decoded_content = decoded_url

    has_any_obfuscation = path_analysis["has_alphanumeric_obfuscation"] or query_analysis["has_alphanumeric_obfuscation"]
    has_proto = path_analysis["has_encoded_protocol"] or query_analysis["has_encoded_protocol"] or url_analysis["has_encoded_protocol"]

    risk_contrib = "None"
    if double_encoding_detected:
        risk_contrib = "Moderate"
    elif has_any_obfuscation or (redirect_info["encoded_redirect_detected"] and redirect_info["is_external"]):
        risk_contrib = "Moderate"
    elif redirect_info["encoded_redirect_detected"]:
        risk_contrib = "Moderate"
    elif encoding_detected:
        risk_contrib = "None"

    encoding_info = {
        "encoding_detected": encoding_detected,
        "encoding_layers": max_layers,
        "double_encoding_detected": double_encoding_detected,
        "decoded_url": decoded_url,
        "decoded_path": decoded_path,
        "decoded_query": decoded_query,
        "decoded_fragment": decoded_fragment,
        "decoded_content": decoded_content,
        "risk_contribution": risk_contrib,
        "path_alphanumeric_obfuscation": path_analysis["has_alphanumeric_obfuscation"],
        "query_alphanumeric_obfuscation": query_analysis["has_alphanumeric_obfuscation"],
        "path_obfuscated_chars": path_analysis["obfuscated_chars"],
        "query_obfuscated_chars": query_analysis["obfuscated_chars"],
        "has_encoded_protocol": has_proto,
        "encoded_redirect_detected": redirect_info["encoded_redirect_detected"]
    }

    return {
        "raw_url": raw_url,
        "canonical_url": canonical_url,
        "decoded_url": decoded_url,
        "scheme": scheme,
        "hostname": clean_host,
        "port": port,
        "userinfo": userinfo,
        "has_at_symbol": "@" in raw_url or "@" in decoded_url,
        "path": raw_path,
        "query": raw_query,
        "fragment": raw_fragment,
        "decoded_path": decoded_path,
        "decoded_query": decoded_query,
        "encoding_info": encoding_info,
        "redirect_info": redirect_info
    }


def is_ip_address(host: str) -> bool:
    """Check whether a host string is a valid IPv4 or IPv6 address."""
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass

    # Decimal or hex IP check (e.g. 0x7f000001 or pure numbers)
    if clean.isdigit() and len(clean) >= 7:
        try:
            ipaddress.IPv4Address(int(clean))
            return True
        except ValueError:
            pass
    if clean.startswith("0x") or clean.startswith("0X"):
        try:
            ipaddress.IPv4Address(int(clean, 16))
            return True
        except ValueError:
            pass

    return False


def extract_domain_info(normalized: dict) -> dict:
    """
    Extract PSL-aware registered domain, subdomain, domain label, and public suffix.
    """
    host = normalized["hostname"]

    if not host:
        return {
            "hostname": "",
            "subdomain": "",
            "domain": "",
            "suffix": "",
            "registered_domain": "",
            "is_ip": False,
            "subdomain_labels": []
        }

    if is_ip_address(host):
        return {
            "hostname": host,
            "subdomain": "",
            "domain": host,
            "suffix": "",
            "registered_domain": host,
            "is_ip": True,
            "subdomain_labels": []
        }

    ext = _tld_extractor(host)
    sub = ext.subdomain or ""
    dom = ext.domain or ""
    suf = ext.suffix or ""

    reg_dom = f"{dom}.{suf}" if (dom and suf) else host
    sub_labels = [p for p in sub.split(".") if p] if sub else []

    return {
        "hostname": host,
        "subdomain": sub,
        "domain": dom,
        "suffix": suf,
        "registered_domain": reg_dom,
        "is_ip": False,
        "subdomain_labels": sub_labels
    }


# ---------------------------------------------------------------------------
# Brand Impersonation & Typosquatting Analysis
# ---------------------------------------------------------------------------
def detect_brand_impersonation(domain_info: dict, normalized: dict) -> dict:
    """
    Inspect whether the URL attempts brand impersonation through:
    1. Misleading subdomains (e.g. google.com.example.com, google-login.example.com)
    2. Typosquatting / Lookalike domains (e.g. paypa1.com, micros0ft.com)
    3. Unauthorized brand names combined with phishing trigger words in registered domains.
    4. Distinguishes official authoritative brand domains from impersonations.
    """
    hostname = domain_info["hostname"].lower()
    reg_dom = domain_info["registered_domain"].lower()
    subdomain = domain_info["subdomain"].lower()
    sub_labels = [s.lower() for s in domain_info.get("subdomain_labels", [])]
    path = normalized["path"].lower()

    if domain_info["is_ip"] or not reg_dom:
        return {
            "is_impersonation": False,
            "is_official": False,
            "brand": None,
            "impersonation_type": None,
            "details": None,
            "risk_impact": 0
        }

    # 1. Authoritative Domain Verification: Official domain of catalog brand or trusted authority
    if reg_dom in TRUSTED_AUTHORITY_DOMAINS:
        auth_name = reg_dom.split(".")[0].capitalize()
        for brand_key, brand_data in BRAND_CATALOG.items():
            if reg_dom in brand_data["official_registered_domains"]:
                auth_name = brand_data["brand_name"]
                break
        return {
            "is_impersonation": False,
            "is_official": True,
            "brand": auth_name,
            "impersonation_type": None,
            "details": f"Official verified domain for {auth_name}.",
            "risk_impact": 0
        }

    for brand_key, brand_data in BRAND_CATALOG.items():
        if reg_dom in brand_data["official_registered_domains"]:
            return {
                "is_impersonation": False,
                "is_official": True,
                "brand": brand_data["brand_name"],
                "impersonation_type": None,
                "details": f"Official verified domain for {brand_data['brand_name']}.",
                "risk_impact": 0
            }

    # 2. Check each brand for impersonation in subdomains, registered domains, or typosquats
    for brand_key, brand_data in BRAND_CATALOG.items():
        brand_name = brand_data["brand_name"]
        keywords = brand_data["keywords"]
        official_domains = brand_data["official_registered_domains"]
        typosquats = brand_data["typosquats"]

        # Check A: Exact official domain mimicry in subdomain
        # e.g., 'google.com' or 'amazon.in' in subdomain 'google.com.example.com'
        for off_dom in official_domains:
            # Full domain match in subdomain
            if off_dom == subdomain or subdomain.endswith(f".{off_dom}") or f"{off_dom}." in subdomain or off_dom in sub_labels:
                return {
                    "is_impersonation": True,
                    "is_official": False,
                    "brand": brand_name,
                    "impersonation_type": "misleading_subdomain",
                    "details": (
                        f"Brand impersonation detected: Subdomain '{domain_info['subdomain']}' deceptively mimics "
                        f"official domain '{off_dom}' for {brand_name} under unrelated registered domain '{reg_dom}'."
                    ),
                    "risk_impact": 80
                }

        # Check B: Subdomain contains brand keyword combined with hyphens or dots
        # e.g., 'google-login' in google-login.example.com, 'paypal' in paypal.com.example.com
        for kw in keywords:
            for label in sub_labels:
                # Direct label match or hyphenated keyword e.g. google-login, paypal-auth
                if label == kw or label.startswith(f"{kw}-") or label.endswith(f"-{kw}") or f"-{kw}-" in label:
                    return {
                        "is_impersonation": True,
                        "is_official": False,
                        "brand": brand_name,
                        "impersonation_type": "misleading_subdomain",
                        "details": (
                            f"Brand impersonation detected: Subdomain '{domain_info['subdomain']}' contains {brand_name} "
                            f"brand identifier under unrelated registered domain '{reg_dom}'."
                        ),
                        "risk_impact": 78
                    }

        # Check C: Typosquatting in domain label or subdomain
        dom_label = domain_info["domain"].lower()
        for typo in typosquats:
            if dom_label == typo or typo in sub_labels:
                return {
                    "is_impersonation": True,
                    "is_official": False,
                    "brand": brand_name,
                    "impersonation_type": "typosquatting",
                    "details": (
                        f"Typosquatting detected: Hostname label '{typo}' is a deceptive lookalike "
                        f"of {brand_name}."
                    ),
                    "risk_impact": 82
                }

        # Check D: Registered domain contains brand keyword combined with phishing keywords
        # e.g., 'google-security.com', 'paypal-verification.net'
        for kw in keywords:
            if kw in dom_label and dom_label != kw:
                has_cred = any(ck in dom_label for ck in ["login", "verify", "secure", "account", "update", "auth"])
                if has_cred:
                    return {
                        "is_impersonation": True,
                        "is_official": False,
                        "brand": brand_name,
                        "impersonation_type": "unauthorized_domain",
                        "details": (
                            f"Suspicious brand-spoofing domain: Registered domain '{reg_dom}' incorporates "
                            f"{brand_name} brand with sensitive security terms."
                        ),
                        "risk_impact": 84
                    }

    return {
        "is_impersonation": False,
        "is_official": False,
        "brand": None,
        "impersonation_type": None,
        "details": None,
        "risk_impact": 0
    }


# ---------------------------------------------------------------------------
# Structural & Behavioral Anomaly Detection
# ---------------------------------------------------------------------------
def detect_structural_anomalies(domain_info: dict, normalized: dict) -> list[dict]:
    """
    Examine structural anomalies: raw IPs, unusual ports, excessive subdomains,
    credential keywords, @ signs, insecure protocol, suspicious TLDs,
    as well as URL encoding obfuscation, double encoding, and open redirects.
    Calibrated to prevent false positives on benign encoded URLs and normal authentication endpoints.
    """
    anomalies = []
    enc = normalized.get("encoding_info", {})
    redir = normalized.get("redirect_info", {})

    # 1. Raw IP address host
    if domain_info["is_ip"]:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "high",
            "risk_delta": 45,
            "message": "Uses a raw numeric IP address instead of a standard registered domain name."
        })

    # 2. Obfuscation with @ symbol
    if normalized["has_at_symbol"]:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "high",
            "risk_delta": 40,
            "message": "Contains '@' symbol, a common tactic for userinfo credential obfuscation."
        })

    # 3. Non-standard port
    port = normalized["port"]
    if port is not None and port not in (80, 443):
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 15,
            "message": f"Connects over an unusual non-standard network port (:{port})."
        })

    # 4. Excessive subdomains (depth check)
    sub_labels = domain_info.get("subdomain_labels", [])
    if len(sub_labels) >= 3:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 15,
            "message": f"Excessive subdomain depth detected ({len(sub_labels)} sub-levels in host)."
        })

    # 5. Excessive hyphens in hostname
    host = domain_info["hostname"]
    if host.count("-") >= 3:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 12,
            "message": f"Unusually high hyphen count in hostname ({host.count('-')} hyphens)."
        })

    # 6. Abusive / suspicious TLD
    suffix = domain_info.get("suffix", "").lower()
    if suffix in SUSPICIOUS_TLDS:
        anomalies.append({
            "vector": "reputation_intelligence",
            "severity": "medium",
            "risk_delta": 20,
            "message": f"Uses high-risk top-level domain (.{suffix}) frequently associated with phishing."
        })

    # 7. Sensitive credential keywords (non-punitive baseline for legitimate sites)
    raw_lower = normalized["raw_url"].lower()
    decoded_lower = normalized["decoded_url"].lower()
    matched_raw = [kw for kw in CREDENTIAL_KEYWORDS if kw in raw_lower]
    matched_decoded = [kw for kw in CREDENTIAL_KEYWORDS if kw in decoded_lower]
    all_matched = list(dict.fromkeys(matched_raw + matched_decoded))

    if all_matched:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "low",
            "risk_delta": 5,
            "message": f"Contains sensitive auth/credential keywords: {', '.join(all_matched[:3])}."
        })

    # 8. Protocol security check (Insecure HTTP)
    if normalized["scheme"] == "http":
        anomalies.append({
            "vector": "domain_structure",
            "severity": "low",
            "risk_delta": 5,
            "message": "Insecure HTTP protocol (missing SSL/TLS transport encryption)."
        })

    # 9. URL Encoding: Alphanumeric path characters encoded
    if enc.get("path_alphanumeric_obfuscation"):
        anomalies.append({
            "vector": "encoding_obfuscation",
            "severity": "low",
            "risk_delta": 6,
            "message": f"URL path utilizes percent-encoded alphanumeric characters (decodes to: '{enc.get('decoded_path')}')."
        })

    # 10. URL Encoding: Double encoding detected
    if enc.get("double_encoding_detected"):
        anomalies.append({
            "vector": "encoding_obfuscation",
            "severity": "medium",
            "risk_delta": 12,
            "message": f"Double percent-encoding detected ({enc.get('encoding_layers')} layers, e.g. %25 sequences)."
        })

    # 11. Redirect inspection
    if redir.get("redirect_detected"):
        if redir.get("destination_brand_impersonation"):
            anomalies.append({
                "vector": "domain_structure",
                "severity": "high",
                "risk_delta": 55,
                "message": f"External redirect parameter '{redir['param_name']}' targets deceptive brand impersonation domain ('{redir['dest_host']}', targeting {redir['destination_brand']})."
            })
        elif redir.get("destination_is_ip"):
            anomalies.append({
                "vector": "domain_structure",
                "severity": "high",
                "risk_delta": 50,
                "message": f"External redirect parameter '{redir['param_name']}' targets raw numeric IP destination ('{redir['dest_host']}')."
            })
        elif redir.get("is_external"):
            anomalies.append({
                "vector": "domain_structure",
                "severity": "low",
                "risk_delta": 10,
                "message": f"Redirect parameter '{redir['param_name']}' targets external destination domain ('{redir['dest_host']}')."
            })
        else:
            anomalies.append({
                "vector": "domain_structure",
                "severity": "low",
                "risk_delta": 3,
                "message": f"Internal redirect parameter '{redir['param_name']}' points to local path '{redir['decoded_destination']}'."
            })

    return anomalies


# ---------------------------------------------------------------------------
# Multi-Vector Risk Synthesis & Evaluation Engine
# ---------------------------------------------------------------------------
def evaluate_url_security(raw_url: str, ml_model_probability: float | None = None) -> dict:
    """
    Synthesize ML lexical predictions with explainable structural indicators,
    brand impersonation intelligence, URL encoding analysis, and public suffix registry data.
    Implements generalized non-punitive multi-signal risk calculation adhering strictly to
    standard security classifications without false positives.
    """
    normalized = normalize_url(raw_url)
    domain_info = extract_domain_info(normalized)
    brand_eval = detect_brand_impersonation(domain_info, normalized)
    anomalies = detect_structural_anomalies(domain_info, normalized)
    enc = normalized["encoding_info"]
    redir = normalized["redirect_info"]

    # Build categorized analysis entries
    # 1. URL Encoding Breakdown
    cat_encoding = []
    if enc["encoding_detected"]:
        cat_encoding.append("✓ Percent encoding detected")
        cat_encoding.append("✓ Decoded successfully")
        layer_str = "1 encoding layer" if enc["encoding_layers"] <= 1 else f"{enc['encoding_layers']} encoding layers"
        if enc["double_encoding_detected"]:
            cat_encoding.append(f"✓ Double encoding detected ({layer_str})")
        else:
            cat_encoding.append(f"✓ {layer_str}")
        if enc.get("decoded_content") and enc.get("decoded_content") != raw_url:
            cat_encoding.append(f"Decoded content: {enc['decoded_content']}")
    else:
        cat_encoding.append("✓ Standard URL (no percent encoding detected)")

    # 2. Authentication Breakdown
    cat_auth = []
    raw_lower = normalized["raw_url"].lower()
    decoded_lower = normalized["decoded_url"].lower()
    matched_creds = list(dict.fromkeys(
        [kw for kw in CREDENTIAL_KEYWORDS if kw in raw_lower] +
        [kw for kw in CREDENTIAL_KEYWORDS if kw in decoded_lower]
    ))
    if matched_creds:
        cat_auth.append(f"⚠ Login endpoint detected ({', '.join(matched_creds[:2])})")
    else:
        cat_auth.append("✓ No sensitive authentication endpoints detected")

    # 3. Redirect Analysis Breakdown
    cat_redirect = []
    if redir["redirect_detected"]:
        if redir["is_external"]:
            if redir["encoded_redirect_detected"]:
                cat_redirect.append("⚠ Encoded redirect detected")
            cat_redirect.append("⚠ External destination detected")
            cat_redirect.append(f"Destination domain: {redir['dest_host']}")
            if redir.get("destination_brand_impersonation"):
                cat_redirect.append(f"🚨 Destination impersonates brand: {redir['destination_brand']}")
            elif redir.get("destination_is_official"):
                cat_redirect.append(f"✓ Destination is verified official asset ({redir['destination_brand']})")
        else:
            if redir["encoded_redirect_detected"]:
                cat_redirect.append("✓ Encoded redirect detected")
            cat_redirect.append("✓ Decoded redirect remains on same domain")
            cat_redirect.append("✓ No external redirect detected")
    else:
        cat_redirect.append("✓ No external redirect detected")

    # 4. Brand Analysis Breakdown
    cat_brand = []
    if brand_eval["is_impersonation"]:
        cat_brand.append(f"🚨 Brand impersonation detected: {brand_eval['brand']}")
        cat_brand.append(brand_eval["details"])
    elif redir.get("destination_brand_impersonation"):
        cat_brand.append(f"🚨 Brand impersonation detected in redirect: {redir['destination_brand']}")
        cat_brand.append(redir.get("destination_brand_details") or f"Destination deceptively mimics {redir['destination_brand']}.")
    elif brand_eval["is_official"]:
        cat_brand.append(f"✓ Verified authoritative domain for {brand_eval['brand']}")
    else:
        cat_brand.append("✓ No brand impersonation detected")

    # 5. Domain Analysis Breakdown
    cat_domain = []
    cat_domain.append(f"✓ Registered domain: {domain_info['registered_domain']}")
    if domain_info.get("subdomain"):
        cat_domain.append(f"Subdomain: {domain_info['subdomain']}")
    if domain_info.get("is_ip"):
        cat_domain.append("⚠ Numeric IP address host")

    # Legacy category groups for UI cards
    cat_structure = [a["message"] for a in anomalies if a["vector"] == "domain_structure" or a["vector"] == "encoding_obfuscation"]
    cat_reputation = [a["message"] for a in anomalies if a["vector"] == "reputation_intelligence"]
    cat_model = []

    # Build categorized flags
    all_flags = []
    for c in cat_encoding:
        all_flags.append(f"URL Encoding: {c}")
    for c in cat_auth:
        all_flags.append(f"Authentication: {c}")
    for c in cat_redirect:
        all_flags.append(f"Redirect Analysis: {c}")
    for c in cat_brand:
        all_flags.append(f"Brand Analysis: {c}")
    for c in cat_domain:
        all_flags.append(f"Domain Analysis: {c}")

    # -------------------------------------------------------------
    # 1. Authoritative Domain Evaluation
    # -------------------------------------------------------------
    if brand_eval["is_official"] and not normalized["has_at_symbol"] and not domain_info["is_ip"]:
        risk_score = 2.5 if normalized["scheme"] == "https" else 15.0
        if normalized["port"] and normalized["port"] not in (80, 443):
            risk_score += 10.0

        risk_summary = f"Low Risk — verified official domain asset for {brand_eval['brand']}."
        all_flags.append(f"Risk Assessment: {risk_summary}")

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(risk_score, 2),
            "verdict": "Safe / Legitimate",
            "confidence_level": "Authoritative Safe",
            "brand_detected": brand_eval["brand"],
            "brand_association": f"{brand_eval['brand']} (Official Authoritative Domain)",
            "is_official_domain": True,
            "encoding_detected": enc["encoding_detected"],
            "encoding_layers": enc["encoding_layers"],
            "decoded_url": enc["decoded_url"],
            "decoded_path": enc["decoded_path"],
            "decoded_query": enc["decoded_query"],
            "encoded_redirect_detected": redir["encoded_redirect_detected"],
            "double_encoding_detected": enc["double_encoding_detected"],
            "decoded_content": enc["decoded_content"],
            "risk_contribution": enc["risk_contribution"],
            "encoding_details": enc,
            "redirect_details": redir,
            "destination_domain": redir.get("dest_host"),
            "destination_registered_domain": redir.get("destination_registered_domain"),
            "destination_subdomain": redir.get("destination_subdomain"),
            "destination_brand": redir.get("destination_brand"),
            "destination_brand_impersonation": False,
            "external_destination_detected": redir.get("is_external", False),
            "risk_summary": risk_summary,
            "category_breakdown": {
                "domain_structure": cat_structure if cat_structure else ["Standard TLS encryption verified."],
                "brand_impersonation": ["No brand impersonation detected (official company asset)."],
                "model_prediction": ["Authoritative reputation override applied."],
                "reputation_intelligence": [f"Verified authoritative domain for {brand_eval['brand']}."],
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "categorized_analysis": {
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "flags": all_flags
        }

    # -------------------------------------------------------------
    # 2. Host Brand Impersonation Scenario (Deceptive Subdomain / Lookalike)
    # -------------------------------------------------------------
    if brand_eval["is_impersonation"]:
        base_risk = float(brand_eval["risk_impact"])
        if matched_creds:
            base_risk += 4.0
        final_risk = min(max(base_risk, 76.0), 98.0)
        risk_summary = f"High Risk — brand impersonation of {brand_eval['brand']} detected."
        all_flags.append(f"Risk Assessment: {risk_summary}")

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(final_risk, 2),
            "verdict": "Suspicious / Brand Impersonation",
            "confidence_level": "High Suspicion (Brand Impersonation)",
            "brand_detected": brand_eval["brand"],
            "brand_association": f"{brand_eval['brand']} (Impersonation / Misleading Subdomain)",
            "is_official_domain": False,
            "encoding_detected": enc["encoding_detected"],
            "encoding_layers": enc["encoding_layers"],
            "decoded_url": enc["decoded_url"],
            "decoded_path": enc["decoded_path"],
            "decoded_query": enc["decoded_query"],
            "encoded_redirect_detected": redir["encoded_redirect_detected"],
            "double_encoding_detected": enc["double_encoding_detected"],
            "decoded_content": enc["decoded_content"],
            "risk_contribution": enc["risk_contribution"],
            "encoding_details": enc,
            "redirect_details": redir,
            "destination_domain": redir.get("dest_host"),
            "destination_registered_domain": redir.get("destination_registered_domain"),
            "destination_subdomain": redir.get("destination_subdomain"),
            "destination_brand": redir.get("destination_brand"),
            "destination_brand_impersonation": False,
            "external_destination_detected": redir.get("is_external", False),
            "risk_summary": risk_summary,
            "category_breakdown": {
                "domain_structure": cat_structure if cat_structure else ["Misleading subdomain hierarchy mimics external domain."],
                "brand_impersonation": cat_brand,
                "model_prediction": ["Elevated risk due to deceptive brand mimicry."],
                "reputation_intelligence": [f"Domain '{domain_info['registered_domain']}' has no verified affiliation with {brand_eval['brand']}."],
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "categorized_analysis": {
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "flags": all_flags
        }

    # -------------------------------------------------------------
    # 3. Redirect Brand Impersonation Scenario (Case F)
    # -------------------------------------------------------------
    if redir.get("destination_brand_impersonation"):
        dest_brand = redir.get("destination_brand")
        base_risk = 78.0
        if matched_creds:
            base_risk += 4.0
        final_risk = min(max(base_risk, 76.0), 96.0)
        risk_summary = f"High Risk — redirect destination targets brand impersonation of {dest_brand}."
        all_flags.append(f"Risk Assessment: {risk_summary}")

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(final_risk, 2),
            "verdict": "Suspicious / Brand Impersonation",
            "confidence_level": "High Suspicion (Redirect Brand Impersonation)",
            "brand_detected": dest_brand,
            "brand_association": f"{dest_brand} (Impersonation in Redirect Destination)",
            "is_official_domain": False,
            "encoding_detected": enc["encoding_detected"],
            "encoding_layers": enc["encoding_layers"],
            "decoded_url": enc["decoded_url"],
            "decoded_path": enc["decoded_path"],
            "decoded_query": enc["decoded_query"],
            "encoded_redirect_detected": redir["encoded_redirect_detected"],
            "double_encoding_detected": enc["double_encoding_detected"],
            "decoded_content": enc["decoded_content"],
            "risk_contribution": "High",
            "encoding_details": enc,
            "redirect_details": redir,
            "destination_domain": redir.get("dest_host"),
            "destination_registered_domain": redir.get("destination_registered_domain"),
            "destination_subdomain": redir.get("destination_subdomain"),
            "destination_brand": dest_brand,
            "destination_brand_impersonation": True,
            "external_destination_detected": True,
            "risk_summary": risk_summary,
            "category_breakdown": {
                "domain_structure": cat_structure if cat_structure else ["Redirect parameter points to spoofed domain."],
                "brand_impersonation": cat_brand,
                "model_prediction": ["Elevated risk due to deceptive brand mimicry in redirect target."],
                "reputation_intelligence": [f"Destination domain '{redir.get('dest_host')}' mimics {dest_brand} under unrelated registered domain '{redir.get('destination_registered_domain')}'."],
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "categorized_analysis": {
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "flags": all_flags
        }

    # -------------------------------------------------------------
    # 4. Structural Malicious Vectors on Host (Raw IP, @ Obfuscation)
    # -------------------------------------------------------------
    if domain_info["is_ip"] or normalized["has_at_symbol"]:
        final_risk = 88.0
        risk_summary = "High Risk — raw IP or credential obfuscation vector detected."
        all_flags.append(f"Risk Assessment: {risk_summary}")

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(final_risk, 2),
            "verdict": "Phishing / Malicious",
            "confidence_level": "High Risk (Critical Structural Vector)",
            "brand_detected": None,
            "brand_association": "None / Direct Network Host",
            "is_official_domain": False,
            "encoding_detected": enc["encoding_detected"],
            "encoding_layers": enc["encoding_layers"],
            "decoded_url": enc["decoded_url"],
            "decoded_path": enc["decoded_path"],
            "decoded_query": enc["decoded_query"],
            "encoded_redirect_detected": redir["encoded_redirect_detected"],
            "double_encoding_detected": enc["double_encoding_detected"],
            "decoded_content": enc["decoded_content"],
            "risk_contribution": enc["risk_contribution"],
            "encoding_details": enc,
            "redirect_details": redir,
            "destination_domain": redir.get("dest_host"),
            "destination_registered_domain": redir.get("destination_registered_domain"),
            "destination_subdomain": redir.get("destination_subdomain"),
            "destination_brand": redir.get("destination_brand"),
            "destination_brand_impersonation": False,
            "external_destination_detected": redir.get("is_external", False),
            "risk_summary": risk_summary,
            "category_breakdown": {
                "domain_structure": cat_structure,
                "brand_impersonation": ["No targeted brand identified in host."],
                "model_prediction": ["Structural threat indicators override lexical model."],
                "reputation_intelligence": ["Direct IP or obfuscated host bypasses domain registry."],
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "categorized_analysis": {
                "url_encoding": cat_encoding,
                "authentication": cat_auth,
                "redirect_analysis": cat_redirect,
                "brand_analysis": cat_brand,
                "domain_analysis": cat_domain,
                "risk_assessment": [risk_summary]
            },
            "flags": all_flags
        }

    # -------------------------------------------------------------
    # 5. Standard Domain Evaluation (Combining ML + Structural Indicators)
    # -------------------------------------------------------------
    structural_deltas = sum(a["risk_delta"] for a in anomalies)
    if structural_deltas == 0:
        computed_risk = 5.0
        if ml_model_probability is not None:
            computed_risk += min(ml_model_probability * 0.05, 3.0)
        risk_summary = "Low Risk — no strong phishing indicators detected."
        verdict = "Safe / Legitimate"
        confidence_level = "Low Risk"
    elif structural_deltas <= 15:
        computed_risk = 8.0 + structural_deltas
        if ml_model_probability is not None:
            computed_risk += min(ml_model_probability * 0.05, 5.0)
        computed_risk = min(computed_risk, 28.0)
        risk_summary = "Low Risk — no strong phishing indicators detected."
        verdict = "Safe / Legitimate"
        confidence_level = "Low Risk"
    elif structural_deltas < 40:
        computed_risk = 15.0 + (structural_deltas * 0.65)
        if ml_model_probability is not None:
            computed_risk += min(ml_model_probability * 0.04, 4.0)
        computed_risk = min(computed_risk, 42.0)
        risk_summary = "Moderate Risk — unusual encoding or parameters detected without brand impersonation."
        verdict = "Safe / Legitimate"
        confidence_level = "Moderate Risk"
    else:
        computed_risk = min(52.0 + (structural_deltas - 40) * 0.8, 88.0)
        risk_summary = "High Risk — multiple suspicious structural vectors detected."
        verdict = "Phishing / Malicious"
        confidence_level = "High Risk (Multiple Structural Anomalies)"

    all_flags.append(f"Risk Assessment: {risk_summary}")
    cat_model.append(f"ML XGBoost lexical classifier: {ml_model_probability:.1f}% baseline." if ml_model_probability is not None else "Heuristic structural analyzer applied.")

    return {
        "target_url": raw_url,
        "canonical_url": normalized["canonical_url"],
        "hostname": domain_info["hostname"],
        "registered_domain": domain_info["registered_domain"],
        "subdomain": domain_info["subdomain"],
        "risk_percentage": round(computed_risk, 2),
        "verdict": verdict,
        "confidence_level": confidence_level,
        "brand_detected": None,
        "brand_association": "None / Standard Domain",
        "is_official_domain": False,
        "encoding_detected": enc["encoding_detected"],
        "encoding_layers": enc["encoding_layers"],
        "decoded_url": enc["decoded_url"],
        "decoded_path": enc["decoded_path"],
        "decoded_query": enc["decoded_query"],
        "encoded_redirect_detected": redir["encoded_redirect_detected"],
        "double_encoding_detected": enc["double_encoding_detected"],
        "decoded_content": enc["decoded_content"],
        "risk_contribution": enc["risk_contribution"],
        "encoding_details": enc,
        "redirect_details": redir,
        "destination_domain": redir.get("dest_host"),
        "destination_registered_domain": redir.get("destination_registered_domain"),
        "destination_subdomain": redir.get("destination_subdomain"),
        "destination_brand": redir.get("destination_brand"),
        "destination_brand_impersonation": False,
        "external_destination_detected": redir.get("is_external", False),
        "risk_summary": risk_summary,
        "category_breakdown": {
            "domain_structure": cat_structure if cat_structure else ["Standard domain topology and clean syntax."],
            "brand_impersonation": cat_brand,
            "model_prediction": cat_model,
            "reputation_intelligence": cat_reputation if cat_reputation else ["Standard registered public suffix."],
            "url_encoding": cat_encoding,
            "authentication": cat_auth,
            "redirect_analysis": cat_redirect,
            "brand_analysis": cat_brand,
            "domain_analysis": cat_domain,
            "risk_assessment": [risk_summary]
        },
        "categorized_analysis": {
            "url_encoding": cat_encoding,
            "authentication": cat_auth,
            "redirect_analysis": cat_redirect,
            "brand_analysis": cat_brand,
            "domain_analysis": cat_domain,
            "risk_assessment": [risk_summary]
        },
        "flags": all_flags
    }
