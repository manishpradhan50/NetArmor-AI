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
def normalize_url(raw_url: str) -> dict:
    """
    Clean, validate, and normalize input URL into canonical parts.
    Handles missing schemes, percent encoding, userinfo (@), and port numbers.
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
            # Ensure it's not an IPv6 address without brackets
            if p_temp.isdigit():
                port = int(p_temp)
                host = h_temp
        except Exception:
            pass

    # Normalize hostname
    host = unquote(host).strip().lower().rstrip(".")

    # Remove enclosing IPv6 brackets if any
    clean_host = host.strip("[]")

    if not clean_host:
        raise ValueError("URL must contain a valid non-empty hostname.")

    canonical_url = f"{scheme}://{host}"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        canonical_url += f":{port}"
    if parts.path:
        canonical_url += parts.path
    if parts.query:
        canonical_url += f"?{parts.query}"
    if parts.fragment:
        canonical_url += f"#{parts.fragment}"

    return {
        "raw_url": raw_url,
        "canonical_url": canonical_url,
        "scheme": scheme,
        "hostname": clean_host,
        "port": port,
        "userinfo": userinfo,
        "has_at_symbol": "@" in raw_url,
        "path": parts.path or "/",
        "query": parts.query or "",
        "fragment": parts.fragment or ""
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
    credential keywords, @ signs, insecure protocol, and suspicious TLDs.
    """
    anomalies = []

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
            "risk_delta": 20,
            "message": f"Connects over an unusual non-standard network port (:{port})."
        })

    # 4. Excessive subdomains (depth check)
    sub_labels = domain_info.get("subdomain_labels", [])
    if len(sub_labels) >= 3:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 18,
            "message": f"Excessive subdomain depth detected ({len(sub_labels)} sub-levels in host)."
        })

    # 5. Excessive hyphens in hostname
    host = domain_info["hostname"]
    if host.count("-") >= 3:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 15,
            "message": f"Unusually high hyphen count in hostname ({host.count('-')} hyphens)."
        })

    # 6. Abusive / suspicious TLD
    suffix = domain_info.get("suffix", "").lower()
    if suffix in SUSPICIOUS_TLDS:
        anomalies.append({
            "vector": "reputation_intelligence",
            "severity": "medium",
            "risk_delta": 22,
            "message": f"Uses high-risk top-level domain (.{suffix}) frequently associated with phishing."
        })

    # 7. Sensitive credential-harvesting keywords
    raw_lower = normalized["raw_url"].lower()
    matched_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in raw_lower]
    if matched_keywords:
        anomalies.append({
            "vector": "domain_structure",
            "severity": "medium",
            "risk_delta": 20,
            "message": f"Contains sensitive auth/credential keywords: {', '.join(matched_keywords[:3])}."
        })

    # 8. Protocol security check (Insecure HTTP)
    if normalized["scheme"] == "http":
        anomalies.append({
            "vector": "domain_structure",
            "severity": "low",
            "risk_delta": 10,
            "message": "Insecure HTTP protocol (missing SSL/TLS transport encryption)."
        })

    return anomalies


# ---------------------------------------------------------------------------
# Multi-Vector Risk Synthesis & Evaluation Engine
# ---------------------------------------------------------------------------
def evaluate_url_security(raw_url: str, ml_model_probability: float | None = None) -> dict:
    """
    Synthesize ML lexical predictions with explainable structural indicators,
    brand impersonation intelligence, and public suffix registry data.
    """
    normalized = normalize_url(raw_url)
    domain_info = extract_domain_info(normalized)
    brand_eval = detect_brand_impersonation(domain_info, normalized)
    anomalies = detect_structural_anomalies(domain_info, normalized)

    # Categories for UI and API reporting
    cat_structure = []
    cat_brand = []
    cat_model = []
    cat_reputation = []
    all_flags = []

    # 1. Authoritative Domain Evaluation
    if brand_eval["is_official"] and not normalized["has_at_symbol"] and not domain_info["is_ip"]:
        risk_score = 2.5 if normalized["scheme"] == "https" else 15.0
        if normalized["port"] and normalized["port"] not in (80, 443):
            risk_score += 10.0

        cat_reputation.append(f"Verified authoritative domain for {brand_eval['brand']}.")
        if normalized["scheme"] == "https":
            cat_structure.append("Standard TLS encryption verified.")
        else:
            cat_structure.append("Missing SSL/TLS encryption (plaintext HTTP).")

        all_flags.append(f"Verified authoritative domain for {brand_eval['brand']}.")
        if normalized["scheme"] != "https":
            all_flags.append("Insecure HTTP protocol detected on authoritative domain.")

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
            "category_breakdown": {
                "domain_structure": cat_structure,
                "brand_impersonation": ["No brand impersonation detected (official company asset)."],
                "model_prediction": ["Authoritative reputation override applied."],
                "reputation_intelligence": cat_reputation
            },
            "flags": all_flags
        }

    # 2. Brand Impersonation Scenario (Deceptive subdomains, typosquatting)
    if brand_eval["is_impersonation"]:
        base_risk = float(brand_eval["risk_impact"])
        cat_brand.append(brand_eval["details"])
        all_flags.append(brand_eval["details"])

        # Add anomaly indicators
        for a in anomalies:
            if a["vector"] == "domain_structure":
                cat_structure.append(a["message"])
            elif a["vector"] == "reputation_intelligence":
                cat_reputation.append(a["message"])
            all_flags.append(a["message"])

        # Extra risk for credential terms on impersonated domains
        matched_creds = [kw for kw in CREDENTIAL_KEYWORDS if kw in normalized["raw_url"].lower()]
        if matched_creds:
            base_risk += 8.0

        if normalized["scheme"] == "http":
            base_risk += 4.0

        # Incorporate ML model score if available
        if ml_model_probability is not None:
            cat_model.append(
                f"ML lexical model baseline: {ml_model_probability:.1f}% "
                f"(risk elevated due to brand impersonation indicators)."
            )
            final_risk = max(base_risk, ml_model_probability)
        else:
            final_risk = base_risk

        final_risk = min(max(final_risk, 76.0), 98.0)
        verdict = "Suspicious / Brand Impersonation"
        confidence_level = "High Suspicion (Brand Impersonation)"

        cat_reputation.append(
            f"Domain '{domain_info['registered_domain']}' has no verified affiliation with {brand_eval['brand']}."
        )

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(final_risk, 2),
            "verdict": verdict,
            "confidence_level": confidence_level,
            "brand_detected": brand_eval["brand"],
            "brand_association": f"{brand_eval['brand']} (Impersonation / Misleading Subdomain)",
            "is_official_domain": False,
            "category_breakdown": {
                "domain_structure": cat_structure if cat_structure else ["Misleading subdomain hierarchy mimics external domain."],
                "brand_impersonation": cat_brand,
                "model_prediction": cat_model if cat_model else ["Elevated risk due to deceptive brand mimicry."],
                "reputation_intelligence": cat_reputation
            },
            "flags": all_flags
        }

    # 3. Structural Malicious Vectors (Raw IP, @ Obfuscation)
    if domain_info["is_ip"] or normalized["has_at_symbol"]:
        base_risk = 85.0
        for a in anomalies:
            if a["vector"] == "domain_structure":
                cat_structure.append(a["message"])
            elif a["vector"] == "reputation_intelligence":
                cat_reputation.append(a["message"])
            all_flags.append(a["message"])

        if ml_model_probability is not None:
            cat_model.append(f"ML lexical model output: {ml_model_probability:.1f}%.")
            final_risk = max(base_risk, ml_model_probability)
        else:
            final_risk = base_risk

        final_risk = min(final_risk, 99.0)
        verdict = "Phishing / Malicious"
        confidence_level = "High Risk (Critical Structural Vector)"

        return {
            "target_url": raw_url,
            "canonical_url": normalized["canonical_url"],
            "hostname": domain_info["hostname"],
            "registered_domain": domain_info["registered_domain"],
            "subdomain": domain_info["subdomain"],
            "risk_percentage": round(final_risk, 2),
            "verdict": verdict,
            "confidence_level": confidence_level,
            "brand_detected": None,
            "brand_association": "None / Direct Network Host",
            "is_official_domain": False,
            "category_breakdown": {
                "domain_structure": cat_structure,
                "brand_impersonation": ["No targeted brand identified in host."],
                "model_prediction": cat_model if cat_model else ["Structural threat indicators override lexical model."],
                "reputation_intelligence": cat_reputation if cat_reputation else ["Direct IP or obfuscated host bypasses domain registry."]
            },
            "flags": all_flags
        }

    # 4. Standard Domain Evaluation (Combining ML model + Structural Indicators)
    structural_deltas = sum(a["risk_delta"] for a in anomalies)
    for a in anomalies:
        if a["vector"] == "domain_structure":
            cat_structure.append(a["message"])
        elif a["vector"] == "reputation_intelligence":
            cat_reputation.append(a["message"])
        all_flags.append(a["message"])

    if ml_model_probability is not None:
        cat_model.append(f"ML XGBoost lexical classifier: {ml_model_probability:.1f}% baseline.")
        # Guard against ML model single-dot artifact when zero suspicious indicators exist
        if structural_deltas == 0 and normalized["scheme"] == "https":
            computed_risk = min(ml_model_probability, 15.0)
        elif structural_deltas <= 10 and normalized["scheme"] == "https":
            computed_risk = min(ml_model_probability * 0.35 + structural_deltas, 35.0)
        else:
            computed_risk = (ml_model_probability * 0.45) + (min(structural_deltas, 70.0) * 0.55)
    else:
        cat_model.append("Heuristic structural analyzer applied (ML model offline).")
        computed_risk = 8.0 + min(structural_deltas, 75.0)

    computed_risk = min(max(computed_risk, 2.5), 98.0)
    verdict = "Phishing / Malicious" if computed_risk >= 50.0 else "Safe / Legitimate"
    confidence_level = "Estimated Threat Risk" if computed_risk >= 50.0 else "Low Risk"

    if not all_flags:
        all_flags.append("No suspicious structural or brand anomalies detected.")
    if not cat_structure:
        cat_structure.append("Standard domain topology and clean syntax.")
    if not cat_brand:
        cat_brand.append("No brand impersonation or trademark mimicry discovered.")
    if not cat_reputation:
        cat_reputation.append("Standard registered public suffix.")

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
        "category_breakdown": {
            "domain_structure": cat_structure,
            "brand_impersonation": cat_brand,
            "model_prediction": cat_model,
            "reputation_intelligence": cat_reputation
        },
        "flags": all_flags
    }
