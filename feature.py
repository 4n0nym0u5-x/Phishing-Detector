"""
feature.py — Enhanced URL feature extraction
Extracts 18 signals from a raw URL string.
"""

import re
import math
from urllib.parse import urlparse


# Brand keywords commonly impersonated in phishing URLs
BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "bank", "chase", "wellsfargo", "citibank",
    "verify", "account", "update", "confirm", "signin", "login",
    "secure", "support", "billing", "password", "credential",
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work"]


def _url_entropy(url: str) -> float:
    """Shannon entropy of the URL string — high entropy suggests randomness."""
    if not url:
        return 0.0
    freq = {}
    for ch in url:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(url)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_features(url: str) -> list:
    """
    Extract 18 numeric features from a URL string.
    Returns a list in the exact order expected by the trained model.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("")

    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()
    subdomains = netloc.split(".")

    # --- Original 10 features (preserved for model compatibility) ---
    url_length     = len(url)
    nb_dots        = url.count(".")
    at_symbol      = 1 if "@" in url else 0
    nb_hyphens     = url.count("-")
    is_https       = 1 if url.lower().startswith("https") else 0
    nb_www         = 1 if netloc.startswith("www.") else 0
    nb_com         = 1 if netloc.endswith(".com") else 0
    nb_underscore  = url.count("_")
    nb_and         = url.count("&")
    nb_or          = url.count("|")           # kept for backward compat

    # --- 8 new enhanced features ---
    has_ip         = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", netloc) else 0
    subdomain_depth = max(0, len(subdomains) - 2)   # e.g. a.b.example.com → 2
    digit_ratio    = sum(c.isdigit() for c in url) / max(len(url), 1)
    path_length    = len(path)
    brand_match    = 1 if any(kw in full for kw in BRAND_KEYWORDS) else 0
    has_port       = 1 if parsed.port and parsed.port not in (80, 443) else 0
    has_redirect   = 1 if any(p in url.lower() for p in ["?url=", "?redirect=", "?next=", "?goto="]) else 0
    entropy        = round(_url_entropy(url), 4)

    return [
        url_length,
        nb_dots,
        at_symbol,
        nb_hyphens,
        is_https,
        nb_www,
        nb_com,
        nb_underscore,
        nb_and,
        nb_or,
        has_ip,
        subdomain_depth,
        round(digit_ratio, 4),
        path_length,
        brand_match,
        has_port,
        has_redirect,
        entropy,
    ]


FEATURE_COLUMNS = [
    "url_length",
    "nb_dots",
    "at_symbol",
    "nb_hyphens",
    "is_https",
    "nb_www",
    "nb_com",
    "nb_underscore",
    "nb_and",
    "nb_or",
    "has_ip",
    "subdomain_depth",
    "digit_ratio",
    "path_length",
    "brand_match",
    "has_port",
    "has_redirect",
    "entropy",
]
