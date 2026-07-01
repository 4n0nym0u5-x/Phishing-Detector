"""
main.py — Flask web app + REST API for the phishing URL detector.
Loads model.pkl once at startup. No training here.
"""

import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template, abort

from feature import extract_features, FEATURE_COLUMNS, BRAND_KEYWORDS, SUSPICIOUS_TLDS

app = Flask(__name__)

# ── Load model ───────────────────────────────────────────────────────────────
_bundle   = joblib.load("model.pkl")
model     = _bundle["model"]
features  = _bundle["features"]   # list of column names the model was trained on


# ── Heuristic engine ─────────────────────────────────────────────────────────

def heuristic_check(url: str) -> dict:
    """
    Returns a weighted heuristic score and a list of triggered rules.
    Score is intentionally NOT used to override ML — it's a secondary signal.
    """
    score  = 0
    rules  = []
    lower  = url.lower()

    if "@" in url:
        score += 2
        rules.append("Contains @ symbol (credential harvesting pattern)")

    if len(url) > 100:
        score += 2
        rules.append(f"Unusually long URL ({len(url)} chars)")
    elif len(url) > 75:
        score += 1
        rules.append(f"Long URL ({len(url)} chars)")

    from urllib.parse import urlparse
    try:
        netloc = urlparse(url if "://" in url else "http://" + url).netloc
    except Exception:
        netloc = ""

    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", netloc):
        score += 3
        rules.append("IP address used as domain (no registered domain name)")

    subdomains = netloc.split(".")
    if len(subdomains) > 4:
        score += 2
        rules.append(f"Deep subdomain nesting ({len(subdomains) - 2} levels)")

    matched_brands = [kw for kw in BRAND_KEYWORDS if kw in lower]
    if matched_brands:
        score += len(matched_brands)
        rules.append(f"Brand/sensitive keywords detected: {', '.join(matched_brands[:5])}")

    if any(lower.endswith(tld) or ("/" + tld[1:] + "/") in lower for tld in SUSPICIOUS_TLDS):
        score += 2
        rules.append("Suspicious TLD (commonly used in phishing)")

    if any(p in lower for p in ["?url=", "?redirect=", "?next=", "?goto="]):
        score += 2
        rules.append("Redirect parameter in URL")

    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digit_ratio > 0.3:
        score += 1
        rules.append(f"High digit ratio ({digit_ratio:.0%} of URL is digits)")

    return {"score": score, "rules": rules}


# ── Shared prediction logic ──────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """Single source of truth for prediction — used by both routes."""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if len(url) > 2048:
        raise ValueError("URL exceeds maximum length (2048 chars)")

    raw_features = extract_features(url)
    feature_map  = dict(zip(FEATURE_COLUMNS, raw_features))

    # Use only the columns the model was trained on
    row = [[feature_map[col] for col in features]]
    df  = pd.DataFrame(row, columns=features)

    ml_class      = int(model.predict(df)[0])
    ml_confidence = float(model.predict_proba(df)[0][1])   # P(phishing)

    heuristic = heuristic_check(url)
    h_score   = heuristic["score"]

    # ── Combined decision ──────────────────────────────────────────────────
    # Both ML confidence and heuristic inform the outcome.
    # Neither overrides the other outright — they are combined.
    if ml_confidence >= 0.75 or h_score >= 5:
        verdict = "phishing"
        risk    = "high"
    elif ml_confidence >= 0.50 or h_score >= 3:
        verdict = "phishing"
        risk    = "medium"
    elif ml_confidence >= 0.35 or h_score >= 2:
        verdict = "suspicious"
        risk    = "low"
    else:
        verdict = "safe"
        risk    = "none"

    return {
        "url":            url,
        "verdict":        verdict,
        "risk_level":     risk,
        "ml_confidence":  round(ml_confidence * 100, 1),
        "heuristic_score": h_score,
        "heuristic_rules": heuristic["rules"],
        "features":       feature_map,
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/predict", methods=["POST"])
def api_predict():
    """JSON API endpoint. POST {"url": "..."} → prediction object."""
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must be JSON with a 'url' key"}), 400
    try:
        result = predict_url(data["url"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        app.logger.exception("Prediction failed")
        return jsonify({"error": "Internal prediction error"}), 500
    return jsonify(result)


@app.route("/", methods=["GET", "POST"])
def home():
    """Web UI. GET → form; POST → form + result."""
    result = None
    error  = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        try:
            result = predict_url(url)
        except ValueError as e:
            error = str(e)
        except Exception:
            error = "Something went wrong. Please try again."
    return render_template("index.html", result=result, error=error)


if __name__ == "__main__":
    # debug=False in production. Use Gunicorn/uWSGI when deploying.
    app.run(debug=False, host="127.0.0.1", port=5000)
