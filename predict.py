"""
predict.py — Command-line phishing URL checker.
Usage: python predict.py <url>
       python predict.py <url> --json
       python predict.py --batch urls.txt
"""

import sys
import json
import argparse

import joblib
import pandas as pd

from feature import extract_features, FEATURE_COLUMNS

_bundle  = joblib.load("model.pkl")
model    = _bundle["model"]
features = _bundle["features"]


def predict(url: str) -> dict:
    url = url.strip()
    raw = extract_features(url)
    fmap = dict(zip(FEATURE_COLUMNS, raw))
    row  = [[fmap[col] for col in features]]
    df   = pd.DataFrame(row, columns=features)
    cls  = int(model.predict(df)[0])
    prob = float(model.predict_proba(df)[0][1])
    return {
        "url":        url,
        "prediction": "phishing" if cls == 1 else "safe",
        "confidence": round(prob * 100, 1),
    }


def format_result(r: dict) -> str:
    icon = "⚠" if r["prediction"] == "phishing" else "✓"
    return (
        f"{icon}  {r['prediction'].upper():<10} "
        f"confidence: {r['confidence']}%   {r['url']}"
    )


def main():
    parser = argparse.ArgumentParser(description="Phishing URL detector CLI")
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--batch", metavar="FILE", help="Check URLs from a file (one per line)")
    args = parser.parse_args()

    if args.batch:
        with open(args.batch) as fh:
            urls = [line.strip() for line in fh if line.strip()]
        results = [predict(u) for u in urls]
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print(format_result(r))
        phishing_count = sum(1 for r in results if r["prediction"] == "phishing")
        print(f"\n{phishing_count}/{len(results)} URLs flagged as phishing.")
    elif args.url:
        r = predict(args.url)
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print(format_result(r))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
