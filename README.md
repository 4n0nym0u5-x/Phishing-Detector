# Phishing Detector — Enhanced Version

## File structure

```
phishing-detector/
├── dataset.csv          # Training data (needs 'target' column)
├── feature.py           # URL feature extractor — 18 signals
├── model.py             # Training script → produces model.pkl
├── main.py              # Flask web app + REST API
├── predict.py           # CLI tool
└── templates/
    └── index.html       # Rich web UI
```

## Setup

```bash
pip install flask scikit-learn pandas joblib
python model.py          # train and save model.pkl
python main.py           # start web server at http://127.0.0.1:5000
```

## CLI usage

```bash
python predict.py https://example.com
python predict.py https://example.com --json
python predict.py --batch urls.txt
python predict.py --batch urls.txt --json
```

## API usage

```bash
curl -X POST http://127.0.0.1:5000/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-secure-login.tk/verify"}'
```

Response:
```json
{
  "url": "http://paypal-secure-login.tk/verify",
  "verdict": "phishing",
  "risk_level": "high",
  "ml_confidence": 97.3,
  "heuristic_score": 6,
  "heuristic_rules": ["Brand/sensitive keywords detected: paypal, secure, login", "Suspicious TLD"],
  "features": { ... }
}
```

## Key improvements over original

| Area | Original | Enhanced |
|------|----------|----------|
| Feature count | 10 (weak) | 18 (+ IP, subdomain depth, entropy, digit ratio, redirect params) |
| Heuristic | 4 binary checks | Weighted multi-rule engine |
| Decision logic | Heuristic overrides ML | ML confidence + heuristic combined |
| RF output | Binary class only | Probability score exposed |
| Model training | Basic RF 200 trees | RF 300, class_weight=balanced, 5-fold CV, feature importance report |
| Flask security | debug=True, no validation | debug=False, input validation, error handling |
| CLI | Single URL only | Single URL, --json flag, --batch file mode |
| DRY | Logic duplicated in 2 routes | Single predict_url() function |
| Web UI | Minimal form + colored label | Confidence bar, heuristic flags, feature grid |
