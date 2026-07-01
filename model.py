"""
model.py — Train the phishing URL classifier.
Run this once to produce model.pkl.
Requires: dataset.csv with a 'target' column (1=phishing, 0=safe).
"""

import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import numpy as np

from feature import FEATURE_COLUMNS  # single source of truth for column names

data = pd.read_csv("dataset.csv")

# ── Select only columns that exist in this dataset ─────────────────────────
available = [c for c in FEATURE_COLUMNS if c in data.columns]
missing   = [c for c in FEATURE_COLUMNS if c not in data.columns]
if missing:
    print(f"[warn] These features are missing from dataset (will be skipped): {missing}")

X = data[available]
y = data["target"]

# ── Split ───────────────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train ───────────────────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=4,
    class_weight="balanced",   # handles imbalanced datasets
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)

# ── Evaluate ────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
print(f"\n5-Fold CV F1: {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

# ── Feature importance ──────────────────────────────────────────────────────
importances = sorted(
    zip(available, model.feature_importances_),
    key=lambda x: x[1], reverse=True
)
print("\n=== Feature Importances ===")
for name, imp in importances:
    bar = "█" * int(imp * 40)
    print(f"  {name:<20} {bar} {imp:.4f}")

# ── Save ────────────────────────────────────────────────────────────────────
joblib.dump({"model": model, "features": available}, "model.pkl")
print("\n[ok] model.pkl saved.")
