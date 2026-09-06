"""
train_classifier.py — Train and serialize the ML phishing classifier.

Run once (or after dataset updates):
    python train_classifier.py

What this does:
  1. Loads Nazario_5.csv (primary dataset — has subject, body, sender, URLs)
  2. Optionally augments with email_text.csv body text (larger corpus, body-only)
     Decision rationale: email_text.csv has ~53k rows vs 3k in Nazario — adding it
     gives the TF-IDF a much richer vocabulary. Label semantics are compatible
     (binary 0/1 phishing), but documented as different source.
  3. Trains TF-IDF (max 10k features, 1-2 ngrams, sublinear TF) + Logistic Regression
  4. Reports real accuracy metrics (stratified k-fold cross-validation + held-out test)
  5. Saves pipeline to models/classifier.pkl

IMPORTANT: This script only trains on REAL dataset labels (0=legitimate, 1=phishing).
No sub-type labels (impersonated, BEC, credential-harvest) exist in these datasets —
those are handled by the heuristic sub-classifier in content_classifier.py.
"""

import logging
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=UserWarning)

# ---------------------------------------------------------------------------
# Paths — always use pathlib.Path
# ---------------------------------------------------------------------------
PROJECT_ROOT    = Path(__file__).parent
SOURCE_DIR      = Path(r"C:\Users\JHANI\OneDrive\Documents\SIH\New folder")
NAZARIO_CSV     = SOURCE_DIR / "Nazario_5.csv"
EMAIL_TEXT_CSV  = SOURCE_DIR / "email_text.csv"
MODEL_PATH      = PROJECT_ROOT / "models" / "classifier.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Training configuration
# ---------------------------------------------------------------------------
TFIDF_MAX_FEATURES = 10_000
TFIDF_NGRAM_RANGE  = (1, 2)
TEST_SIZE          = 0.20    # 80/20 train/test split
RANDOM_STATE       = 42
CV_FOLDS           = 5

# How many rows to sample from email_text.csv for augmentation
# Capped to avoid dominating the Nazario training signal
EMAIL_TEXT_AUGMENT_ROWS = 10_000


def load_nazario(path: Path) -> pd.DataFrame:
    """
    Load Nazario_5.csv and build feature text as 'subject + body'.
    Returns DataFrame with columns: text (str), label (int).
    """
    df = pd.read_csv(path)
    log.info("Nazario_5.csv: %d rows loaded, columns: %s", len(df), list(df.columns))

    # Drop rows with null body (0 nulls confirmed, but defensive)
    df = df.dropna(subset=["body"])

    # Feature: subject + body (concat with space; handle null subject)
    df["subject"] = df["subject"].fillna("")
    df["text"] = df["subject"].str.strip() + " " + df["body"].str.strip()
    df["label"] = df["label"].astype(int)

    log.info(
        "Nazario label distribution: %s",
        df["label"].value_counts().to_dict(),
    )
    return df[["text", "label"]]


def load_email_text(path: Path, max_rows: int = EMAIL_TEXT_AUGMENT_ROWS) -> pd.DataFrame:
    """
    Load email_text.csv for augmentation.
    Has only 2 columns: label (0/1), text (body only).
    Samples up to max_rows rows stratified by label.

    NOTE: This dataset's label 0 = legitimate, 1 = spam/phishing.
    Semantics are compatible with Nazario binary labels.
    Source is documented in the returned DataFrame's source column.
    """
    if not path.exists():
        log.warning("email_text.csv not found at %s — skipping augmentation", path)
        return pd.DataFrame(columns=["text", "label"])

    df = pd.read_csv(path, nrows=max_rows * 2)  # read extra, then sample
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    # Stratified sample to cap rows while preserving label balance
    per_class = max_rows // 2
    df_sample = pd.concat([
        df[df["label"] == 0].sample(n=min(per_class, (df["label"] == 0).sum()), random_state=RANDOM_STATE),
        df[df["label"] == 1].sample(n=min(per_class, (df["label"] == 1).sum()), random_state=RANDOM_STATE),
    ]).reset_index(drop=True)

    log.info(
        "email_text.csv augmentation: %d rows sampled, label dist: %s",
        len(df_sample),
        df_sample["label"].value_counts().to_dict(),
    )
    return df_sample[["text", "label"]]


def build_pipeline() -> Pipeline:
    """
    Construct the sklearn Pipeline: TfidfVectorizer → LogisticRegression.

    TF-IDF settings:
      - max_features=10000: limits vocabulary to top 10k terms by TF-IDF score
      - ngram_range=(1,2): unigrams + bigrams (captures "wire transfer", "click here")
      - sublinear_tf=True: apply log(1+tf) normalization to reduce impact of term frequency
      - strip_accents='unicode': handles unicode/accented characters in international phishing

    Logistic Regression settings:
      - class_weight='balanced': adjusts for any class imbalance automatically
      - max_iter=1000: sufficient for convergence on this dataset size
      - C=1.0: default regularization strength (tunable if needed)
      - solver='lbfgs': efficient for medium-sized text datasets
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=TFIDF_MAX_FEATURES,
            ngram_range=TFIDF_NGRAM_RANGE,
            sublinear_tf=True,
            strip_accents="unicode",
            min_df=2,          # ignore terms appearing in fewer than 2 documents
            token_pattern=r"(?u)\b\w\w+\b",  # minimum 2-char tokens
        )),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
            random_state=RANDOM_STATE,
        )),
    ])


def train_and_evaluate() -> None:
    # ------------------------------------------------------------------
    # 1. Load data
    # ------------------------------------------------------------------
    df_nazario    = load_nazario(NAZARIO_CSV)
    df_email_text = load_email_text(EMAIL_TEXT_CSV, max_rows=EMAIL_TEXT_AUGMENT_ROWS)

    if len(df_email_text) > 0:
        df_combined = pd.concat([df_nazario, df_email_text], ignore_index=True)
        log.info(
            "Combined dataset: %d rows (%d Nazario + %d email_text augmentation)",
            len(df_combined), len(df_nazario), len(df_email_text),
        )
    else:
        df_combined = df_nazario
        log.info("Using Nazario_5.csv only (%d rows)", len(df_combined))

    X = df_combined["text"].values
    y = df_combined["label"].values

    log.info("Overall label distribution: %s", dict(zip(*np.unique(y, return_counts=True))))

    # ------------------------------------------------------------------
    # 2. Train/test split (stratified)
    # ------------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    log.info(
        "Train: %d samples | Test: %d samples",
        len(X_train), len(X_test),
    )

    # ------------------------------------------------------------------
    # 3. Cross-validation on training set (5-fold stratified)
    # ------------------------------------------------------------------
    pipeline = build_pipeline()
    log.info("Running %d-fold stratified cross-validation...", CV_FOLDS)

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)

    print("\n" + "=" * 60)
    print("CROSS-VALIDATION RESULTS (F1 score, phishing class)")
    print("=" * 60)
    for i, score in enumerate(cv_scores, 1):
        print(f"  Fold {i}: {score:.4f}")
    print(f"  Mean:  {cv_scores.mean():.4f}  (+/- {cv_scores.std():.4f})")

    # ------------------------------------------------------------------
    # 4. Train on full training set, evaluate on held-out test set
    # ------------------------------------------------------------------
    log.info("Training final pipeline on full training set...")
    pipeline.fit(X_train, y_train)

    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 60)
    print("HELD-OUT TEST SET METRICS")
    print("=" * 60)
    print(classification_report(
        y_test, y_pred,
        target_names=["legitimate (0)", "phishing (1)"],
        digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  [[ TN={cm[0,0]:4d}  FP={cm[0,1]:4d} ]]")
    print(f"  [[ FN={cm[1,0]:4d}  TP={cm[1,1]:4d} ]]")

    auc = roc_auc_score(y_test, y_proba)
    print(f"\nROC-AUC Score: {auc:.4f}")

    # ------------------------------------------------------------------
    # 5. Retrain on ALL data (train + test) for the final saved model
    # ------------------------------------------------------------------
    log.info("Retraining on full dataset for final saved model...")
    final_pipeline = build_pipeline()
    final_pipeline.fit(X, y)

    # ------------------------------------------------------------------
    # 6. Save
    # ------------------------------------------------------------------
    joblib.dump(final_pipeline, MODEL_PATH)
    log.info("Model saved to %s", MODEL_PATH)

    print("\n" + "=" * 60)
    print("TOP 20 PHISHING INDICATOR FEATURES (TF-IDF weights)")
    print("=" * 60)
    tfidf     = final_pipeline.named_steps["tfidf"]
    clf       = final_pipeline.named_steps["clf"]
    feature_names = tfidf.get_feature_names_out()
    # coef_[0] = class 0 vs class 1, so positive = phishing indicator
    coef = clf.coef_[0]
    top_phish = np.argsort(coef)[-20:][::-1]
    top_legit = np.argsort(coef)[:20]
    print("  Phishing indicators (positive weight):")
    for idx in top_phish:
        print(f"    {feature_names[idx]:30s}: {coef[idx]:+.4f}")
    print("\n  Legitimate indicators (negative weight):")
    for idx in top_legit:
        print(f"    {feature_names[idx]:30s}: {coef[idx]:+.4f}")

    print(f"\n[OK] Training complete. Model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train_and_evaluate()
