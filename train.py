"""
================================================================================
BehavGuard – Path Traversal Detection: Training Pipeline
================================================================================
Project  : BehavGuard – AI-Powered Web Application Firewall
Component: ML Training Script

WHAT IS PATH TRAVERSAL?
-----------------------
A Path Traversal (Directory Traversal) attack exploits insufficient input
validation to navigate outside the intended web root and read sensitive files.
Attackers craft payloads using "../" sequences and encoding tricks to reach
files like /etc/passwd, SSH keys, or Windows registry hives.

  Attack example:
    GET /download.php?file=../../etc/passwd HTTP/1.1

This script builds a production-ready ML pipeline to detect such attacks.
================================================================================
"""

import os, time, warnings
import joblib
import pandas as pd
import scipy.sparse as sp

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble          import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model      import LogisticRegression
from sklearn.model_selection   import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics           import (accuracy_score, precision_score, recall_score,
                                       f1_score, classification_report, confusion_matrix)

# ── Import shared preprocessing & heuristic transformer ────────────────────
from behavguard_core import preprocess, HeuristicTransformer

warnings.filterwarnings("ignore")

# ─── Configuration ───────────────────────────────────────────────────────────
DATASET_PATH = "dataset/path_traversal_dataset.csv"
MODEL_DIR    = "models"
MODEL_PATH   = os.path.join(MODEL_DIR, "path_traversal_model.joblib")
META_PATH    = os.path.join(MODEL_DIR, "model_metadata.joblib")
TEST_SIZE    = 0.20
RANDOM_STATE = 42

os.makedirs(MODEL_DIR, exist_ok=True)


def evaluate(clf, X_test, y_test, name):
    """Print metrics and return F1 score."""
    y_pred = clf.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0,0]:>4}  FP={cm[0,1]:>4}")
    print(f"    FN={cm[1,0]:>4}  TP={cm[1,1]:>4}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Benign","Malicious"], digits=4))
    return f1


def main():
    print("\n" + "="*60)
    print("  BehavGuard – Path Traversal ML Training")
    print("="*60)

    # ── 1. Load dataset ──────────────────────────────────────────────────
    print(f"\n[1/6] Loading dataset from '{DATASET_PATH}'...")
    df = pd.read_csv(DATASET_PATH)
    print(f"      Samples  : {len(df)}")
    print(f"      Malicious: {(df.label==1).sum()}")
    print(f"      Benign   : {(df.label==0).sum()}")

    X = df["payload"].values
    y = df["label"].values

    # ── 2. Train/Test split ──────────────────────────────────────────────
    print(f"\n[2/6] Splitting data (80% train / 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    # ── 3. TF-IDF Features ───────────────────────────────────────────────
    print("\n[3/6] Fitting TF-IDF vectorizers (word n-grams + char n-grams)...")

    # Word-level: captures full tokens like '..', 'etc', 'passwd'
    tfidf_word = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"[^\s/]+",
        ngram_range=(1, 2),
        max_features=3000,
        sublinear_tf=True,
        preprocessor=preprocess,
    )

    # Char-level: captures sub-token attack patterns like '%2f', '..'
    tfidf_char = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=5000,
        sublinear_tf=True,
        preprocessor=preprocess,
    )

    X_train_word = tfidf_word.fit_transform(X_train)
    X_test_word  = tfidf_word.transform(X_test)
    X_train_char = tfidf_char.fit_transform(X_train)
    X_test_char  = tfidf_char.transform(X_test)

    # ── 4. Heuristic Features ────────────────────────────────────────────
    print("\n[4/6] Extracting hand-crafted security heuristic features...")
    heur = HeuristicTransformer()
    X_train_heur = sp.csr_matrix(heur.transform(X_train))
    X_test_heur  = sp.csr_matrix(heur.transform(X_test))

    # Combine all feature sets
    X_train_all = sp.hstack([X_train_word, X_train_char, X_train_heur])
    X_test_all  = sp.hstack([X_test_word,  X_test_char,  X_test_heur])
    print(f"      Combined feature matrix: {X_train_all.shape}")

    # ── 5. Train & Compare Models ────────────────────────────────────────
    print("\n[5/6] Training and evaluating models...")
    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced",
            random_state=RANDOM_STATE, n_jobs=-1
        ),
        "Logistic Regression": LogisticRegression(
            C=5.0, max_iter=1000, class_weight="balanced",
            random_state=RANDOM_STATE
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.1,
            max_depth=5, random_state=RANDOM_STATE
        ),
    }

    best_f1, best_name, best_clf = -1, None, None

    for name, clf in candidates.items():
        t0 = time.time()
        clf.fit(X_train_all, y_train)
        print(f"      [{name}] trained in {time.time()-t0:.1f}s")
        f1 = evaluate(clf, X_test_all, y_test, name)
        if f1 > best_f1:
            best_f1, best_name, best_clf = f1, name, clf

    print(f"\n{'='*60}")
    print(f"  Best Model : {best_name}  (F1 = {best_f1:.4f})")
    print(f"{'='*60}")

    # Cross-validation on best model
    print(f"\n[5b] 5-Fold Cross-Validation for '{best_name}'...")
    cv = cross_val_score(best_clf, X_train_all, y_train,
                         cv=StratifiedKFold(5), scoring="f1", n_jobs=-1)
    print(f"     CV F1: {cv.mean():.4f} ± {cv.std():.4f}")

    # ── 6. Save Model Artifacts ──────────────────────────────────────────
    print(f"\n[6/6] Saving artifacts to '{MODEL_DIR}/'...")
    joblib.dump(best_clf, MODEL_PATH)

    metadata = {
        "model_name"  : best_name,
        "tfidf_word"  : tfidf_word,
        "tfidf_char"  : tfidf_char,
        "heuristic"   : heur,
        "f1_score"    : best_f1,
        "class_map"   : {0: "Benign", 1: "Malicious"},
    }
    joblib.dump(metadata, META_PATH)
    print(f"      model    → {MODEL_PATH}")
    print(f"      metadata → {META_PATH}")
    print("\n  Training complete! Run: python test_model.py\n")


if __name__ == "__main__":
    main()
