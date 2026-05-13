"""
================================================================================
BehavGuard – Path Traversal Detection: Inference / Testing Script
================================================================================
Usage:
  python test_model.py                         # Interactive demo
  python test_model.py "../../etc/passwd"      # Single payload
  python test_model.py --batch payloads.txt    # Batch file
================================================================================
"""

import sys, os, argparse
import joblib
import numpy as np
import scipy.sparse as sp

from behavguard_core import preprocess, HeuristicTransformer

MODEL_PATH = "models/path_traversal_model.joblib"
META_PATH  = "models/model_metadata.joblib"


def load_artifacts():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(META_PATH):
        print("[ERROR] Model not found. Run 'python train.py' first.")
        sys.exit(1)
    return joblib.load(MODEL_PATH), joblib.load(META_PATH)


def predict(payload: str, clf, meta: dict) -> dict:
    """Classify a single URL/payload and return verdict + confidence."""
    tw = meta["tfidf_word"].transform([payload])
    tc = meta["tfidf_char"].transform([payload])
    th = sp.csr_matrix(meta["heuristic"].transform([payload]))
    X  = sp.hstack([tw, tc, th])

    pred       = clf.predict(X)[0]
    prob       = clf.predict_proba(X)[0]
    confidence = float(prob[pred])
    label      = meta["class_map"][pred]
    risk       = ("HIGH" if confidence >= 0.85 else "MEDIUM") if label == "Malicious" else "LOW"

    return {
        "payload"    : payload,
        "clean"      : preprocess(payload),
        "label"      : label,
        "confidence" : confidence,
        "risk_level" : risk,
    }


# ── Terminal color helpers ────────────────────────────────────────────────────
C = {"R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[1m","X":"\033[0m"}
def red(s):  return f"{C['R']}{s}{C['X']}"
def grn(s):  return f"{C['G']}{s}{C['X']}"
def bld(s):  return f"{C['B']}{s}{C['X']}"


def print_result(r: dict):
    icon  = red("⚠  MALICIOUS") if r["label"] == "Malicious" else grn("✓  BENIGN")
    color = red if r["label"] == "Malicious" else grn
    print("\n" + "─"*56)
    print(f"  Payload    : {r['payload']}")
    print(f"  Decoded    : {r['clean']}")
    print(f"  Verdict    : {icon}")
    print(f"  Confidence : {r['confidence']*100:.1f}%")
    print(f"  Risk Level : {color(r['risk_level'])}")
    print("─"*56)


def batch_predict(filepath, clf, meta):
    with open(filepath, "r", errors="ignore") as f:
        payloads = [l.strip() for l in f if l.strip()]
    print(f"\nBatch: {len(payloads)} payloads from '{filepath}'\n")
    mal = ben = 0
    for p in payloads:
        r = predict(p, clf, meta)
        if r["label"] == "Malicious": mal += 1
        else: ben += 1
        status = red("MALICIOUS") if r["label"] == "Malicious" else grn("BENIGN")
        print(f"  [{status}] ({r['confidence']*100:.0f}%) {p[:80]}")
    print(f"\n  {len(payloads)} scanned | {red(str(mal)+' malicious')} | {grn(str(ben)+' benign')}\n")


# ── Demo payloads ─────────────────────────────────────────────────────────────
DEMO = [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "../../windows/win.ini",
    "/api/v1/users",
    "/static/css/main.css",
    "/search?q=machine+learning&page=2",
]


def main():
    parser = argparse.ArgumentParser(description="BehavGuard WAF – Path Traversal Classifier")
    parser.add_argument("payload", nargs="?", help="Single payload")
    parser.add_argument("--batch", metavar="FILE", help="File with one payload per line")
    args = parser.parse_args()

    print(bld("\n  BehavGuard WAF – Path Traversal Detector"))
    print("  " + "─"*42)

    clf, meta = load_artifacts()
    print(f"  Model: {meta['model_name']}  |  F1: {meta['f1_score']:.4f}\n")

    if args.batch:
        batch_predict(args.batch, clf, meta)
        return

    if args.payload:
        print_result(predict(args.payload, clf, meta))
        return

    # Demo mode
    print("  Demo: classifying sample payloads...\n")
    for p in DEMO:
        print_result(predict(p, clf, meta))

    print("\n  ── Interactive Mode (Ctrl+C to exit) ──\n")
    try:
        while True:
            user_input = input("  Payload> ").strip()
            if user_input:
                print_result(predict(user_input, clf, meta))
    except KeyboardInterrupt:
        print("\n\n  Stay secure!\n")


if __name__ == "__main__":
    main()
