# BehavGuard – Path Traversal Attack Detector

**AI-Powered Web Application Firewall Component**

---

## What Is a Path Traversal Attack?

A **Path Traversal** (also called Directory Traversal) attack exploits insufficient input validation in web applications to access files and directories **outside the intended web root**.

Attackers craft special payloads using `../` sequences and encoding tricks to navigate the server filesystem and read sensitive files.

### Attack Example

```
GET /download.php?file=../../etc/passwd HTTP/1.1
Host: vulnerable-site.com
```

The server intended to serve files from `/var/www/uploads/`, but the `../../etc/passwd` payload escapes this directory to reach the system password file.

### Common Attacker Techniques

| Technique | Example |
|---|---|
| Basic traversal | `../../etc/passwd` |
| URL encoding | `..%2f..%2fetc%2fpasswd` |
| Double encoding | `..%252f..%252fetc%252fpasswd` |
| Overlong UTF-8 | `..%c0%af..%c0%afetc%c0%afpasswd` |
| Null byte injection | `../../etc/passwd%00.jpg` |
| Mixed separators | `....//....//etc/passwd` |
| Windows paths | `..\..\windows\win.ini` |

---

## Project Structure

```
BehavGuard/
├── dataset/
│   ├── build_dataset.py          # Dataset builder (malicious + benign)
│   └── path_traversal_dataset.csv
├── models/
│   ├── path_traversal_model.joblib   # Trained ML model
│   └── model_metadata.joblib         # Vectorizers + metadata
├── behavguard_core.py            # Shared preprocessing & heuristics
├── train.py                      # Training pipeline
├── test_model.py                 # Inference / testing script
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# 1. Clone or copy the project
cd BehavGuard

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## How to Run

### Step 1 — Build the dataset (optional, already included)

```bash
python dataset/build_dataset.py
```

### Step 2 — Train the model

```bash
python train.py
```

**Output:**

```
============================================================
  BehavGuard – Path Traversal ML Training
============================================================

[1/6] Loading dataset...
[2/6] Splitting data (80% train / 20% test)...
[3/6] Fitting TF-IDF vectorizers (word n-grams + char n-grams)...
[4/6] Extracting hand-crafted security heuristic features...
[5/6] Training and evaluating models...

  Logistic Regression
  Accuracy  : 1.0000
  Precision : 1.0000
  Recall    : 1.0000
  F1-Score  : 1.0000

  Best Model : Logistic Regression  (F1 = 1.0000)
  CV F1: 0.9917 ± 0.0102
```

### Step 3 — Test the model

```bash
# Single payload
python test_model.py "../../etc/passwd"

# Interactive mode (demo + REPL)
python test_model.py

# Batch mode
python test_model.py --batch payloads.txt
```

---

## Sample Predictions

| Payload | Verdict | Confidence |
|---|---|---|
| `../../etc/passwd` | ⚠ MALICIOUS | 99.9% |
| `..%2f..%2fetc%2fpasswd` | ⚠ MALICIOUS | 100.0% |
| `....//....//etc/passwd` | ⚠ MALICIOUS | 99.9% |
| `../../windows/win.ini` | ⚠ MALICIOUS | 98.5% |
| `/api/v1/users` | ✓ BENIGN | 99.0% |
| `/static/css/main.css` | ✓ BENIGN | 98.4% |

---

## ML Architecture

### Feature Engineering

1. **TF-IDF Word N-grams** — Captures full tokens (`..`, `etc`, `passwd`) and bigrams
2. **TF-IDF Char N-grams** (2–5 chars) — Captures sub-token attack patterns (`%2f`, `../`, `etc/`)
3. **Security Heuristics** — 10 hand-crafted features:
   - `../` and `..\` sequence counts
   - Sensitive Unix/Windows path presence
   - URL-encoded character counts (`%2e`, `%2f`, `%5c`)
   - Double-encoding detection (`%25`)
   - Null byte presence (`%00`)
   - Path depth, absolute path detection
   - Special character ratio

### Models Compared

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Random Forest | 98.4% | 100% | 96.8% | 98.4% |
| **Logistic Regression** | **100%** | **100%** | **100%** | **100%** |
| Gradient Boosting | 98.4% | 100% | 96.8% | 98.4% |

### Dataset

- **306 samples** (153 malicious, 153 benign)
- Sources: OWASP, PayloadsAllTheThings, CSIC 2010-inspired patterns
- Covers: basic traversal, URL encoding, double encoding, null bytes, Windows paths, LFI in query params

---

## WAF Integration

The `predict()` function in `test_model.py` is designed for WAF middleware:

```python
from test_model import predict, load_artifacts

clf, meta = load_artifacts()

def waf_check(request_path: str) -> bool:
    result = predict(request_path, clf, meta)
    if result["label"] == "Malicious":
        # Block request, log incident
        return False
    return True
```

---

## Future Improvements (Zero-Day Protection)

1. **LSTM / Transformer models** — Sequence models that learn long-range traversal patterns
2. **Online learning** — Update model in real-time from WAF logs without full retraining
3. **Anomaly detection** — Isolation Forest / Autoencoder for unseen attack variants
4. **Ensemble voting** — Combine ML prediction with rule-based signatures
5. **CSIC 2010 full dataset** — Integrate the complete HTTP dataset for broader coverage
6. **Adversarial training** — Augment with GAN-generated evasion payloads
7. **Context-aware detection** — Analyze full HTTP request (headers + body) not just URL
8. **Feedback loop** — Security analysts flag FPs/FNs → retrain pipeline

---

## Tech Stack

- **Python 3.9+**
- **scikit-learn** — ML models, TF-IDF, evaluation
- **pandas** — Data handling
- **joblib** — Model serialization
- **scipy** — Sparse matrix operations
