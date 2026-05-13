"""
BehavGuard – Shared core: preprocessing + heuristic transformer.
Imported by both train.py and test_model.py so pickle works correctly.
"""
import urllib.parse
import re
import numpy as np


def preprocess(text: str) -> str:
    """URL-decode (iteratively), lowercase, normalize slashes, strip noise."""
    if not isinstance(text, str):
        text = str(text)
    prev = None
    while prev != text:
        prev = text
        text = urllib.parse.unquote(text)
    text = text.lower()
    text = text.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f]", "", text)
    return text.strip()


class HeuristicTransformer:
    """
    Hand-crafted security features that complement TF-IDF.
    Features per sample:
      0  – count '../' sequences
      1  – count '..\' sequences (raw)
      2  – Unix sensitive path presence (/etc/, /proc/, etc.)
      3  – Windows sensitive path presence (win.ini, SAM, etc.)
      4  – URL-encoded dots/slashes (%2e, %2f, %5c)
      5  – Double-encoded sequences (%25)
      6  – Null byte presence (%00)
      7  – Path depth (count of '/')
      8  – Absolute path start (/etc, /proc, C:/)
      9  – Ratio of special chars to total length
    """
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array([self._features(raw) for raw in X], dtype=float)

    def fit_transform(self, X, y=None):
        return self.transform(X)

    def _features(self, raw: str) -> list:
        p = preprocess(raw)
        r = raw.lower()

        dotdot_fwd  = p.count("../")
        dotdot_bwd  = r.count("..\\")
        unix_sens   = int(any(s in p for s in [
            "/etc/", "/proc/", "/var/log/", "/var/www/",
            "/home/", "/root/", "/usr/", "/bin/", "/sys/"
        ]))
        win_sens    = int(any(s in p for s in [
            "win.ini", "boot.ini", "sam", "system32",
            "windows/", "winnt/", "autoexec.bat"
        ]))
        encoded     = r.count("%2e") + r.count("%2f") + r.count("%5c")
        double_enc  = r.count("%25")
        null_byte   = int("%00" in r or "\x00" in raw)
        depth       = p.count("/")
        abs_path    = int(p.startswith("/etc") or p.startswith("c:/") or
                          p.startswith("/proc") or p.startswith("/var"))
        special     = sum(1 for c in raw if c in r"./\%?&=;#@!")
        ratio       = special / max(len(raw), 1)

        return [dotdot_fwd, dotdot_bwd, unix_sens, win_sens,
                encoded, double_enc, null_byte, depth, abs_path, ratio]
