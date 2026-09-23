"""Shared normalisation / shingling / sketching for the SecJudge contamination study."""
from __future__ import annotations
import hashlib, json, re, unicodedata
import numpy as np

SHINGLE_N = 5          # character 5-grams
SKETCH_K  = 128        # bottom-k (KMV) sketch size
MAX_CHARS = 1_000_000  # hard cap on normalised chars fed to the shingler

# framing tags emitted by secjudge_serialize / build_state, incl. attributes
TAG_RE = re.compile(
    r"</?(?:SESSION_USER_INTENT|RECENT_TOOL_CALL|CURRENT_TOOL_CALL)(?:\s[^>]*)?>",
    re.IGNORECASE,
)
WS_RE = re.compile(r"\s+")

def normalize(s) -> str:
    """NFKC -> strip framing tags -> lowercase -> collapse whitespace -> strip."""
    if s is None: return ""
    if not isinstance(s, str): s = str(s)
    s = unicodedata.normalize("NFKC", s)
    s = TAG_RE.sub(" ", s)
    s = s.lower()
    s = WS_RE.sub(" ", s)
    return s.strip()

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def canon_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)

_FNV_OFF = np.uint64(14695981039346656037)
_FNV_PRM = np.uint64(1099511628211)

def shingle_hashes(s: str, n: int = SHINGLE_N) -> np.ndarray:
    """Unique 64-bit FNV-1a hashes of the character n-grams of s (sorted)."""
    if not s: return np.empty(0, dtype=np.uint64)
    if len(s) > MAX_CHARS: s = s[:MAX_CHARS]
    cp = np.frombuffer(s.encode("utf-32-le"), dtype=np.uint32)
    if cp.size < n:
        h = _FNV_OFF
        for c in cp:
            h = np.uint64((h ^ np.uint64(c)) * _FNV_PRM)
        return np.array([h], dtype=np.uint64)
    w = np.lib.stride_tricks.sliding_window_view(cp, n)
    h = np.full(w.shape[0], _FNV_OFF, dtype=np.uint64)
    with np.errstate(over="ignore"):
        for i in range(n):
            h = (h ^ w[:, i].astype(np.uint64)) * _FNV_PRM
    return np.unique(h)

UINT64_MAX = np.uint64(np.iinfo(np.uint64).max)

def kmv_sketch(h: np.ndarray, k: int = SKETCH_K):
    """Bottom-k sketch (sorted, right-padded with UINT64_MAX) + true unique-shingle count."""
    n = int(h.size)
    out = np.full(k, UINT64_MAX, dtype=np.uint64)
    if n == 0: return out, 0, True
    if n <= k:
        out[:n] = h            # h already sorted by np.unique
        return out, n, True
    out[:] = np.sort(h[np.argpartition(h, k)[:k]])
    return out, n, False

def exact_jaccard(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 and b.size == 0: return 1.0
    if a.size == 0 or b.size == 0: return 0.0
    inter = int(np.intersect1d(a, b, assume_unique=True).size)
    union = int(a.size) + int(b.size) - inter
    return inter / union if union else 0.0

def read_docs(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
