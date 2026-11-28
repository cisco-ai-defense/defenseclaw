"""The frozen s7-gate holdout split (rel-1-0-10, S7 lane L2).

Why: lanes tuned on the same corpora they reported (fix1 on s3's false blocks, the AD pack on cochise, effects on s3/s2 misses), and the corpora's own
`split` fields disagree (s3 smoke/test, s2 development/validation), so no number in the trend was a generalisation number. This module assigns every
case to "tune" (the lane may look at its errors and tune on it) or "holdout" (about 30% of each corpus; a lane reports it and never reads its cases).

The rule is frozen in holdout-split-v1.json (never edited; a change is a new file, holdout-split-v2.json, with its own sha). Its sha256 goes into every
RUN.json and every score file, and the audit reports a score computed under a different split.

  holdout  iff  int(sha256(salt + "|" + group_key)[:8], 16) % 100 < percent

group_key keeps what one source shares on one side, so a session, a campaign or a pair never lands on both sides:
  pair_group                        AgentDojo intent pairs (both sides of a pair, clean and attacked)
  cochise run file (original_id up to the first ":")   the Active Directory pentest corpus s3: one run is one AD campaign against one lab
  strata.split_group                the source session / trajectory (agent transcripts: the session; MCP / AgentDojo: the trajectory or item)
  strata.trajectory_id, else the case id
The key does not name the corpus: the same session in agent-transcripts-small, -sample and -aidev-sample, or the same item in public-surfaces and -v2, falls
on the same side everywhere.

tuned_corpora are regression suites (each case is the repro of a fix it scores): everything is tune and they are reported as "tuned", with no holdout.
overrides keep a lane's pre-registered split for its own cases: s7-shellrecall froze sha256('sr-split-v1|'+key)[0]&1 on source-session / command-skeleton
groups before it wrote any rule, so a case it has already put on a side stays on it.
"""

import hashlib
import json
import os

# The frozen split file is data, not code: s7-gate deploys holdout-split-v1.json beside this module on every bench box (it is
# not in the repository). S7_HOLDOUT_SPLIT names another file (the repository tests use testdata/holdout-split-test.json).
FILE = os.environ.get("S7_HOLDOUT_SPLIT") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "holdout-split-v1.json"
)
TUNE, HOLDOUT = "tune", "holdout"
_cache = {}


def load(path=None):
    path = path or FILE
    if path not in _cache:
        raw = open(path, "rb").read()
        cfg = json.loads(raw)
        cfg["_sha256"] = hashlib.sha256(raw).hexdigest()
        cfg["_overrides"] = {
            (o["corpus"], o["id"]): o["split"] for src in cfg.get("overrides", []) for o in src["rows"]
        }
        _cache[path] = cfg
    return _cache[path]


def sha256(path=None):
    return load(path)["_sha256"]


def group_key(r):
    st = r.get("strata") or {}
    src = r.get("source") or {}
    if st.get("pair_group"):
        return "pair:" + st["pair_group"]
    if "cochise" in (src.get("dataset") or "") and src.get("original_id"):
        return "cochise-run:" + src["original_id"].split(":", 1)[0]
    return st.get("split_group") or st.get("trajectory_id") or r["id"]


def bucket(salt, key):
    return int(hashlib.sha256((salt + "|" + key).encode()).hexdigest()[:8], 16) % 100


def split_of(corpus, r, cfg=None):
    """-> "tune" | "holdout" for one case record of a corpus."""
    cfg = cfg or load()
    if corpus in cfg["tuned_corpora"]:
        return TUNE
    o = cfg["_overrides"].get((corpus, r["id"]))
    if o:
        return o
    return HOLDOUT if bucket(cfg["salt"], group_key(r)) < cfg["percent"] else TUNE
