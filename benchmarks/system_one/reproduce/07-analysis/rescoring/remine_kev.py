"""Third pass: kev-9b on s2 at the parity grid C7/I3/Q2.
Body staged read-only from the studio; source under runs/ untouched.
ZERO GPU. Same arithmetic as remine.py, unchanged."""
import json, sys
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as R

KEV = Path("/home/ubuntu/rescoring-remine/kev-s2/kev-9b-shard0.jsonl")
R.ARMS = [("kev-9b", None, KEV, None, None, None)]
R.main()
