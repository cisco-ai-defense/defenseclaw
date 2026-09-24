"""Verification POST through the dev-host tunnel 8011 -> GPU shim 8011 -> vLLM 8100.
Builds a genuine request with the runner's own builders, in the exact shape the
completed s3-diffgemma-q2 run used (C7 / I3 / Q2, instruction-format string).
"""
import json, sys, urllib.request, importlib.util
from pathlib import Path

REPO = Path("$WORK/defenseclaw-system-one")
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "benchmarks/scripts"))
spec = importlib.util.spec_from_file_location("runner", REPO / "benchmarks/scripts/benchmark_run_system_one.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

ctx = json.loads((REPO / "benchmarks/system_one/contexts-v1.json").read_text())
qcfg = json.loads((REPO / "benchmarks/system_one/questions-v1.json").read_text())
case = json.loads(open("$WORK/.system-one-data/outputs/cache/cases20.jsonl").readline())

job = next(iter(runner.case_jobs(case, ["C7"], ["I3"], ["Q2"], ctx, qcfg, "string")))
_, _, _, _, state, _, questions = job
body = {"model": "diffusiongemma", "state": state, "questions": questions}
req = urllib.request.Request(
    "http://127.0.0.1:8011/v1/systemone",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=180) as r:
        code = r.status
        payload = json.loads(r.read())
    print("HTTP_STATUS =", code)
    print("answers present:", sorted(payload.get("answers", {})))
    print("usage:", payload.get("usage"))
    d = payload.get("answers", {}).get("disposition", {})
    print("disposition:", d.get("choice"), "confidence:", d.get("confidence"))
    print("RESULT: PASS" if code == 200 and payload.get("answers") else "RESULT: FAIL")
except Exception as e:
    print("HTTP_STATUS = ERROR")
    print("RESULT: FAIL", type(e).__name__, str(e)[:400])
