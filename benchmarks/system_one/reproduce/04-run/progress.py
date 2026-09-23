"""Report row counts, rate and ETA for the two Gemma 4 s2 arms."""
import json
import os
import subprocess
import sys
import time

G = "$WORK/.system-one-data/outputs/gemma4jev/s2"
ARMS = [("arm3 jevify", "jevify-gemma4-26b-a4b.jsonl"),
        ("arm2 base+T", "gemma-4-26b-a4b-it.jsonl")]
TOTAL = 30310
WINDOW = int(sys.argv[1]) if len(sys.argv) > 1 else 180


def count(path):
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except FileNotFoundError:
        return 0


first = {name: count(os.path.join(G, f)) for name, f in ARMS}
t0 = time.time()
time.sleep(WINDOW)
dt = time.time() - t0
print("window %.0fs  %s" % (dt, time.strftime("%H:%M:%SZ", time.gmtime())))
for name, f in ARMS:
    path = os.path.join(G, f)
    now = count(path)
    delta = now - first[name]
    rate = delta / dt if dt else 0
    done = os.path.exists(path + ".meta.json")
    settled = False
    if done:
        try:
            settled = json.load(open(path + ".meta.json")).get("settled", False)
        except Exception:
            pass
    line = "  %-12s %6d/%d (%.1f%%)" % (name, now, TOTAL, 100.0 * now / TOTAL)
    if rate > 0:
        line += "  %.3f rows/s  %.3f s/row  ETA %.2f h" % (rate, 1 / rate, (TOTAL - now) / rate / 3600)
    else:
        line += "  stalled (0 rows in window)"
    if done:
        line += "  META_PRESENT settled=%s" % settled
    print(line)
print(subprocess.run(
    ["ssh", "-i", "<SSH_KEY>", "-o", "StrictHostKeyChecking=yes",
     "ubuntu@<GPU_HOST>", "nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv,noheader"],
    capture_output=True, text=True).stdout.strip())
