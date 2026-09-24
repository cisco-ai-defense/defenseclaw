#!/bin/bash
# Status for the System One GPU benchmark programme.
# Neither this host's instance role nor the operator's local credentials can call
# ec2:DescribeInstances against the GPU account, so ssh reachability plus nvidia-smi
# is the liveness signal rather than instance state.
O=$WORK/.system-one-data/outputs
GPU_IP="<GPU_HOST>"          # public ip changes if the instance is restarted
RATE=12.90014               # g6e.12xlarge on-demand, ap-northeast-2, USD/hour
GPU_SSH="ssh -o ConnectTimeout=8 -o BatchMode=yes -i <SSH_KEY> ubuntu@$GPU_IP"

echo "=== BENCHMARK ARMS (target 30310 rows) ==="
$WORK/.system-one-venv/bin/python - <<'PY'
import glob, json, os, time
O = "$WORK/.system-one-data/outputs"
SNAP = "$WORK/.status-snap.json"
TARGET = 30310
# A sharded run writes into shards/<pred>-shardN.jsonl and only merges at the end, so count
# the shards until the merged file appears - otherwise a live run reads as "not started".
ARMS = [
    ("jevify-gemma4-26b-a4b", "gemma4jev/s2/jevify-gemma4-26b-a4b.jsonl", None),
    ("gemma-4-26b-a4b-it",    "gemma4jev/s2/gemma-4-26b-a4b-it.jsonl",    None),
    ("open-jev-qwen-27b",     "openjev-qwen/s2/open-jev-qwen-27b.jsonl",
     "openjev-qwen/s2/shards/open-jev-qwen-27b-shard*.jsonl"),
]
now = time.time()
try:
    snap = json.load(open(SNAP))
except Exception:
    snap = {}
new = {}
for name, rel, shard_glob in ARMS:
    path = os.path.join(O, rel)
    shards = sorted(glob.glob(os.path.join(O, shard_glob))) if shard_glob else []
    if not os.path.exists(path) and not shards:
        print(f"  {name:<24} not started")
        continue
    if os.path.exists(path):
        rows = sum(1 for _ in open(path, "rb"))
        suffix = ""
    else:
        rows = sum(sum(1 for _ in open(s, "rb")) for s in shards)
        suffix = f" [{len(shards)} shards]"
        path = max(shards, key=os.path.getmtime)
    done = os.path.exists(os.path.join(O, rel) + ".meta.json")
    new[name] = {"rows": rows, "t": now}
    trend = ""
    prev = snap.get(name)
    if prev and not done:
        drows = rows - prev["rows"]
        dmin = (now - prev["t"]) / 60.0
        if dmin > 0 and drows > 0:
            rate = drows / dmin
            trend = f"  {rate:5.1f} rows/min  eta {(TARGET - rows) / rate / 60:4.1f}h"
        elif dmin > 1:
            trend = f"  STALLED no new rows in {dmin:.0f}m"
    last = time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(path)))
    state = "DONE" if done else "running"
    print(f"  {name:<24} {rows:6d}/{TARGET}  {state:<7} last {last}{trend}{suffix}")
json.dump(new, open(SNAP, "w"))
PY

echo
echo "=== GPU HOST <GPU_INSTANCE> g6e.12xlarge ap-northeast-2b ==="
if OUT=$($GPU_SSH 'echo BOOT=$(uptime -s); nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv,noheader; echo NVME=$(df -h /opt/dlami/nvme | tail -1 | awk "{print \$4}")' 2>/dev/null); then
  BOOT=$(echo "$OUT" | sed -n 's/^BOOT=//p')
  UP=$(( $(date +%s) - $(date -d "$BOOT" +%s) ))
  COST=$(awk -v s="$UP" -v r="$RATE" 'BEGIN{printf "%.2f", s/3600*r}')
  printf "  reachable  up %dh%02dm  session cost ~\$%s at \$%s/h\n" $((UP/3600)) $((UP%3600/60)) "$COST" "$RATE"
  echo "$OUT" | grep -E '^[0-9]+,' | awk -F', ' '{printf "  card %s  %9s / %-9s  util %s\n", $1, $2, $3, $4}'
  echo "  nvme avail $(echo "$OUT" | sed -n 's/^NVME=//p')"
else
  echo "  UNREACHABLE over ssh - the public ip changes on restart, so this is either"
  echo "  a stopped instance or a stale GPU_IP in this script. Check before assuming."
fi

echo
echo "=== PUBLIC SPACE ==="
$WORK/.system-one-venv/bin/python -c "
from huggingface_hub import HfApi
i=HfApi().repo_info('Vineethsain/defenseclaw-system-one', repo_type='space')
print(f'  rev={(i.sha or \"\")[:12]} public={not i.private} files={len(i.siblings or [])} modified={str(getattr(i,\"lastModified\",\"\"))[:19]}')
" 2>/dev/null
B=$WORK/.system-one-space-build
echo "  build last write: $(find $B -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1 | cut -d. -f1 | xargs -I{} date -d @{} +%H:%M:%S)"
echo "  charts in site/: $(grep -ho '<svg' $B/site/*.html 2>/dev/null | wc -l)"

echo
echo "=== DETECTION PR WORKTREES ==="
for w in $WORK/dc-detrules $WORK/dc-main; do
  [ -d "$w" ] || continue
  echo "  $(basename $w): $(git -C $w log --oneline -1 2>/dev/null)  |  $(git -C $w status --porcelain 2>/dev/null | wc -l) changed"
done

echo
echo "=== JEV (parity complete, credits exhausted) ==="
$WORK/.system-one-venv/bin/python - <<'PY' 2>/dev/null
import json, glob
total = 0.0; n = 0
for p in glob.glob("$WORK/.system-one-data/outputs/**/jev*.meta.json", recursive=True):
    try:
        d = json.load(open(p))
    except Exception:
        continue
    u = d.get("estimated_usd")
    if isinstance(u, (int, float)):
        total += u; n += 1
print(f"  ${total:.4f} across {n} jev metas")
PY

echo
echo "=== live benchmark processes ==="
ps -eo etime=,args= | grep -E "benchmark_run_system_one|benchmark_score" | grep -v grep \
  | sed -E 's/--cases [^ ]+//; s#$WORK/\.system-one-venv/bin/python#py#; s#benchmarks/scripts/##' \
  | cut -c1-150 | head -6
[ -z "$(ps -eo args= | grep benchmark_run_system_one | grep -v grep)" ] && echo "  none running"
exit 0
