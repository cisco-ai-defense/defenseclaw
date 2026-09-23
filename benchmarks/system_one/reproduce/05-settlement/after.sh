#!/bin/bash
# After finish_arms.sh scores both arms, build the three registry artifacts.
G=$WORK/.system-one-data/outputs/gemma4jev
exec >>"$G/s2/after.log" 2>&1
echo "===== $(date -u +%FT%TZ) after.sh waiting for FINISH DONE"
for i in $(seq 1 600); do
  grep -q "FINISH DONE" "$G/s2/finish.log" 2>/dev/null && break
  sleep 60
done
grep -q "FINISH DONE" "$G/s2/finish.log" 2>/dev/null || { echo "finish never completed"; exit 1; }
echo "scoring complete, building extras at $(date -u +%FT%TZ)"
$WORK/.system-one-venv/bin/python "$G/build_extras.py" --append-comparison
echo "===== EXTRAS DONE $(date -u +%FT%TZ)"
