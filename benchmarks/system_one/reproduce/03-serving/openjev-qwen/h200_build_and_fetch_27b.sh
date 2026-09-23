#!/bin/bash
# Non-apt half of the 4x H200 bring-up plus the 27B artifacts, so the big download
# overlaps the studio still finishing provisioning. python3.12-dev is applied separately
# once apt unblocks; it only affects the fla/Triton fast path, not correctness of load.
set -euo pipefail
ROOT="$HOME/sysone"
export HF_HOME="$ROOT/hf"
CK="$ROOT/checkpoints"
mkdir -p "$ROOT"/{logs,agree/cfg,agree/out} "$CK"
cd "$ROOT"

echo "=== [1/4] Open-Jev loader pinned at ed45657b ==="
if [ ! -d "$ROOT/Open-Jev/.git" ]; then
  git clone -q https://github.com/Zefan-Cai/Open-Jev.git "$ROOT/Open-Jev"
fi
git -C "$ROOT/Open-Jev" fetch -q --depth 1 origin ed45657bf726c3b77408942830e5578f99df904e
git -C "$ROOT/Open-Jev" checkout -q ed45657bf726c3b77408942830e5578f99df904e
COMMIT=$(git -C "$ROOT/Open-Jev" rev-parse HEAD)
[ "$COMMIT" = "ed45657bf726c3b77408942830e5578f99df904e" ] || { echo "COMMIT MISMATCH: $COMMIT"; exit 1; }
echo "Open-Jev HEAD OK: $COMMIT"

echo "=== [2/4] venv-ojev (transformers 5.10.2 / peft 0.19.1 via [train] extra) ==="
uv venv -q --python 3.12 "$ROOT/venv-ojev"
uv pip install -q --python "$ROOT/venv-ojev/bin/python" -e "$ROOT/Open-Jev[train]"
uv pip install -q --python "$ROOT/venv-ojev/bin/python" \
  "flash-linear-attention==0.5.0" requests jsonschema
"$ROOT/venv-ojev/bin/python" -c "import jev, jev.server, jev.serving; print('jev importable OK')"

echo "=== [3/4] fetch 27B base + adapter at pinned revisions ==="
"$ROOT/venv-ojev/bin/python" - <<'PY'
import os, time
from huggingface_hub import snapshot_download
CK = os.path.expanduser("~/sysone/checkpoints")
jobs = [
    ("ZefanCai/Open-Jev-27B-v1.1", "28cf73067d5b337860bbef3c85b8b82ba8730956", CK + "/open-jev-27b"),
    ("Qwen/Qwen3.8-27B", "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0", None),
]
for repo, rev, local in jobs:
    t = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] {repo} @ {rev}", flush=True)
    p = snapshot_download(repo_id=repo, revision=rev, local_dir=local, max_workers=16)
    print(f"    done in {time.time()-t:.0f}s -> {p}", flush=True)
PY

echo "=== [4/4] verify published 27B digests (abort on mismatch) ==="
cd "$CK/open-jev-27b/package/checkpoint"
check() {  # file, expected
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" = "$2" ]; then echo "OK       $1  $got"
  else echo "MISMATCH $1"; echo "  expected $2"; echo "  got      $got"; exit 1; fi
}
check adapter/adapter_model.safetensors 1c857224bd3609c6a71eacf7f71dd021115fcc0f791936b1fc332e915b548a81
check head.pt                           76e382f122abfa4e0c467d860a8d142d2fb6d2a98dc0ef9e19870bfc6eb296b4
check temperature.json                  185c0b85539d195d02a2d4949295f0400fc208d9eb7ac4e5e6c97ebd339a235f
echo "--- model.json / temperature.json ---"
cat model.json; cat temperature.json
du -sh "$HF_HOME" "$CK"
echo "=== FETCH DONE ==="
