#!/bin/bash
# Build the pinned stack on the 4x H200 studio while `uv` and `apt` are still blocked by
# Lightning's lazy image hydration. Two substitutions, neither of which changes the stack:
#   uv  -> python3 -m venv + pip, with the SAME exact pins (identity is the resolved
#          versions, which are recorded and verified, not the installer)
#   apt -> fetch libpython3.12-dev from the Ubuntu archive and extract the headers into a
#          user prefix, then expose them via CPATH. Needed because without Python.h Triton
#          cannot compile its driver shim and flash-linear-attention silently falls back to
#          CPU -- 99 rows/min at 0% GPU, which would make any throughput number invalid.
set -euo pipefail
ROOT="$HOME/sysone"
export HF_HOME="$ROOT/hf"
CK="$ROOT/checkpoints"
INC="$ROOT/pyinc"
mkdir -p "$ROOT"/{logs,agree/cfg,agree/out} "$CK" "$INC"
cd "$ROOT"

echo "=== [1/6] python headers without apt ==="
if [ ! -f "$INC/usr/include/python3.12/Python.h" ]; then
  # zstandard is needed to unpack Ubuntu 24.04's zstd-compressed .deb
  python3 -m venv "$ROOT/venv-boot" 2>/dev/null || true
  "$ROOT/venv-boot/bin/python" -m pip install -q zstandard
  "$ROOT/venv-boot/bin/python" - "$INC" <<'PY'
import io, sys, tarfile, urllib.request
dest = sys.argv[1]
base = "http://archive.ubuntu.com/ubuntu/pool/main/p/python3.12/"
names = ["libpython3.12-dev_3.12.3-1ubuntu0.17_amd64.deb",
         "libpython3.12-dev_3.12.3-1ubuntu0.16_amd64.deb",
         "libpython3.12-dev_3.12.3-1ubuntu0.15_amd64.deb"]
blob = None
for n in names:
    try:
        blob = urllib.request.urlopen(base + n, timeout=90).read()
        print("fetched", n, len(blob), "bytes")
        break
    except Exception as exc:
        print("miss", n, exc)
if blob is None:
    raise SystemExit("could not fetch libpython3.12-dev")

# A .deb is an ar archive; pull out data.tar.* and untar it.
assert blob[:8] == b"!<arch>\n", "not an ar archive"
off, data = 8, None
while off < len(blob):
    hdr = blob[off:off + 60]
    name = hdr[0:16].decode().strip()
    size = int(hdr[48:58].decode().strip())
    body = blob[off + 60: off + 60 + size]
    if name.startswith("data.tar"):
        data = (name, body)
        break
    off += 60 + size + (size & 1)
assert data, "no data.tar member"
name, body = data
if name.endswith(".zst"):
    # Ubuntu 24.04 ships zstd-compressed debs; tarfile has no zstd codec.
    import zstandard
    body = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body)).read()
    mode = "r:"
else:
    mode = {"data.tar.xz": "r:xz", "data.tar.gz": "r:gz",
            "data.tar": "r:"}.get(name, "r:*")
with tarfile.open(fileobj=io.BytesIO(body), mode=mode) as tf:
    tf.extractall(dest, filter="data")
print("extracted", name, "->", dest)
PY
fi
test -f "$INC/usr/include/python3.12/Python.h" && echo "Python.h OK at $INC/usr/include/python3.12"
export CPATH="$INC/usr/include/python3.12:${CPATH:-}"

echo "=== [2/6] Open-Jev loader pinned at ed45657b ==="
if [ ! -d "$ROOT/Open-Jev/.git" ]; then
  git clone -q https://github.com/Zefan-Cai/Open-Jev.git "$ROOT/Open-Jev"
fi
git -C "$ROOT/Open-Jev" fetch -q --depth 1 origin ed45657bf726c3b77408942830e5578f99df904e
git -C "$ROOT/Open-Jev" checkout -q ed45657bf726c3b77408942830e5578f99df904e
C=$(git -C "$ROOT/Open-Jev" rev-parse HEAD)
[ "$C" = "ed45657bf726c3b77408942830e5578f99df904e" ] || { echo "COMMIT MISMATCH: $C"; exit 1; }
echo "Open-Jev HEAD OK: $C"

echo "=== [3/6] venv-ojev via pip, pins matched to studio 1 ==="
python3 -m venv "$ROOT/venv-ojev"
P="$ROOT/venv-ojev/bin/python"
"$P" -m pip install -q --upgrade pip
"$P" -m pip install -q "torch==2.14.0"
"$P" -m pip install -q -e "$ROOT/Open-Jev[train]"
"$P" -m pip install -q "flash-linear-attention==0.5.0" requests jsonschema
"$P" -c "import jev, jev.server, jev.serving; print('jev importable OK')"

echo "=== [4/6] verify Triton compiles and fla does NOT fall back to CPU ==="
cat > "$ROOT/tri_check.py" <<'PY'
import warnings, torch, triton, triton.language as tl
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    import fla.utils
    bad = [str(x.message) for x in w if "roll back to CPU" in str(x.message)]
print("fla_cpu_rollback:", bad if bad else "NONE")
@triton.jit
def add1(X, Y):
    i = tl.program_id(0)
    tl.store(Y + i, tl.load(X + i) + 1.0)
x = torch.zeros(8, device="cuda"); y = torch.empty_like(x)
add1[(8,)](x, y); torch.cuda.synchronize()
print("triton_ok:", y.tolist()[:4] == [1.0, 1.0, 1.0, 1.0])
print("cards:", torch.cuda.device_count(), torch.cuda.get_device_name(0),
      torch.cuda.get_device_capability(0), "torch", torch.__version__)
PY
"$P" "$ROOT/tri_check.py"

echo "=== [5/6] fetch 27B at pinned revisions ==="
"$P" - <<'PY'
import os, time
from huggingface_hub import snapshot_download
CK = os.path.expanduser("~/sysone/checkpoints")
for repo, rev, local in [
    ("ZefanCai/Open-Jev-27B-v1.1", "28cf73067d5b337860bbef3c85b8b82ba8730956", CK + "/open-jev-27b"),
    ("Qwen/Qwen3.8-27B", "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0", None),
]:
    t = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] {repo} @ {rev}", flush=True)
    p = snapshot_download(repo_id=repo, revision=rev, local_dir=local, max_workers=16)
    print(f"    done in {time.time()-t:.0f}s -> {p}", flush=True)
PY

echo "=== [6/6] verify published 27B digests (abort on mismatch) ==="
cd "$CK/open-jev-27b/package/checkpoint"
check() {
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" = "$2" ]; then echo "OK       $1"; else
    echo "MISMATCH $1"; echo "  expected $2"; echo "  got      $got"; exit 1; fi
}
check adapter/adapter_model.safetensors 1c857224bd3609c6a71eacf7f71dd021115fcc0f791936b1fc332e915b548a81
check head.pt                           76e382f122abfa4e0c467d860a8d142d2fb6d2a98dc0ef9e19870bfc6eb296b4
check temperature.json                  185c0b85539d195d02a2d4949295f0400fc208d9eb7ac4e5e6c97ebd339a235f
cat model.json; echo; cat temperature.json; echo
df -h "$HOME" | tail -1
echo "=== STUDIO2 BUILD DONE ==="
