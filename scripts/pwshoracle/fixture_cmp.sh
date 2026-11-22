#!/bin/bash
# fixture_cmp.sh <outdir>: compare the current internal/psparse with the recorded pwsh 7.6.6 fixture
# (no pwsh needed) and write <outdir>/pub.rootcause.md, the disagreement count per root cause.
# Run on a build box: DCB_BOX=<box> dcb <worktree> "bash scripts/pwshoracle/fixture_cmp.sh /var/tmp/<dir>"
# Keep <outdir> outside the worktree copy (dcb sync deletes unknown files there).
set -eu -o pipefail
W=$1; mkdir -p "$W"; cd "$(git rev-parse --show-toplevel)"
F=scripts/pwshoracle/fixture
(cd $F && sha256sum -c --quiet SHA256SUMS)
gunzip -c $F/pub.b64.gz > "$W/pub.b64"
gunzip -c $F/pub.oview.jsonl.gz > "$W/pub.oview.jsonl"
cp $F/pub.ids "$W/pub.ids"
go build -o "$W/psview" ./scripts/pwshoracle/psview
"$W/psview" "$W/pub.b64" "$W/pub.uview.jsonl"
python3 scripts/pwshoracle/compare.py "$W/pub.oview.jsonl" "$W/pub.uview.jsonl" "$W/pub.ids" "$W/pub" --public > /dev/null
python3 scripts/pwshoracle/rootcause.py "$W" pub > /dev/null
echo "rows differing: $(wc -l < "$W/pub.rows.tsv")"
cut -d"|" -f2,3 "$W/pub.rootcause.md" | tail -n +3
