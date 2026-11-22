#!/bin/bash
# make_fixture.sh <rundir>: package the PUBLIC rows' inputs and pwsh 7 oracle output as the committed fixture
# (scripts/pwshoracle/fixture/). Private rows (priv.*) are never packaged.
set -eu -o pipefail
W=${1:-/var/tmp/pwsho/run1}; cd "$(git rev-parse --show-toplevel)"
F=scripts/pwshoracle/fixture; rm -rf $F; mkdir -p $F
gzip -9 -c $W/pub.b64 > $F/pub.b64.gz
gzip -9 -c $W/pub.oracle.jsonl > $F/pub.oracle.jsonl.gz
gzip -9 -c $W/pub.oview.jsonl > $F/pub.oview.jsonl.gz
cp $W/pub.ids $F/pub.ids
cp $W/pub.oracle.version $F/oracle.version
( cd $F && sha256sum pub.b64.gz pub.oracle.jsonl.gz pub.oview.jsonl.gz pub.ids oracle.version > SHA256SUMS )
cat > $F/README.md <<'EOR'
# PowerShell oracle fixture

Recorded output of Microsoft's real PowerShell parser (`System.Management.Automation.Language.Parser.ParseInput`,
pwsh 7.6.6) over every public PowerShell row of our corpora and generators. Test data for the differential oracle of
`internal/pwshparse`; regenerate with `scripts/pwshoracle/run_all.sh`.

- `pub.b64.gz`: one base64 (UTF-8) script per line, deduplicated. Row N is line N (0-based).
- `pub.ids`: row id and the corpora the row came from, one line per row (`pw-<sha1 prefix>`; same order).
- `pub.oracle.jsonl.gz`: one JSON object per row: `i`, `ast` (pre-order `[depth, type, start, end, {props}]`),
  `tok` (`[kind, flags, start, end, value]`), `err` (`[errorId, start, end]`). Offsets are UTF-16 code units.
- `pub.oview.jsonl.gz`: the reading view derived from it (commands, arguments, string kinds, redirections, script blocks,
  pipelines) by `oracle_view.py`; this is the shape `scripts/pwshoracle/psview` prints for `internal/psparse`.
- `oracle.version`: the pwsh version that produced the output.

Rows from real agent traces are private and are not in this directory.
EOR
du -sh $F; ls -la $F
