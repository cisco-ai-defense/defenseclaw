# DET111 probe, generators and comparison (bar step 0b)

Test-only. Nothing here changes a verdict.

- `internal/gateway/det111_probe_test.go`, `det111_rows_test.go`, `det111_gen_test.go`: `TestDET111Probe`, skipped unless `DET111_OUT` is set.
  It sends every row through the real hook path in the five tiers of `gap0437Packs` (default, strict, permissive, managed,
  managed-strict) on each route (hook-cc, hook-codex, inspect-oc, llm, the connector's own tool name `as-is`, and the native
  connector shapes of the P-PARITY train), in the POSIX flavor and the Windows hook-host flavor
  (`windowsHookHost`, `sameHostHomeForTest`, `C:\Users\alice`). It writes `key|tier|route|action severity rule_ids`.
- Rows: case-v1 files (`DET111_CASES`) and the generators (`DET111_GEN=corpus,r1,r2w,r2o,r3`).
  Generators: R1 bodies (sh -c, here-document, here-string, `. /dev/stdin`, `source <(...)`, eval, staged file, `find -exec`,
  `xargs sh -c`, `powershell -Command`, `-EncodedCommand` with blanks and tabs, `Start-Process -ArgumentList`, `& { }`,
  `foreach` header, `cmd /c`), R2 wrappers (one and two deep) and option spellings per program shape, R3 path spellings
  (`~`, `~login`, `~other/../login`, `$HOME`, `${HOME}`, `$env:USERPROFILE`, `%USERPROFILE%`, cd then relative, pushd, `x/..`,
  drive-relative, MSYS `/c/`, forward slashes, UNC admin share). Seeds: the TD target table x shapes (own tree), and every
  corpus row that alerts or blocks at 1.0.10 (`seeds-a64bfdb931.txt`); benign seeds: corpus rows with `expected_disposition=allow`
  (`DET111_BENIGN_CASES`: a deterministic sample of the owner transcript corpus, never committed; without it the allow rows of the corpus files, sampled by `DET111_BENIGN`). Each attack variant has a benign twin (same spelling, non-protected target).
- `det111-run-v5.sh <outdir> [shards]`: builds the test binary and runs the shards in parallel on a build box (run it through
  `DCB_BOX=<box> dcb <worktree> '...'`). Last line `DET111RUN rows=N lines=N errors=N shards=N bad=N sha=<sha> dirty=<0|1>`;
  exit 1 when a shard failed, a shard printed no `DET111_ROWS` line or no rows were written.
- `det111cmp.py`: `props RUN` (generator properties inside one run), `cmp HEAD BASE` (weaker/stronger rows per tier, benign
  raises, missing rows), `all HEAD BASE` (both, one verdict line `DET111CMP PASS|FAIL|NOT-READY ...`), `seeds RUN`
  (corpus ids that alert or block). Exit 0 PASS, 1 FAIL, 2 NOT-READY (a missing or unreadable row never passes).
  Allowed weaker rows are only the owner-ruled gaps in `OWNER_RULED` (GAP-1611, 1698, 0851, 0962).

Properties: an attack variant is at least the seed (action, then severity) with the seed's rule ids; a benign twin is no
stronger than the twin of the seed; a benign variant is no stronger than its benign seed. The LLM tool-call route carries no
working folder, so cwd-relative spellings are not judged there.

Run (base and head the same way, then compare):

    DET111_CASES=<comma list> DET111_GEN=corpus bash benchmarks/s7/det111/det111-run-v5.sh out/corpus-<side> 32
    DET111_CASES=<comma list> DET111_SEEDS=benchmarks/s7/det111/seeds-a64bfdb931.txt DET111_GEN=r1,r2w,r2o,r3 \
      DET111_ROUTES=hook-cc,hook-codex,inspect-oc,llm DET111_NATIVE=0 bash benchmarks/s7/det111/det111-run-v5.sh out/gen-<side> 48
    python3 benchmarks/s7/det111/det111cmp.py all out/gen-head out/gen-base
    python3 benchmarks/s7/det111/det111cmp.py cmp out/corpus-head out/corpus-base

## Gen run and R-NOLOSS (tracked since rel-1-0-10:GAP-1969)

The probe files, the runner and the comparison scripts are tracked here, so a fresh worktree runs the gen with no hand copy.
The bar (det111-bar-v*.sh) still copies its pinned kit over these paths at run time and restores them after.

- `det111-gen-v1.sh <indir> <outdir> [workers]`: the gen every train runs (generators r1,r2w,r2o,r3; routes
  hook-cc,hook-codex,inspect-oc,llm; DET111_BENIGN=700; no native shapes), then `det111-noloss-v2.py` against every
  reference run named in `DET111_REFS="t20=<dir>,t21f=<dir>,t23b=<dir>"`. `<indir>` must hold exactly the bytes in
  `gen-inputs-v1.sha256` (checked first; anything else is NOT-READY). `<outdir>/kit.txt` records the kit hash and the
  head sha: put both in the testctl row. Last line `DET111GEN PASS|FAIL|NOT-READY ...`; exit 0, 1 or 2.
  The run uses a TMPDIR of its own next to `<outdir>`, so a box guard that sweeps the shared temp folder cannot
  change verdicts mid-run (GAP-2113).
- `openloop-quiet-gate.sh <gateway test binary> [tries] [pause]`: the fail-closed step for the open-loop latency tests
  (TestGAP0490OpenLoop{SandboxStream,TwoSandboxes,FourSandboxes}; with DC_GAP0490_OPEN_LOOP_BUDGET=1 also the opt-in account-budget streams). Under measured CPU
  contention they end as the named skip `GAP-1456 INCONCLUSIVE, box short of CPU (...)`, which prints the probe values and
  limits (rel-1-0-10:GAP-2129). The step reruns them until each has RUN and PASSED once. If one never passed, or any run
  failed, the gate fails. Last line `OPENLOOP_GATE PASS|FAIL tries=N runs=R skipped=S passed=P failed=F <Test>=pass/skip/fail ...`.
- `det111-noloss-v2.py REF HEAD [--base BASE] [--out FILE]`: R-NOLOSS. Counts attack cells weaker at HEAD, benign and
  twin cells raised or newly blocked, REF cells HEAD lost, error verdicts and rows with no role; any of them fails.
  Replaces lanes/trg-nl-v1.py and trg-br-v1.py, which never saw a lost cell and always exited 0.
  Tests: `python3 -m pytest benchmarks/s7/det111/test_det111_noloss.py`.

Stage the inputs on the box (from dev), then run:

    D=/var/tmp/det111-train/in; C=~/dc-eh/evidence/rel-1-0-10/s7/corpus; G=~/dc-eh/plans/r111/detection/corpus
    # copy $C/{gap-regression,windows-shell,win-credential-paths}.cases.jsonl, $G/gaps-{A,B,C}.cases.jsonl and the
    # bar kit's meta-<pin>/in/owner-benign.cases.jsonl to $D on the box
    DET111_REFS=t20=/var/tmp/det111-train/gen-t20i,t21f=/var/tmp/det111-train/gen-t21f \
      bash benchmarks/s7/det111/det111-gen-v1.sh /var/tmp/det111-train/in /var/tmp/det111-train/gen-<tag> 40
