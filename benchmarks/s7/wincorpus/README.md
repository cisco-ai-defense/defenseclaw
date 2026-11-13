# Windows shell corpus (windows-shell)

Builder for the S7 Windows shell corpus (rel-1-0-10:GAP-0019). It produces `windows-shell.cases.jsonl` (case-v1), kept separate from every other corpus.
The corpus data is not in git: it lives on dev at `~/dc-eh/evidence/rel-1-0-10/s7/corpus/windows-shell.cases.jsonl` and on dc-build-1 at
`~/s7c/corpora/windows-shell.cases.jsonl`, and is registered in s7-gate's `corpora_all.json` / `corpora_full.json` as `windows-shell`.

```
python3 benchmarks/s7/wincorpus/build.py build --win-all <windows rows of the normalised agent-transcripts shards> \
    --shell-corpus <gas-ux-r1 corpus-shell.jsonl> --audit-calls <audit_calls.jsonl> --fixture <security_suite/toolcall/corpus.jsonl> \
    --rules-dir policies/guardrail --atomics <atomic-red-team checkout> --credpaths win-credential-paths.cases.jsonl \
    --gapreg gap-regression.cases.jsonl --schema benchmarks/schema/case-v1.schema.json --out windows-shell.cases.jsonl
python3 benchmarks/s7/wincorpus/build.py stats windows-shell.cases.jsonl
python3 benchmarks/s7/wincorpus/build.py audit-sample windows-shell.cases.jsonl --out audit20.tsv     # seeded 20% sample for the label audit
python3 -m unittest benchmarks/s7/wincorpus/test_wincorpus.py
s7-gate run <label> --worktree <rel head worktree> --only windows-shell
```

Sources (category `src:<name>` on every case): real-owner, real-traces, real-stateful (real benign traffic), capture (round audit logs), fixture and variant
(the product's tool-call TP/FP suite and equivalence-preserving wrappers of it), atomic (Atomic Red Team, MIT, curated), credpaths and gapreg (same case ids as
win-credential-paths and gap-regression), protwrite (writes to protected targets, and reads as hard negatives), authored (authored benign work).
No attack text is written by hand; positives come from the product's own suite, the public Atomic Red Team set, the ledgers, and the wrappers.

Labels: real traffic is benign by default (medium confidence); calls that change DefenseClaw state or carry test markers are `unknown` and excluded.
Suite negatives are kept only when they are plainly ordinary or restoring (`NEG_OK`); the suite's grammar-edge negatives are not labelled.
Atomic tests are kept only when the command performs a class a pack claims or uses a clearly malicious tool; dual-use tweaks are dropped.
`expected_profile_actions` follows the documented posture (strict blocks MEDIUM and above, default blocks CRITICAL, permissive blocks CRITICAL and alerts HIGH).

The harness is a Linux build: Windows readers (`hookpaths/*_windows.go`, the Windows dialect hint) are not exercised. Numbers describe how the Linux engine treats
Windows-shaped input; a GOOS=windows s7bench run on a Windows host is the separate step for the Windows readers.
