# Windows shell corpus (windows-shell)

Builder for the S7 Windows shell corpus (rel-1-0-10:GAP-0019). It produces `windows-shell.cases.jsonl` (case-v1), kept separate from every other corpus.
The corpus data is not in git: it lives on dev at `~/dc-eh/evidence/rel-1-0-10/s7/corpus/windows-shell.cases.jsonl` and on dc-build-1 at
`~/s7c/corpora/windows-shell.cases.jsonl`, and is registered in s7-gate's `corpora_all.json` / `corpora_full.json` as `windows-shell`.

```
python3 benchmarks/s7/wincorpus/build.py build --win-all <windows rows of the normalised agent-transcripts shards> \
    --shell-corpus <gas-ux-r1 corpus-shell.jsonl> --audit-calls <audit_calls.jsonl> --fixture <security_suite/toolcall/corpus.jsonl> \
    --rules-dir policies/guardrail --atomics <atomic-red-team checkout> --credpaths win-credential-paths.cases.jsonl \
    --gapreg gap-regression.cases.jsonl --schema benchmarks/schema/case-v1.schema.json --denylist <real-lab-values.jsonl> --out windows-shell.cases.jsonl
python3 benchmarks/s7/wincorpus/build.py stats windows-shell.cases.jsonl
python3 benchmarks/s7/wincorpus/build.py leakscan windows-shell.cases.jsonl --denylist <real-lab-values.jsonl>     # exit 1 on any hit; prints categories and case ids only
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

## Redaction and the leak scan

Redaction is by category (`wc_lib.redact`, one final pass over every finished row in `redact_row`), with stable numbered placeholders: the first value seen
gets 1, the same value always gets the same placeholder inside one build, and a rebuild from the same inputs numbers it the same way.

| category | placeholder |
|---|---|
| Windows computer names: `EC2AMAZ-*`, `WIN-*`, UNC `\\name\`, `-ComputerName`/`/s` operands | `LABPC<n>` (`LABPC<n>.labdomain<m>.example.com` for a FQDN) |
| other host names: `dc-*` test aliases, `ip-*` / `ec2-*` EC2 names, private-TLD hosts | `labhost<n>` |
| AD / DNS domains (private-TLD suffix, UPN suffix) and NetBIOS domains | `labdomain<n>.example.com`, `LABDOM<n>` (one number for both spellings of a domain) |
| user names: `DOMAIN\user`, UPNs, `/user:` / `-User` / `/grant` operands, the owner's names | `labuser<n>` (built-ins such as Administrator and Guest are kept) |
| home paths with a user name: `C:\Users\x`, `C:/Users/x`, `/c/Users/x`, `/mnt/c/Users/x`, `/Users/x`, `/home/x` | `alice` |
| SIDs `S-1-5-21-a-b-c[-rid]` | `S-1-5-21-1000000000-2000000000-<n>[-rid]` (the RID is kept) |
| IPv4, IPv6 (with zone), MAC addresses | `198.51.100.<n>`, `2001:db8::<n>`, `00:00:5E:00:53:<n>` (documentation ranges; loopback and broadcast are kept) |
| EC2 instance ids, other AWS resource ids, 12-digit account ids, secrets, e-mail | fixed placeholders |

The placeholders are bare tokens on purpose: `<host1>` would be a shell redirection to the guardrail's command parser and change what a rule sees.

Patterns cannot know an arbitrary NetBIOS name or user name, so the build also takes `--denylist`, a jsonl file of the real lab values (`{"cat": ..., "v": ...}`,
categories `computername hostalias labdomain netbios labuser domuser upn labfqdn ip account instance sid`). It is generated on the dev host from the host registry, the
ssh config, the lab AD docs and the identities found in the previous corpus, kept outside git and never printed. The build redacts those values and the leak scan
(`scan_row`, over every string of every row except `source.dataset`) reports any survivor next to the pattern categories; a build with a leak-scan hit exits 1.
