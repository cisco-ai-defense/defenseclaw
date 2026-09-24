# archive - tooling for staging benchmark artifacts to private HuggingFace datasets

## `scan_credentials.py`

Pre-publication credential scan. Run it over everything staged for git or for a HuggingFace
dataset before pushing.

```
python3 benchmarks/archive/scan_credentials.py --selftest      # prove the scanner works
python3 benchmarks/archive/scan_credentials.py PATH [PATH ...] # scan
python3 benchmarks/archive/scan_credentials.py --json PATH     # machine-readable
```

Exit 0 clean, 1 findings. Matches are **redacted in the output** (prefix, suffix, length) so
running the scanner never itself prints a secret.

### Why it is built the way it is

Finding credentials is easy. Not firing on this programme's artifacts is the hard part,
because they are saturated with things that look exactly like secrets:

- sha256 digests in `prediction_sha256`, `context_sha256`, `request_sha256`, `cases_sha256`
- 40-hex git/HF revisions in `revision` / `model_revision`
- an **adversarial security corpus** whose whole point is to contain secret-shaped strings

So there is deliberately **no generic high-entropy rule**. Every rule is anchored on a
credential-specific prefix (`hf_`, `AKIA`, `ghp_`, `sk-ant-`, `AIza`), a PEM header, an
`Authorization:` header, or an assignment to a secret-named field. Values appearing under a
known digest/id key (`DIGEST_KEYS`) are never treated as secrets, and secret-named
assignments whose value is a placeholder (`REDACTED`, `<YOUR_API_KEY>`, `${DB_PASSWORD}`,
`xxxx`, …) are filtered by `is_placeholder()`.

It also carries a `provider_rationale` rule, because raw provider reasoning
(`reasoning_content`, `thinking`, `chain_of_thought`) must not be published either.

### The two controls, and why both are mandatory

`--selftest` runs both and fails if either misbehaves:

- **Positive control** - a fixture seeding every credential class. Proves the scanner *fires*.
  This is not optional theatre: it caught a real bug during development. The
  `secret_assignment` rule had a zero-width `\s*` branch inside its negative lookahead, which
  made the lookahead always succeed and the rule **never fire at all**. A scan without a
  positive control would have reported a confident, meaningless "CLEAN".
- **Negative control** - sha256 digests, revisions, case ids, and the redacted/templated
  secret-shaped strings that legitimately appear in an adversarial corpus. Proves the scanner
  does *not* fire on them, i.e. that a clean result is informative rather than an artifact of
  the scanner being tuned off.

Scanning the scanner itself will report ~11 findings: those are its own fixtures
(`AKIAIOSFODNN7EXAMPLE`, the RFC JWT sample, `hunter2…`), all public example values. Exclude
`benchmarks/archive/` when scanning a staging tree, or read those findings as expected.

## Publication constraints these archives operate under

- **`mcptox` is LOCAL-EVALUATION-ONLY.** Its manifest forbids uploading the corpus, upstream
  payloads, **or any derived case file** to HuggingFace or any other host - aggregate numbers
  only. Gate row-by-row on `source.dataset == "mcptox"`. 2,797 of the 3,402 rows in the
  `intent-real` lane are mcptox-derived, so that lane is ~82% unpublishable at row level. The
  established precedent is to upload a filtered `cases.mcptox-excluded.jsonl` with **both**
  pre- and post-filter digests recorded.
- **`robustintelligence/augur_unsafe_tool_input_eval`** is `redistribution: aggregate-only` -
  the source of `intent-ablation` (18,322 rows) and `toolcall-labels` (9,999 rows). Numbers
  publishable, rows not.
- **Model weights are never archived.** ~97 GiB of checkpoints and GGUFs are re-downloadable
  from the pinned repos/revisions instead.
- **All datasets stay private.** Verify `private: true` before and after every push. The
  HuggingFace Space is public; the datasets are not.
