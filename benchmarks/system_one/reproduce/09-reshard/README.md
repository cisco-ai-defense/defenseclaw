# 09-reshard - recovering the `bespoke-nimble-9b` s3 run by chunked resharding

The s3 cell for `bespoke-nimble-9b` (100,001 requests over 24,476 cases at the parity grid
`C7` / `I3` / `Q2`, `instruction_format: structured`) was driven by a single forward-walking
worker (`shard0`). To finish it inside the available window, the remaining tail was cut into
independent chunks and handed to extra replicas on one spare card, then merged back into one
artifact.

The design constraint that makes this sound: **a chunk's requests must be byte-identical to
the requests `shard0` would have produced for the same cases.** `verify_slice_identity.py`
is the proof of that, and `merge.py` re-checks it position-by-position before writing.

## The partition

`chunks.json` holds the plan actually used: `n_chunks: 67`, `cmax: 66`, target ~1500
requests per chunk, whole-case aligned (no case is split across chunks). Each entry carries
`chunk`, `case_start`, `case_end`, `cases`, `req_start`, `req_end`, `requests`, `shard`.

Chunks are claimed in **descending** order while `shard0` walks **forward**, so the two
meet in the middle. `shard = cmax - chunk + 1` makes descending claims produce contiguous
shard numbers.

## Scripts

| script | what it does |
|---|---|
| `analyze.py` | Confirms how `agree/s3-cases.jsonl` expands into requests and checks the live driver's row ordering against the on-disk `shard0` prefix. Writes `reshard/case_index.json` (`ids`, `counts`, `cum`). |
| `make_chunks.py` | Reads `case_index.json`, greedily partitions into whole-case-aligned chunks of ~1500 requests, writes `chunks.json`. |
| `next_chunk.py` | Atomically claims the highest unclaimed chunk (`mkdir reshard/claims/<chunk>/` as the lock) and materialises its slice by copying case lines **verbatim** out of `agree/s3-cases.jsonl` into `runs/nimble-s3/cases-shard<N>.jsonl`. Prints `chunk shard case_start req_start requests slice_path`, or nothing when exhausted. Refuses to claim past the point `shard0` has already reached, which is what prevents duplicated rows. |
| `worker.sh` | One dispatcher per replica (arg: port). Loop: claim a chunk, run `benchmark_run_system_one.py` against the slice, gate with `check_chunk.py`, retry error rows with `--resume --resume-retry-errors`, then write `reshard/done/<chunk>.json`. Honours a `reshard/STOP` sentinel. |
| `check_chunk.py` | The completion gate. Args: meta path, body path, expected request count. |
| `check_recoverable.py` | **Read-only.** Decides whether a cap-tripped body can be salvaged by `--resume --resume-retry-errors`, by checking that every error row still validates against `cfg/system-one-prediction-v1.schema.json`, carries the right `run_id`/`model`, and has a `request_sha256` that matches a freshly rebuilt canonical request. Reports `clean_prefix_rows`, `error_rows_failing_schema`, `error_rows_missing_request_sha256`, `mismatches`. Writes no durable output. |
| `verify_slice_identity.py` | The identity proof. For a case range `[a,b)` that `shard0` already covered, builds the slice the same way `next_chunk.py` does, re-derives every request, and compares `case_id`, `event_index` and `request_sha256` against `shard0`'s actual rows. Exit 1 on any mismatch. |
| `merge.py` | Merges the `shard0` prefix plus the banked chunk shards into `runs/nimble-s3/settled/bespoke-nimble-9b.jsonl` (+ `.meta.json`). Validates everything *before* writing anything; only writes under `--write`. |
| `status.py` | Progress/ETA. Reads shard row counts, `claims/`, `done/`, and the previous `rate.json` snapshot; rewrites `rate.json`. |
| `monitor.sh` | Detached recorder, one status line every 120s; honours `reshard/STOP_MONITOR`. |
| `start_replicas.sh` | Brings up N extra `nimble_shim.py` replicas pinned to **card 3 only** (`CUDA_VISIBLE_DEVICES=3`), under identical serving conditions to the original card-2 server: same checkpoint, `--max-length 8192`, `--device cuda:0`, `attn_implementation="sdpa"`. Logs to `reshard/logs/serve-nimble-<port>.log`. |

## When is a chunk "banked"?

This is the term used in the archive manifests, and it is precise:

1. **Unclaimed** - no `reshard/claims/<chunk>/` directory.
2. **Claimed** - that directory exists (created with `mkdir`, which is the atomic lock).
3. **Banked** - `reshard/done/<chunk>.json` exists with `"status": "ok"`.

`"status": "ok"` is written by `worker.sh` only after `check_chunk.py` passes, which requires
all of:

- `meta["complete"] is True`
- `meta["requests"]` equals the expected count from `chunks.json`
- `meta["model"] == "bespoke-nimble-9b"` and
  `meta["model_revision"] == "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c"`
- `meta["contexts"] == ["C7"]`, `meta["instructions"] == ["I3"]`,
  `meta["questions"] == ["Q2"]`, `meta["instruction_format"] == "structured"`
- **zero** rows carrying an `error_code` or `route == "error"`

The other two terminal states are `"status": "failed"` (the driver itself failed) and
`"status": "gate_failed"` (the gate rejected it even after an error-row retry). Neither is
mergeable.

`merge.py` independently re-verifies, per chunk shard, that `meta["complete"] is True` and
that `sha256(body)` equals `meta["prediction_sha256"]`, and then re-checks plan identity
across all 100,001 output positions. A chunk that fails any of that stops the merge rather
than silently degrading the artifact.

## Meta artifacts

Per-chunk metas are emitted by the driver at
`runs/nimble-s3/bespoke-nimble-9b-shard<N>.jsonl.meta.json` and carry `complete`,
`prediction_sha256`, `requests`, `model`, `model_revision`, `contexts`, `instructions`,
`questions`, `instruction_format`, `run_id`, `actual_input_tokens`,
`reserved_input_tokens`, `attempted_provider_calls`, `schema_version`.

The merged meta additionally carries `stage`, `cases`, `cases_sha256`, and `serving{}` /
`merge{}` provenance blocks.

## Results this produced

The settled `bespoke-nimble-9b` s3 artifact under `runs/nimble-s3/settled/`, which is the
s3-side input to the held-out `s2 -> s3` transfer analysis in
`../07-analysis/rescoring/transfer_s2_to_s3.py`.

Note that the `shard0` body and the chunk shards are all pinned to the same single cell -
this tooling recovers one cell faster, it does not widen the grid.
