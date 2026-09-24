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

### Recovery and operational helpers

These were written while the run was live, in response to a Lightning studio stop/restart, and
were vendored later than the scripts above.

| script | what it does |
|---|---|
| `reconcile.py` | Reconciles reshard state after the studio stop/restart, then verifies what survived. Two hazards it fixes: `claims/` is **empty** after rehydration, because those were empty directories and object storage does not preserve them — without re-creating claims for the already-completed chunks, `next_chunk.py` would hand them out again; and it re-verifies the bodies that did survive. |
| `release_stale.py` | Releases claims that have no `done` record and no live driver, so the chunk gets re-run. The restart restored old empty claim directories, leaving chunks claimed with nobody working them — a silent coverage gap. A chunk counts as live only if a running driver is matched to it, never by pattern. |
| `audit.py` | Independent audit of the settled artifact, re-derived from the cases file rather than from the merge's own bookkeeping. |
| `check_recoverable.py` | (above) |
| `release_res.py`, `upd_res.py` | Release and update card reservations on the shared studio. |
| `retire_ports.sh` | Retires the shims on given ports, worker → driver → shim, each **by exact PID after matching its cmdline — never a pattern kill**. Needed because `nimble_shim` leaks host RAM (~0.21 GB/min/process; an 18 GB model reached 51 GB RSS at 2h35m), so retiring the two oldest reclaimed ~102 GB. |
| `fix_note.py` | Corrects one provenance claim in the settled meta and re-verifies the body digest. The generated note had said `shard0`'s driver was "stopped at a case boundary it had passed"; it was not signalled at all — it was lost when the studio stopped. The correction is recorded rather than the note being quietly rewritten. |

**`next_chunk.py` was superseded.** The earlier vendored copy claimed chunks on a
strictly-descending frontier (`min(claimed) - 1`) and documented a "meeting guard". That cannot
come back for a gap in the middle, and the studio restart produced exactly that: claimed chunks
with no worker, restored out of order. The copy here claims the **highest unclaimed** chunk, which
fills gaps first and then continues downward, and it stops when the frozen `shard0` prefix already
covers the whole candidate chunk. This is the version the run actually finished under.

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
