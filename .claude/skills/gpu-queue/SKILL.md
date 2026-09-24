---
name: gpu-queue
description: Submit, monitor and coordinate GPU jobs on the shared 4x H200 Lightning studio. Use this whenever you need to run training, inference, benchmarking or any CUDA workload on the studio, before launching anything on a GPU. Covers the job queue, card reservations, and the environment traps that cause silent failures.
---

# GPU job queue — shared 4× H200 Lightning studio

Several Claude agents and several people share one box with four NVIDIA H200 cards
(143,771 MiB each). Everything here exists so two agents do not land on the same card.

```
ssh s_01m37s22w78v9j8pnsf687m8be@ssh.lightning.ai
```

Queue root: `/teamspace/studios/this_studio/queue`

## Before you submit anything: read the reservations

```bash
cat /teamspace/studios/this_studio/queue/RESERVATIONS.json
```

**The queue reports worker liveness, not card availability.** `status.sh` printing
`card 0 up` means the dispatch loop is alive — it says nothing about whether that card
has free memory. Long-lived benchmark arms are pinned directly with
`CUDA_VISIBLE_DEVICES` outside the queue, and `dispatch.sh` cannot see them.

This has already cost someone a job. On 2026-09-23 a queued vLLM job was handed card 0
while another agent's sweep held 127,841 of 143,771 MiB on it. vLLM reserves ~90% of card
memory by default, so its engine core failed to initialise and the job died with `rc=4`
after 60 seconds. The log contained no "out of memory" string, which is what makes this
failure mode expensive to diagnose.

So: check `RESERVATIONS.json`, and check actual memory, not just worker status:

```bash
nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv
```

If you pin a card yourself outside the queue, **add your own entry** to
`RESERVATIONS.json` and delete it when you are done. That file is the only place
out-of-band usage is visible.

## Submitting a job

**Use `qadd`. Do not hand-write JSON.** Writing it yourself has to survive your shell,
ssh's shell, and then JSON parsing. It breaks, and a malformed line is silently skipped
by every worker.

```bash
ssh s_01m37s22w78v9j8pnsf687m8be@ssh.lightning.ai \
  "/teamspace/studios/this_studio/queue/qadd \
     --id alice-sweep-01 --owner alice \
     --note 'lr sweep seed 3' \
     --cmd 'cd /teamspace/studios/this_studio && python my_train.py --seed 3'"
```

`--id` must be unique, 3–80 chars of letters, digits, dot, underscore or hyphen. Prefix
it with your own name so ids do not collide. `qadd` rejects duplicates and refuses a line
over 3500 bytes so appends stay atomic.

**Keep `--cmd` simple.** Nested quotes are the one thing that reliably goes wrong. If
your command needs quotes, pipes or loops, put it in a script and call the script.

Appends are atomic (`O_APPEND`, single short write) and claiming uses `mkdir`, so any
number of agents can submit and run concurrently with no locking. Never edit or rewrite
`QUEUE.jsonl`; only ever append.

## Monitoring

```bash
bash /teamspace/studios/this_studio/queue/status.sh
```

Shows reservations, queued/running/finished counts, per-card worker state, real card
memory, and the last few results. Per-job output is `queue/logs/<id>.log`; the result
record is `queue/done/<id>.json`.

To retry a job, delete `claims/<id>` and `done/<id>.json`. A worker will pick it up again.

## When to use the queue, and when not to

**Use the queue** for anything bounded: a sweep, a smoke test, an eval pass, a fine-tune
that fits in one card and finishes.

**Pin directly** for a long-lived server-plus-driver arm that must own a card for hours.
That is the established pattern for benchmark arms here — they run under
`nohup setsid` with `CUDA_VISIBLE_DEVICES` set explicitly, not through the queue. If you
do this, you **must** add a `RESERVATIONS.json` entry, because nothing else will tell
other agents.

### Known gap: the queue has no card affinity

`qadd` writes only `{id, owner, note, cmd}`. `dispatch.sh` is launched per card, exports
`CUDA_VISIBLE_DEVICES=$CARD`, and every worker walks the same `QUEUE.jsonl` claiming
oldest-first. **You cannot target or avoid a specific card from a submission.** A job
lands on whichever of the four workers polls first.

You cannot work around this from inside the job: overriding `CUDA_VISIBLE_DEVICES` is
forbidden (see rules below), and exiting early when you see the wrong card burns the job,
because the worker writes `done/<id>.json` on any exit code and will not retry it.

**Until this is implemented: if you need a specific card, pin directly and reserve it.**

#### The design, for whoever closes this gap

Two new optional fields on the record. Both default to today's behaviour when absent, so
existing queued lines and existing workers keep working.

| field | meaning |
|---|---|
| `cards` | allowlist of card indices, e.g. `[2,3]`. Absent means any card. Covers "avoid card 0" by enumerating the complement. |
| `min_free_mib` | require this much *free* VRAM on the card before launching. Absent means no check. |

`min_free_mib` is the more valuable of the two, because card identity is almost never the
real requirement — free memory is. It is what would have prevented the 2026-09-23 failure
above, where a vLLM job was handed a card holding 127,841 of 143,771 MiB.

Three constraints the implementation must respect, all of them load-bearing in the current
design:

1. **Never rewrite `QUEUE.jsonl`.** Appends are atomic only because they are single short
   `O_APPEND` writes. Affinity is a *read-side filter* in the worker: skip records whose
   `cards` excludes your own index. A skipped record stays at the head and is simply picked
   up by the worker it names, so oldest-first ordering still holds per card.
2. **Filter before `mkdir claims/<id>`.** The record is immutable once appended, so a
   pre-claim check cannot go stale. Claiming first and then discovering the wrong card would
   burn the job, because `done/<id>.json` is written on any exit and is never retried.
3. **Check `min_free_mib` twice** — once before claiming, once again as the last thing
   before `exec`. Two workers can both pass the first check, so the second one is what
   actually protects you. This narrows the race to the window between the final check and
   the child's first allocation; it does not eliminate it. Say so in the code rather than
   implying the check is a guarantee.

On a `min_free_mib` failure after the claim, do **not** silently write a normal result.
Release the claim (`rmdir claims/<id>`) and leave no `done/` record, so the job is still
queued. Add a `deferrals` counter to the log line; a job that defers more than a handful of
times is a reservation problem, not a scheduling one, and should surface in `status.sh`.

#### The failure mode this introduces

A job pinned to a card whose worker is not running **waits forever with no signal**. That is
new: today every queued job is eligible for every live worker. `status.sh` must grow a line
for it — for each queued record with a `cards` field, whether any named card has a live
worker, and if not, name the job as unschedulable. Without that line this feature converts
a loud mistake into a silent one.

## Rules that keep this working for everybody

- **One card per job.** `CUDA_VISIBLE_DEVICES` is preset by the worker. Do not override
  it, and do not use `device_map="auto"` — you will land on a card another job owns.
- **Never `pkill` or `killall`.** Several agents share this box; a pattern kill matches
  other people's work. `pkill -f` also matches your own invoking command line, which has
  killed a build here. Stop only an exact PID you have confirmed.
- **Never touch these ports:** 8011, 8765, 8767, 8768, 8831, 8832, 8833, 8834, 8841–8844,
  8921, 8922, 3100. They are ssh tunnels and live model servers.
- **Keep the shared venvs as they are.** `venv-ojev` (transformers 5.10.2 / peft 0.19.1),
  `venv-nimble` (5.17.0 / 0.21.0), `venv-kev` (torch 2.13.0, deliberately older).
  Changing a shared venv silently invalidates other people's measurements. Build your own.
- **Redirect your own output.** The worker captures stdout and stderr per job, but
  anything you background yourself escapes that.

## Environment traps that fail silently

These cost hours each when hit. All are real, all happened here.

**Install `python3.12-dev` and `build-essential` first.** Without `Python.h`, Triton
cannot compile its driver shim, `flash-linear-attention` falls back to CPU, and
throughput collapses to ~99 rows/min at 0% GPU **with no error message**.

**Assert your imports in the first second.** Lightning's `studio-setup` hydration has
completed *after* ssh was already working, silently replacing `accelerate` and removing
`flash-linear-attention`, `pip` and `jev` from under a running process. A long job dying
hours in with `ModuleNotFoundError` is this, not an OOM. Fail fast instead.

**Install `numpy` explicitly and early.** Torch initialises a NumPy bridge at import and
*warns* rather than errors if it is absent, which is how a broken venv looks healthy.

**`uv venv` refuses a stale venv.** `rm -rf` the target before creating.

**Benchmark runners have a token cap.** `benchmark_run_system_one.py` defaults to
`--max-input-tokens 200_000_000`. A full 100,001-request s3 pass needs about 282M, so a
single driver trips at roughly row 70,833 — and it does not stop cleanly. It writes
`route: "error"` on every remaining row and skips the metadata entirely, leaving a
prediction body that looks complete and is unusable. The budget is **per driver**, so
sharding the work across four drivers avoids it for free. Raising the cap is safe: it is
pure accounting and changes no inference parameter.

## Throughput, for scoring-only workloads

If your job scores rather than generates, two settings matter more than batch size:

- `logits_to_keep=1` — otherwise a batch materialises `[batch, seq, vocab]` logits and
  simply will not fit.
- `use_cache=False` — a KV cache for a workload that never generates a token wastes about
  31 GB on a 3B model.

Measured here: the **token budget binds, not the batch count**. `max_batch` 32 against
128 gave 291.8 vs 271.6 rows/min — no gain. Tune the token budget, leave batch count alone.

Encoder classifiers are roughly 8× faster than generative arms at the same task, because
there is no generation step at all.

## Measurement discipline

If your job produces rows that will be compared against existing results:

- A run is valid only if its meta says `complete: true` **and** the on-disk sha256 of the
  prediction body equals `prediction_sha256`. Verify both.
- **Runs cannot be spliced.** Multi-shard merges are fine, but only when every row was
  produced under identical serving conditions. Batched inference changes float reduction
  order, so a row produced at concurrency 4 is not bit-identical to the same row at
  concurrency 32. Never change concurrency, batch size or attention implementation
  mid-run to go faster.
- **Record full distributions, never argmax.** Storing only a label throws away every
  threshold, every ranking variable and every decision rung. One model here scored 0.332
  block-only F1 at its shipped argmax and 0.822 re-thresholded on the same forward passes.

## Restarting a worker

Workers are plain loops; losing one costs nothing but throughput.

```bash
cd /teamspace/studios/this_studio/queue
nohup setsid bash dispatch.sh 0 > logs/dispatch-0.log 2>&1 &
```

When the queue drains, each worker pokes its card every 45 s with a tiny bf16 matmul.
That keeps the studio from idle-stopping, so an empty queue is not a problem — add work
and it gets absorbed.
