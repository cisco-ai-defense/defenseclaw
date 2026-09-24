---
name: gpu-saturation
description: Drive a multi-GPU box to full utilisation and keep it there. Use when launching many model-inference or scoring jobs across several GPUs, when GPUs sit idle while work is queued, when throughput is lower than the hardware should give, or when a studio/instance keeps stopping unexpectedly. Covers the five resource dimensions, the failure modes that look like something else, and the order to do things in.
---

# Saturating a multi-GPU box

Written from a night that went 46% → 100% aggregate SM on 4× H200, with a three-hour
outage in the middle. Every number here is measured on that box.

## The one rule that matters most

**Prefetch weights sequentially before launching anything.**

On object-store-backed storage (Lightning `/teamspace`, S3-backed mounts, lazily-hydrating
network filesystems), a file's *first* read pulls from the backing store. Many processes
each pulling individual shards is the worst possible access pattern.

Measured on the same files:

| access pattern | throughput |
|---|---|
| N processes pulling random shards | **6.62 s for one shard** |
| one process streaming files in order | **570–4,731 MB/s** |
| already-hydrated file | 1.7 GB/s |
| page-cache warm | 8.8 GB/s |
| local overlay disk | 9.4 GB/s |

```bash
find /path/to/weights -type f -size +1M | sort | while read -r f; do cat "$f" > /dev/null; done
```

99 GB hydrated in under a minute this way. I/O pressure fell from 80 to 26. Six model
arms that had each been taking two minutes to reach 31% of their shards then loaded in 75
seconds total.

**Do not relocate the cache to "faster" local disk without measuring.** Local overlay read
9.4 GB/s against the network mount's 1.7 GB/s sounds decisive, but the mount only costs
more on first touch — after hydration the difference is irrelevant to a job that reads its
weights once. Relocating 99 GB to gain nothing wastes an hour.

## The five dimensions, and which one actually binds

Check all five. Optimising the wrong one is how hours disappear.

```bash
nvidia-smi --query-gpu=index,utilization.gpu,utilization.memory,memory.used,temperature.gpu,power.draw \
  --format=csv,noheader,nounits          # sample repeatedly; one read is meaningless
cat /proc/pressure/{cpu,memory,io}       # the honest signal
cut -d' ' -f4 /proc/loadavg              # runnable/total THREADS
free -g
```

**`/proc/pressure/*` is the diagnostic that settles arguments.** On the night in question,
load average read 517 on 96 cores while `cpu avg60=0.00` and `memory avg60=0.00` and
`io avg60=79.99`. Load average counts processes blocked in uninterruptible disk wait, so it
looked like catastrophic CPU oversubscription and was entirely I/O.

Verdict logic that has held up:

| binding | signature | action |
|---|---|---|
| **GPU SM** | SM mean *and min* ≥90% | **Optimal — stop.** Unused VRAM is not waste when compute is pegged. More workers queue on busy SMs and slow existing ones. |
| **Disk I/O** | `io avg60` ≥40 | Do not add workers. Prefetch sequentially, wait for io60 under 20. |
| **CPU** | `cpu avg60` ≥20 | Thread caps are not applied. See below. |
| **RAM** | `memory avg60` ≥5 | Reap orphans before adding anything. |
| **VRAM** | ≥85% of total | Rebalance across cards. |
| **none** | all clear | Add workers, ~4 per card, until SM reaches 90%. |

Note `utilization.memory` is memory *bandwidth*, not occupancy. At 100% SM it sat at
35–42%, which confirms small-batch inference is compute-bound and larger batches would not
help — and that was independently A/B'd: `max-batch` 32 against 128 gave 291.8 vs 271.6
rows/min.

### The scaling curve, measured

Adding workers to one card, same model, same slice size, measured over ~550 s windows:

| replicas | aggregate rows/min | per replica |
|---|---|---|
| 2, card shared with another workload | 130.0 | 65.0 |
| 3, card cleared | 270.4 | 90.1 |
| 5, card cleared | 342.0 | 68.4 |

Two things to read off it. **Per-replica throughput falls as you add** — 90.1 to 68.4 — so
aggregate gains shrink while the card approaches 100% SM; going 3 to 5 bought only
+71.6 rows/min. And **evicting a foreign co-tenant was worth more than any replica**: 130.0
to 342.0, a 2.6× gain, came from moving 73 GB of another workload off the card rather than
from adding workers.

So the order is: clear foreign tenants first, then add workers until SM pins, then stop. A
6th replica here would not have fit anyway — 6 × 24.6 GiB projected peak against 143,771 MiB
— which is the other reason to compute the projection rather than discover it with an OOM.

## Thread exhaustion, the failure that looks like everything else

Symptom: **ssh completes key exchange, the server accepts your key, then closes the
connection.** Nothing in any log. GPUs fall to 0%. Memory looks fine.

Cause: the box cannot fork. `sshd` needs to fork a session and there is no capacity.
Thread count climbed 5,102 → 7,922 across an evening from 19 concurrent arms, each running
`torch.get_num_threads()=48` plus a HuggingFace `tokenizers` Rayon pool sized to all 96
cores.

```bash
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false
```

**Export these in the launching environment, before the interpreter starts.** Setting them
inside Python after the torch import is too late. Keep an `os.environ.setdefault` before
the torch import as a backstop for stray manual invocations, but the export is the
load-bearing part. Verify by logging `torch.get_num_threads()` per worker.

Also set `torch.set_num_threads(4)` **unconditionally**, not only on a CPU code path — that
conditional was the actual bug that left GPU workers at 48 threads.

Safe ceiling observed: 4,348 threads with 16 workers was fine; 7,922 broke the box.

## `pgrep -f` is unreliable for counting, not just for killing

The `pkill -f` prohibition is well known — a pattern kill matches other people's work, and
`pkill -f X` also matches your own invoking command line.

**The same self-match breaks counting.** A concurrency limiter using
`pgrep -c -f 'score_arm.py --arm'` counted the monitoring ssh command lines that contained
that string, inflated its own count, and stalled forever waiting for a limit it could never
satisfy.

Walk `/proc` instead:

```bash
n=0
for p in /proc/[0-9]*; do
  tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q 'score_arm.py' && n=$((n+1))
done
```

## Long-lived model servers leak host RAM, and this is the root cause

Everything else in this file — thread exhaustion, cold hydration, idle shutdown — was
downstream of one defect on the night this was written: **a server process that stays up
grows its host RSS without bound.**

Measured across four identical shims serving an 18 GB model at a fixed batch shape, with no
restarts and no change in workload:

| process age | RSS |
|---|---|
| at startup | ~20 GB |
| 1h55m | 37.8 GB |
| 2h06m | 43.5 GB |
| 2h35m | 51.2 GB |
| **3h30m** | **86.7 GB** |

That is **~0.21 GB/min per process**, tracking age almost linearly and still linear at the
end — **4.3× growth over 3.5 hours** to serve an 18 GB model. A separate 2B model's server
reached **117 GB** before the first collapse, and a 9B's reached 69 GB.

Retiring three such processes took the box from **247 GB used to 14 GB used / 418 GB
available**. So on this machine the leak accounted for essentially the entire memory history
of the night: what presented as thread exhaustion, cold S3 hydration and idle shutdown were
all downstream of long-lived servers growing without bound.

**`MemAvailable` is not an early warning — it is a post-mortem.** The kernel killed two
running jobs at 243 GB of 432 GB with **zero cgroup OOM events recorded**
(`memory.events` showed `oom 0 oom_kill 0 oom_group_kill 0`, and `memory.max` was
unlimited), and their logs ended mid-progress with no error and no traceback. So a silent
death with a clean log is the signature. Watch the **RSS trend per long-lived process**
instead, and act on the slope rather than the level.

Mitigations, in order of value:

1. **Reap a server the instant its driver exits.** See below. Four reaps on one night
   returned 117 GB, 48 GB, 70 GB and ~100 GB.
2. **Retire the oldest and largest servers first** when memory tightens. Age predicts RSS,
   so oldest-first is also biggest-first. Retiring 2 of 5 replicas reclaimed ~100 GB and cost
   **9.5%** aggregate throughput, not the ~21% a naive reading of the scaling table
   predicted — because the earlier 3-replica datapoint had been measured on a contended card
   and was never a like-for-like comparison. Re-measure rather than extrapolating.
3. **Stop there.** A rolling restart to reclaim memory you do not need costs work in flight
   for nothing.

## Reap orphaned servers, every time

A server process whose driver has exited holds its memory and serves nothing. One held
**117 GB of 432 GB for over an hour** and was the enabling condition for the outage.
Killing it freed 124 GB and returned all four GPUs to 100% within seconds.

Detect it as: a listening port with no driver process referencing that port.

```bash
for port in 8831 8832 8833 8834; do
  ss -tln | grep -q ":$port " || continue
  pgrep -f "driver_script.*:$port/" >/dev/null || echo "ORPHAN on :$port"
done
```

Gate before killing: match the full cmdline, confirm zero established connections to the
port, and confirm no driver references it. Then `kill -TERM <exact pid>`. Never a pattern.

## Idle shutdown counts sessions, not GPU work

A managed studio (Lightning and similar) stops on idle. **Its idle detector watches
interactive sessions, not GPU utilisation.** All four cards at 100% will not save you.

Worse, the two interact: once the box cannot fork, new sessions are refused, so the idle
timer starts precisely when the box is in trouble. And a GPU-poking keepalive that spawns a
subprocess **also cannot fork**, so the protection fails exactly when needed.

Hold a live session instead, cheaply:

```bash
ssh host 'for ((i=0;i<300;i++)); do printf "hb %(%H:%M:%SZ)T\n" -1; sleep 60; done'
```

`printf %()T` is a bash builtin, so this is one fork per minute.

## Order of operations

1. Verify the environment is not still provisioning. A managed studio's setup phase can
   replace packages under a running process — assert imports in the first second of every
   worker and abort loudly rather than dying hours later with `ModuleNotFoundError`.
2. Start a session holder.
3. **Prefetch weights sequentially.** Biggest single win.
4. Reap orphans.
5. Launch ~3 workers per card with thread caps exported. Stagger launches a few seconds.
6. Sample all five dimensions over a window and read the verdict.
7. If nothing binds, add a 4th per card. Repeat until SM ≥90%.
8. Stop when SM mean and min are both ~100%. That is done.

## Measurement discipline for scored output

If workers produce rows that will be compared against existing results:

- **Record full distributions, never argmax.** One model scored 0.332 block-only F1 at its
  shipped argmax and 0.822 re-thresholded on the same forward passes.
- **Never change batch size, concurrency or token budget mid-run.** Batched inference
  changes float reduction order, so rows before and after are not guaranteed identical.
  Throughput comes from more workers on disjoint slices, never from re-tuning a live run.
- **Per-driver budget caps are per-driver.** A 200M input-token cap killed a run at row
  70,833 of 100,001, writing `route: "error"` on every remaining row and skipping the
  metadata — a body that looks complete and is unusable. Sharding across four drivers
  avoids it for free.
- Resume support must **verify** rather than trust: check the on-disk row N against the
  rebuilt plan's key and hard-abort rather than append on mismatch. A misalignment should
  cost one run, never a corrupt body.
- A run is valid only if its meta says `complete: true` **and** the on-disk sha256 equals
  the recorded `prediction_sha256`. If a harness does not write those, say the integrity
  check is **unverifiable** rather than reporting a pass.

## Coordination on a shared box

Several agents and people may share the machine. A job queue that reports worker liveness
says nothing about card availability — directly-pinned processes are invisible to it. A
queued job was handed a card already at 89% memory and its engine failed to initialise with
no "out of memory" string anywhere in the log.

Keep a reservations file that the status command surfaces first, listing card, owner, what
is running, live memory, and expected release. Write it from measurement, not intent.
