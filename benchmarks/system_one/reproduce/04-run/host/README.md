# 04-run/host — the controller-side drivers

The scripts that launched, queued and audited System One runs from `defenseclaw-dev`, the
controller. The rest of `04-run/` holds the GPU-side drivers; these are the ones that sat in the
operator's home directory and were never copied into the bundle. Vendored 2026-09-24 from
`defenseclaw-dev:$WORK/` after a blob-hash audit found them only on that host.

Scrubbed like the rest of the bundle: `$WORK` is the operator home, `<GPU_HOST>` the serving host,
`<SSH_KEY>` its key, `<GPU_INSTANCE>` its EC2 id. Placeholders outside a quoted string are quoted
so every `.sh` still parses. Nothing else was changed.

| directory | from the host | what it is |
|---|---|---|
| `drivers/` | `$WORK/*.{py,sh}` | Launchers and queues for every hosted-Jev arm (`jev-arms.sh`, `jev-arm2.sh`, `drive_jev{,2,3,4,5}.py` with their cumulative budget guards), the Q1/Q4 question-format queues (`queue_q4_*.sh`, `q4_*.sh`, `q1_split.sh`), the intent-real and intent-ablation stages (`run_intent_real.sh`, `queue_intent_real.sh`, `replicate_*.sh`, `abl_q4.sh`), and the audits that closed them (`enumerate_gaps.py`, `final_audit.py`, `build_parity.py`, `make_realdet.py`, `native_scores.sh`, `repeatability.py`). `status.sh` is the programme status view. |
| `repeatability/` | `$WORK/.s1-repeat-task/` | Three deliberate repeats of one corpus per backend, and the Gemma 4 flex-vs-default service-tier comparison with its default-vs-default control. |
| `prefix-cache/` | `$WORK/prefix-unit-test/` | The prefix-cache unit test: exports the exact production prompts, runs identical pass sequences on each arm, and compares decision flips and margins. |
| `cachework/` | `$WORK/cw/` | Controlled shim-configuration comparison (`SHIM_COMPACT`, `SHIM_LAYOUT`) on a dedicated shim port. |
| `skill-jev/` | `$WORK/scratch/jevjob/` | Asks OpenJev about skills several ways and writes value-free prediction files; used by the skill-scanner lane, not by a board row. |

`drivers/cw_tunnel.sh`, `drivers/cachework-gpu.sh`, `drivers/cw_rec_stats.py` belong with
`cachework/`; they were in the home directory rather than `cw/` on the host and are kept where the
audit found them.

## Still only on the host

Left out on purpose:

- `$WORK/scratch/` apart from `jevjob/`: about 65 one-off probes, dataset searches and early
  smoke tests from before the protocol was frozen. Nothing published reads them.
- `$WORK/detrules-analysis/`: the deterministic-rules analysis. It belongs to the
  `feat/deterministic-exfil-tamper-rules` work, not this branch.
- `$WORK/.s1-prose*/`, `$WORK/.s1-viz*/`, `$WORK/.slm-space-stage/`: earlier copies of the two
  Space generators, superseded by `08-site-build/` and `../../../slm_toolcall/site-build/`.
