# Guardrail Rule Packs & Suppressions

Use this guide when the guardrail is working, but you need to tune a false
positive without turning off the entire judge. The most common example is a
real application username being flagged as `JUDGE-PII-USER`.

## Two layers control guardrail behavior

DefenseClaw splits guardrail behavior across two separate layers:

| Layer | What it controls | Typical way to change it |
|---|---|---|
| OPA policy | Block / alert thresholds, severity-to-action behavior, enforcement rules | `defenseclaw policy activate default|strict|permissive` |
| Guardrail rule pack | Judge prompts, PII category severity, pre-judge strips, `suppressions.yaml`, sensitive tool rules | `guardrail.rule_pack_dir` in `~/.defenseclaw/config.yaml` |

The important gotcha is that these are **not the same switch**.

`defenseclaw policy activate strict` updates the OPA-backed policy data, but it
does **not** change `guardrail.rule_pack_dir`. If you want the strict rule
pack, point `guardrail.rule_pack_dir` at the strict profile as well.

## Where the files live

The active rule pack is selected by `guardrail.rule_pack_dir` in
`~/.defenseclaw/config.yaml`.

Common built-in locations are:

- `~/.defenseclaw/policies/guardrail/default/`
- `~/.defenseclaw/policies/guardrail/strict/`
- `~/.defenseclaw/policies/guardrail/permissive/`

Inside each profile directory you will usually see:

- `judge/*.yaml` for category prompts and severities
- `sensitive_tools.yaml` for tool-level rules
- `suppressions.yaml` for false-positive tuning

DefenseClaw ships built-in defaults for these files. In a normal install,
`defenseclaw init` seeds editable copies under `~/.defenseclaw/policies/`.
If your install does not have a guardrail directory yet, create the active
profile directory and add `suppressions.yaml` yourself.

## Check which rule pack is active

Look at `guardrail.rule_pack_dir` in `~/.defenseclaw/config.yaml`.

```bash
grep -n "rule_pack_dir" ~/.defenseclaw/config.yaml
```

If it is missing, DefenseClaw defaults to the `default` rule pack under your
data directory.

To use the strict rule pack, set the value to the full path for your machine,
for example:

```yaml
guardrail:
  rule_pack_dir: /home/alice/.defenseclaw/policies/guardrail/strict
```

Use the matching profile path if you want `default` or `permissive` instead.

## Add a targeted suppression

If the active profile already has a `suppressions.yaml`, keep the file and add
just the new item under `finding_suppressions:`.

If the file does not exist yet, create it with this shape:

```yaml
version: 1

pre_judge_strips: []

finding_suppressions:
  - id: SUPP-APP-USERNAME
    finding_pattern: JUDGE-PII-USER
    entity_pattern: '^(your-app-username)$'
    reason: "Allowed application username"

tool_suppressions: []
```

What each field means:

- `finding_pattern`: the judge finding to suppress
- `entity_pattern`: a regular expression for the exact value to allow
- `reason`: why this is safe in your environment

For a username false positive, prefer a narrow exact-match regex like
`'^(your-app-username)$'` instead of a broad pattern that could hide real
findings.

## Restart after editing

Restart the gateway so the sidecar reloads the rule pack:

```bash
defenseclaw-gateway restart
```

If the binary is not on your `PATH`, use the installed path instead:

```bash
~/.local/bin/defenseclaw-gateway restart
```

Then replay the original prompt that was being blocked.

## Which lever should you use?

Use a targeted suppression when:

- one known-safe value is noisy
- you still want the judge enabled for everything else
- the false positive is tied to a specific entity such as a username, host,
  or internal ID

Switch from `strict` to `default` or `permissive` when:

- the whole profile is too aggressive for your environment
- you want broader changes to severity and blocking behavior

Disable only prompt-side PII judging when:

- prompt-side PII blocks are the issue
- you still want completion-side PII inspection

Example:

```yaml
guardrail:
  judge:
    pii: true
    pii_prompt: false
    pii_completion: true
```

## Common gotchas

- `policy activate strict` does not switch `guardrail.rule_pack_dir`
- editing `default/suppressions.yaml` has no effect if the active rule pack is
  `strict`
- if the file is missing on disk, built-in defaults can still load, so create
  the file if you want a persistent local override
- restart `defenseclaw-gateway` after changing rule pack files
