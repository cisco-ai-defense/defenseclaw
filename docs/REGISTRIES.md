# Registries

DefenseClaw operators use **registries** to bring an external catalog
of skills and MCP servers under admission control without paving over
their existing vendor relationships. A registry is a fetchable
manifest — corporate HTTPS YAML, smithery.ai, a git repo, ClawHub —
that DefenseClaw ingests, scans, and (when clean) auto-promotes into
`asset_policy.{skill,mcp}.registry` so the gateway treats every
matching asset as an approved entry.

This page covers the v1 surface: skills and MCPs only. Plugins follow
the same pattern but are scaffolded behind the existing
`asset_policy.plugin.*` block until the v2 plugin manifest lands.

---

## Mental model

```
┌──────────────────┐   fetch + size cap   ┌──────────────────┐
│ external catalog │ ───────────────────► │ DefenseClaw CLI  │
│ (https / smithery│                      │ registries/      │
│  / git / file /  │ ◄─── SSRF guard ──── │ adapters         │
│  clawhub)        │                      └────────┬─────────┘
└──────────────────┘                               │
                                                   │ parse + validate
                                                   ▼
                                          ┌──────────────────┐
                                          │ JSON Schema +    │
                                          │ hand-written     │
                                          │ invariants       │
                                          └────────┬─────────┘
                                                   │
                       scan via existing skill /   │
                       mcp scanners (or skipped    │
                       with --no-scan)             ▼
                                          ┌──────────────────┐
                                          │ ~/.defenseclaw/  │
                                          │ registries/<id>/ │
                                          │ index.json       │
                                          └────────┬─────────┘
                                                   │ promote clean
                                                   │ entries
                                                   ▼
                                          ┌──────────────────┐
                                          │ asset_policy.    │
                                          │ {skill,mcp}.     │
                                          │ registry         │
                                          │ Reason="registry:│
                                          │  <id>"           │
                                          └──────────────────┘
```

Every promoted rule carries `Reason="registry:<source-id>"`. The
gateway preserves this on `AssetPolicyDecision.RegistrySource` so
audit events and the TUI can attribute the rule back to the source
that promoted it.

---

## Source kinds

| Kind | Description | Required URL? |
|------|-------------|---------------|
| `clawhub` | Synthesises a manifest from the npm `openclaw` package metadata | No (defaults to npm) |
| `smithery` | Public smithery.ai catalog API | No (defaults to `https://registry.smithery.ai`) |
| `skills_sh` | [skills.sh](https://skills.sh/) public catalog (Vercel-maintained, GitHub-hosted skills) | No (defaults to curated view) |
| `http_yaml` | Corporate HTTPS YAML manifest | Yes |
| `http_json` | Corporate HTTPS JSON manifest | Yes |
| `git` | Git repo containing `defenseclaw-registry.yaml` at root (HTTPS clones only) | Yes |
| `file` | Local manifest file (air-gapped, regression tests) | Yes (absolute path) |

`http://` is accepted but flagged. `file://`, `ssh://`, `git://` are
intentionally rejected by the SSRF guard — see the [security
notes](#security-notes) below.

### skills.sh views

The `skills_sh` adapter accepts an empty URL (defaults to the
curated/official view), one of the bare keywords below, or a full
`https://skills.sh?view=...&per_page=...&max=...` URL with caps:

| URL value | Endpoint | Use case |
|-----------|----------|----------|
| `` (empty) or `curated` | `/api/v1/skills/curated` | Default. Publisher-vetted official skills only |
| `all-time` | `/api/v1/skills?view=all-time` | Mirror broad popular usage |
| `trending` | `/api/v1/skills?view=trending` | Recent-growth feed |
| `hot` | `/api/v1/skills?view=hot` | Last-hour vs same-hour-yesterday |

Caps: `per_page` 1..500 (default 50), `max` 1..2000 (default 200).
Entries flagged `isDuplicate=true` by skills.sh are filtered out.
Auth tokens are read from `auth_env` (env var **name**, never the
literal token) and sent as `Authorization: Bearer <token>` —
`mailto:skills-api@vercel.com` to obtain an API key for higher rate
limits.

---

## Manifest schema

Manifests are validated against
[`schemas/registry-manifest.schema.json`](../schemas/registry-manifest.schema.json).
Sample manifests live in [`bundles/registries/`](../bundles/registries/):

* [`example-skill-catalog.yaml`](../bundles/registries/example-skill-catalog.yaml)
* [`example-mcp-catalog.yaml`](../bundles/registries/example-mcp-catalog.yaml)

Top-level shape:

```yaml
schema_version: 1
publisher: "acme"        # optional
generated_at: "2026-05-07T00:00:00Z"  # optional
default_connector: openclaw  # optional fallback
entries:
  - name: my-skill
    type: skill
    source_url: clawhub://my-skill
    sha256: "<64 hex>"   # required for https:// skills, optional for clawhub://
    connector: openclaw
  - name: my-mcp
    type: mcp
    transport: stdio
    command: npx
    args: ["-y", "@scope/server"]
    env_required: ["MY_API_KEY"]   # NAMES only, never values
```

Security-relevant invariants enforced by the parser (and by the JSON
Schema when the optional `jsonschema` package is installed):

* `name` must match `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$` — keeps the
  identifier safe to use as a directory name, scanner subprocess
  argv, audit query.
* `command` must match `^[A-Za-z0-9_./@-]*$` — refuses shell
  metacharacters at parse time.
* `source_url` for skills must start with `clawhub://`, `https://`,
  or `http://`. `file://` is intentionally NOT accepted in published
  manifests; operators that want to ingest local catalogs register
  the source itself with `kind=file`.
* `env_required` lists ENV VAR **names** (uppercase only) — DefenseClaw
  never copies tokens through a manifest.
* Per-field length caps; a hard cap of 10 000 entries per manifest.
* Manifest payload capped at 8 MiB during fetch.

---

## CLI

All commands sit under `defenseclaw registry`. Every subcommand
supports both interactive (default) and non-interactive
(`--non-interactive`) modes; the non-interactive form is what the TUI
and CI/CD pipelines call, with `--json` for machine-readable output.

| Command | Description |
|---------|-------------|
| `registry add <id>` | Register a new registry source |
| `registry edit <id>` | Update an existing source |
| `registry list` | List configured registry sources |
| `registry show <id>` | Show details + verdict summary for one source |
| `registry remove <id>` | Delete a source and its on-disk cache |
| `registry sync [<id>...] [--all]` | Fetch + scan + promote |
| `registry entries <id>` | Show cached entries (after sync) |
| `registry approve <id> <name> --type {skill|mcp}` | Mark approved |
| `registry reject <id> <name> --type {skill|mcp}` | Mark rejected |
| `registry require --type <t> --enabled/--disabled` | Toggle `asset_policy.<t>.registry_required` |
| `registry wizard` | Interactive add+sync convenience flow |

### Examples

Register a corporate catalog non-interactively:

```bash
defenseclaw registry add corp-skills \
    --kind http_yaml \
    --url https://catalog.example.com/skills.yaml \
    --content skill \
    --auth-env DEFENSECLAW_REGISTRY_TOKEN \
    --non-interactive
```

Register the skills.sh public catalog (no URL = curated/official view):

```bash
defenseclaw registry add skills-sh-public \
    --kind skills_sh \
    --content skill \
    --non-interactive
```

Mirror the trending feed with a higher cap and a custom auth env var:

```bash
export DEFENSECLAW_SKILLSSH_TOKEN="sk_live_..."
defenseclaw registry add skills-sh-trending \
    --kind skills_sh \
    --url 'https://skills.sh?view=trending&max=500' \
    --content skill \
    --auth-env DEFENSECLAW_SKILLSSH_TOKEN \
    --non-interactive
```

Sync everything that's enabled (the typical CI/CD pattern):

```bash
defenseclaw registry sync --all --json
```

> **No built-in scheduler today.** The `auto_sync` and
> `sync_interval_hours` fields on `RegistrySource` are persisted for a
> future release but no runtime component reads them. Run
> `defenseclaw registry sync --all` from cron / a systemd timer / your
> existing CI cadence; v1 is intentionally a manual ingest pipeline so
> the operator stays in the loop on every promotion.

Operator preview (scan + show what would be promoted, without touching
asset_policy):

```bash
defenseclaw registry sync corp-skills --no-promote --json
```

Manually approve an entry that the scanner can't reach (e.g. a
network-isolated MCP server):

```bash
defenseclaw registry approve corp-mcps internal-server --type mcp
```

Tighten admission so only registry-approved skills are allowed:

```bash
defenseclaw registry require --type skill --enabled
```

---

## TUI

A new top-level **Registries** panel sits between Tools and Setup.
Open it with `R` (capital R; tools is `T`, registries is `R`).

The panel has three sub-tabs (`1` / `2` / `3`):

* **Sources** — every configured registry source with last sync,
  status, kind, content. `s` syncs the highlighted source; `S` syncs
  all enabled sources; `d` removes; `r` refreshes.
* **Entries** — the union of cached verdicts from every source.
  `a` approves, `x` rejects, `s` re-syncs the source the cursor is on.
* **Approved** — same view filtered to entries the operator has
  manually approved.

The Skills and MCPs panels both grow an `R` keybind that jumps to the
Registries panel with the cursor focused on the highlighted entry —
useful for quickly answering "which registry approved this skill?".

For the first-run flow, the Setup panel includes a **Registries**
wizard that wraps `defenseclaw registry add --non-interactive` so an
operator can register a catalog without leaving the TUI.

---

## On-disk layout

```
~/.defenseclaw/
└── registries/
    └── <source-id>/
        ├── index.json     # SourceIndex — verdicts the TUI / CLI render
        └── manifest.yaml  # raw fetched payload, kept for forensics
```

Both files are written atomically (temp + rename, mode 0o600). The
JSON index is the contract between the Python ingest pipeline and the
Go TUI panel; the raw manifest is kept for diff-based forensics when a
publisher's served bytes drift from what the validator accepted.

---

## Security notes

The ingest pipeline is operator-supplied URLs feeding scanner
subprocesses, so the security guards are layered:

* **SSRF guard.** Every URL is validated by
  `cli/defenseclaw/registries/ssrf.py::guard_url` before any HTTP call.
  Loopback, link-local, multicast, RFC1918, and ULA addresses are
  blocked by default. Operators with on-prem registries pass
  `--allow-private`.
* **Schema + invariant check.** Manifests are validated against the
  JSON Schema (when `jsonschema` is installed) **and** by a
  hand-written validator that enforces the same name / command /
  scheme / length / size invariants. The hand-written path is the
  source of truth so the security guards stay on even in
  reduced-deps installs.
* **Auth tokens.** `auth_env` accepts an env var **name**, never a
  literal token. The CLI's `_validate_auth_env` rejects anything that
  looks like a value.
* **Manifest size cap.** Fetches are streamed and aborted at 8 MiB to
  prevent zip-bomb-style payloads.
* **Subprocess isolation.** The git adapter shells out via
  `subprocess.run` with `shell=False` and a fixed argv; the manifest
  schema's `command` regex blocks shell metacharacters at parse time
  so a poisoned manifest can't smuggle them through.
* **Atomic writes.** `index.json` and `manifest.yaml` are written via
  temp + rename so a concurrent `registry list` never sees a
  half-written file.
* **Operator overrides win.** A `rejected` verdict is never promoted,
  even when the scanner reports clean; an `approved` verdict is
  always promoted, even when the scanner hasn't run.

The matched rule's `Reason="registry:<id>"` is preserved through
admission as `AssetPolicyDecision.RegistrySource` so audit events and
TUI badges can attribute the decision back to its source.

---

## Migration / back-compat

* Configs without a `registries:` block load with an empty source
  list — no migration step required.
* Removing a source deletes only that source's promoted rules
  (matched by `Reason="registry:<id>"`); rules from other sources or
  hand-written rules are preserved.
* Re-syncing a source first wipes its previous promoted rules, then
  re-emits them in lockstep with the current manifest. Removing an
  entry from a manifest cleanly removes its promoted rule on the next
  sync.

---

## Related docs

* [`docs/CLI.md`](./CLI.md) — CLI command index, including
  `defenseclaw registry`.
* [`docs/TUI.md`](./TUI.md) — TUI panels, including the Registries
  panel and Setup wizard.
* [`docs/CONFIG_FILES.md`](./CONFIG_FILES.md) — `registries:` and
  `asset_policy:` schema.
* [`schemas/registry-manifest.schema.json`](../schemas/registry-manifest.schema.json)
  — manifest JSON Schema.
* [`bundles/registries/`](../bundles/registries/) — sample manifests.
