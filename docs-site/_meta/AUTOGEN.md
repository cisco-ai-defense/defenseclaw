# AUTOGEN Sentinel Registry

**This file is the contract between `scripts/docgen/` generators and every MDX page with an AUTOGEN block.**

Generators ONLY rewrite content between matched `<!-- BEGIN AUTOGEN:<generator>:<key> -->` and `<!-- END AUTOGEN:<generator>:<key> -->` markers. Everything outside is preserved.

## Generator → Target pages

### `cli_py` (Python Click)

Source: `cli/defenseclaw/main.py` + all `cli/defenseclaw/commands/cmd_*.py`. Introspected via `click.Context.to_info_dict()` (same pattern as `scripts/audit_parity.py`).

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `root` | `docs-site/cli/python-cli.mdx` | Top-level group + global options + subcommand list |
| `<cmd>` | `docs-site/cli/commands/<cmd>.mdx` | Synopsis, subcommands, flags, arguments, env vars for `<cmd>` |

Per-command blocks (one per `cmd_*.py`): `init`, `status`, `alerts`, `doctor`, `setup`, `skill`, `mcp`, `plugin`, `tool`, `policy`, `aibom`, `codeguard`, `keys`, `audit`, `config`, `sandbox`, `quickstart`, `upgrade`, `uninstall`, `tui`, `version`, `settings`.

### `cli_go` (Go Cobra)

Source: `internal/cli/*.go`. Introspected via `cobra.Command` walker in `internal/clidocgen/`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `root` | `docs-site/cli/gateway-cli.mdx` | `defenseclaw-gateway` root + persistent flags + subcommand list |
| `<cmd>` | `docs-site/cli/commands-gateway/<cmd>.mdx` | Synopsis, subcommands, flags, arguments, and inherited flags for gateway commands |

### `api_routes` (Go HTTP muxes)

Source: `internal/gateway/api.go` + `internal/gateway/proxy.go`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `all` | `docs-site/api/endpoints.mdx` | Registered route table with surface, methods, handler, and source file |

### `make_targets` (Makefile)

Source: `Makefile`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `all` | `docs-site/installation/make-install.mdx` | Make target inventory parsed from real target declarations |

### `schemas` (JSON Schema)

Source: `schemas/*.json` + `schemas/otel/*.json`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `audit_event` | `docs-site/api/schemas.mdx` | `audit-event.json` rendered as annotated JSON |
| `scan_event` | `docs-site/api/schemas.mdx` | `scan-event.json` |
| `scan_finding_event` | `docs-site/api/schemas.mdx` | `scan-finding-event.json` |
| `activity_event` | `docs-site/api/schemas.mdx` | `activity-event.json` |
| `gateway_envelope` | `docs-site/api/schemas.mdx` | `gateway-event-envelope.json` |
| `network_egress` | `docs-site/api/schemas.mdx` | `network-egress-event.json` |
| `scan_result` | `docs-site/api/schemas.mdx` | `scan-result.json` |
| `otel_<name>` | `docs-site/observability/otel-spec.mdx` | per OTEL schema file |

### `env_vars`

Source: AST/grep over the repo for Python `os.getenv`, `os.environ[...]`, Click `envvar=`, Go `os.Getenv`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `all` | `docs-site/reference/env-vars.mdx` | Grouped by prefix (DEFENSECLAW_*, DEFENSECLAW_GATEWAY_*, etc.) |

### `exit_codes`

Source: AST/grep for `sys.exit(N)`, `ctx.exit(N)`, `os.Exit(N)`, plus `scripts/check_error_codes.py`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `all` | `docs-site/reference/exit-codes.mdx` | Exit code inventory grouped by command |

### `providers`

Source: `internal/configs/providers.json` + `internal/gateway/adapter_*.go`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `matrix` | `docs-site/guardrail/providers.mdx` | Provider / adapter / auth / streaming / notes |

### `otel`

Source: grep `internal/telemetry/*.go` for instrument registrations (`Meter.*Counter`, `*Histogram`, `*UpDownCounter`, `Tracer.Start`).

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `metrics` | `docs-site/observability/otel-spec.mdx` | Metric instrument inventory |
| `spans` | `docs-site/observability/otel-spec.mdx` | Span name inventory |

### `rules`

Source: `policies/guardrail/{default,strict,permissive}/rules/*.yaml` + `internal/guardrail/defaults/`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `packs_diff` | `docs-site/guardrail/rule-packs.mdx` | Side-by-side count/severity diff across packs |
| `default_rules` | `docs-site/guardrail/rule-packs.mdx` | Full default pack inventory by category |

### `rego`

Source: `policies/rego/*.rego` + `policies/rego/data.json`.

| Key | Target page | Block contents |
|-----|-------------|----------------|
| `modules` | `docs-site/policy/writing-rego.mdx` | Module signatures + entry point rules |
| `data_json` | `docs-site/policy/data-json.mdx` | `data.json` structure with inline comments |

---

## Splicing algorithm (implementors)

```python
def splice(path: Path, generator: str, key: str, new_block: str) -> None:
    text = path.read_text()
    begin = f"<!-- BEGIN AUTOGEN:{generator}:{key} -->"
    end = f"<!-- END AUTOGEN:{generator}:{key} -->"
    if begin not in text:
        raise MissingSentinelError(path, generator, key)
    pre, _, rest = text.partition(begin)
    _, _, post = rest.partition(end)
    path.write_text(
        f"{pre}{begin}\n<!-- Do not edit by hand. Regenerate with `make docs-gen`. -->\n\n"
        f"{new_block.rstrip()}\n\n{end}{post}"
    )
```

CI check (`make docs-check`):

```bash
make docs-gen
make docs-verify
make docs-deadlinks
git diff --exit-code docs-site/
```

Any diff = documentation drift = PR blocked.
