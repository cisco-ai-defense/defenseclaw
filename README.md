<div align="center">

<pre>
     ____         ____                       ____  _
    / __ \  ___  / __/___   ___   ___  ___  / ___|| | __ _ __      __
   / / / / / _ \/ /_// _ \ / _ \ / __|/ _ \| |    | |/ _` |\ \ /\ / /
  / /_/ / /  __/ __//  __/| | | |\__ \  __/| |___ | | (_| | \ V  V /
 /_____/  \___/_/   \___/ |_| |_||___/\___| \____||_|\__,_|  \_/\_/
</pre>

<h1>DefenseClaw</h1>

<p>
  <strong>Security governance for OpenClaw and agentic AI runtimes.</strong><br />
  Scan capabilities before use, inspect runtime traffic, and export durable audit evidence.
</p>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" /></a>
  <a href="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://discord.com/invite/nKWtDcXxtx"><img alt="Discord" src="https://img.shields.io/badge/Discord-join-7289DA?logo=discord&amp;logoColor=white" /></a>
</p>

</div>

DefenseClaw combines a Python operator CLI, a Go gateway, connector hooks, policy,
scanners, and observability exporters. It is an enforcement and evidence layer;
it does not prove that an agent, model interaction, or third-party capability is
risk-free.

## Documentation

The [DefenseClaw documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/)
is the source of truth for installation, setup, configuration, commands, and
operator workflows:

| Topic | Canonical guide |
| --- | --- |
| Install | [Install DefenseClaw](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/) |
| First run | [Quickstart](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/quickstart/) |
| Upgrade | [Upgrade](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/) |
| Windows | [Native Windows](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/windows/) |
| Connectors | [Connector compatibility](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/) |
| Guardrails | [Guardrail setup](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/guardrail/) |
| Configuration | [Configuration reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/configuration/) |
| CLI | [CLI reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/cli/) |
| Observability | [Observability](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/) |

Repository Markdown is limited to contributor guidance, implementation
contracts, package-local notes, generated schema references, test fixtures, and
historical design records. Start at [`docs/README.md`](docs/README.md).

## Source development

Source targets are contributor tooling. They are not an installation or upgrade
path for a release-managed host; use the website guides above for those tasks.
The checked-in toolchain contracts are Python `>=3.10,<3.14`
([`pyproject.toml`](pyproject.toml)) and Go `1.26.4`
([`go.mod`](go.mod)). CI exercises the TypeScript components with Node.js 24.

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
make build
make test
make check
make lint
```

`make build` produces artifacts without installing them. Run `make help` before
using state-changing source targets. `make all` intentionally rebuilds and
activates the current checkout for local development; the lower-level
`make install`, `make dev-install`, and `scripts/install-dev.sh` targets enforce
source-ownership rules and are not an upgrade path. Release-managed
installations use the release-owned `scripts/upgrade.sh` or
`scripts/upgrade.ps1` resolver described on the
[upgrade page](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/).

The principal source areas are:

| Area | Path |
| --- | --- |
| Python CLI and TUI | [`cli/defenseclaw/`](cli/defenseclaw/) |
| Go gateway commands | [`cmd/`](cmd/) |
| Go implementation packages | [`internal/`](internal/) |
| OpenClaw extension | [`extensions/defenseclaw/`](extensions/defenseclaw/) |
| Policy bundles | [`policies/`](policies/) |
| Versioned schemas | [`schemas/`](schemas/) |
| Release and developer automation | [`scripts/`](scripts/) |
| Tests and fixtures | [`test/`](test/) and component-local `*_test.*` files |

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the pull-request workflow and
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Copyright 2026 Cisco Systems, Inc. and its affiliates.
