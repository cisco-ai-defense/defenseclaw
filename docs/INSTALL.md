# Installation

Installation is operator documentation and is maintained on the
[DefenseClaw installation page](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/).
Use the related published guides for
[upgrades](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/)
and
[native Windows](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/windows/).

This repository file remains only as a stable target for older links. It does
not duplicate commands because release versions, platform support, and
installer behavior change together.

Current macOS releases support Apple Silicon (`arm64`) only. Intel
(`x86_64`/`amd64`) macOS is unsupported across release, upgrade, rescue,
managed-package, and source-install entry points.

## Contributor builds

Contributor build targets are defined in [`../Makefile`](../Makefile); run
`make help` for the current contract. `make build` builds artifacts without
installing them. Source activation targets are development tooling, do not
claim an upgrade, and are not an alternate upgrade mechanism for an existing
release-managed installation. `scripts/install.sh` and `scripts/install.ps1`
are the installers and upgraders for release installs; `defenseclaw upgrade`
runs the latest release's copy.

Release construction and validation belong in
[`RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md), not in the operator install guide.
