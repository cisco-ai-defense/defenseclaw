# CI/CD Proposal: Monorepo with Independent Pipelines

> **Status:** PROPOSAL (not implemented)

**Status**: Proposal
**Date**: 2026-04-30
**Authors**: DefenseClaw Team

## Overview

This document defines the CI/CD architecture for the DefenseClaw monorepo. The
repository houses three components — control plane, data plane common, and data
plane Pulse — each with its own CI pipeline, container image, and release
process. All components follow a weekly release cadence.

`dataplane-common` is deployed to customer environments via
[Replicated](https://www.replicated.com/), which handles packaging,
distribution, airgapped delivery, and lifecycle management.

## Repository Layout

```
defenseclaw/
├── controlplane/               # Control plane (management API, UI, orchestration)
│   ├── cmd/
│   ├── internal/
│   ├── api/
│   ├── go.mod
│   ├── Makefile
│   └── Dockerfile
│
├── dataplane-common/           # Shared data plane — deployed via Replicated
│   ├── pkg/                    # Shared Go packages consumed by all data planes
│   ├── proto/                  # Protobuf/gRPC service definitions
│   ├── policies/               # OPA/Rego policies shared across data planes
│   ├── schemas/                # JSON schemas and validation contracts
│   ├── chart/                  # Helm chart packaged into the Replicated release
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   └── templates/
│   ├── replicated/             # Replicated vendor portal manifests
│   │   ├── kots-app.yaml       # KOTS application spec
│   │   ├── kots-config.yaml    # Customer-facing configuration screen
│   │   ├── kots-preflight.yaml # Pre-install environment checks
│   │   └── support-bundle.yaml # Troubleshooting collectors
│   ├── go.mod
│   ├── Makefile
│   └── Dockerfile
│
├── dataplane-pulse/            # Pulse-specific data plane implementation
│   ├── cmd/
│   ├── internal/
│   ├── scanners/
│   ├── go.mod
│   ├── Makefile
│   └── Dockerfile
│
├── .github/
│   └── workflows/
│       ├── ci-controlplane.yml
│       ├── ci-dataplane-common.yml
│       ├── ci-dataplane-pulse.yml
│       └── release.yml
│
├── docs/
├── scripts/
└── Makefile                    # Top-level orchestrator (build-all, test-all, etc.)
```

### Go Module Strategy

Each component is its own Go module to allow independent dependency management:

```
controlplane/go.mod        → module github.com/cisco-ai-defense/defenseclaw/controlplane
dataplane-common/go.mod    → module github.com/cisco-ai-defense/defenseclaw/dataplane-common
dataplane-pulse/go.mod     → module github.com/cisco-ai-defense/defenseclaw/dataplane-pulse
```

`dataplane-pulse` and `controlplane` depend on `dataplane-common` via a local
`replace` directive in development:

```go
// dataplane-pulse/go.mod
require github.com/cisco-ai-defense/defenseclaw/dataplane-common v0.0.0
replace github.com/cisco-ai-defense/defenseclaw/dataplane-common => ../dataplane-common
```

For releases, the `replace` directive is stripped and replaced with a tagged
version reference (e.g., `dataplane-common/v0.42.0`).

## CI Pipelines

Each component has its own CI workflow, triggered only when files in its
directory (or shared dependencies) change. All three pipelines run on every PR
and on merges to `main`.

### Path Filters

| Workflow                    | Triggers on changes to                                                |
|-----------------------------|-----------------------------------------------------------------------|
| `ci-controlplane.yml`       | `controlplane/**`, `dataplane-common/**` (shared dependency), `.github/workflows/ci-controlplane.yml` |
| `ci-dataplane-common.yml`   | `dataplane-common/**`, `.github/workflows/ci-dataplane-common.yml`    |
| `ci-dataplane-pulse.yml`    | `dataplane-pulse/**`, `dataplane-common/**` (shared dependency), `.github/workflows/ci-dataplane-pulse.yml` |

A change to `dataplane-common` triggers CI for all three components, since both
`controlplane` and `dataplane-pulse` depend on it.

### Pipeline: Control Plane

```yaml
# .github/workflows/ci-controlplane.yml
name: "CI: Control Plane"

on:
  push:
    branches: [main]
    paths:
      - "controlplane/**"
      - "dataplane-common/**"
      - ".github/workflows/ci-controlplane.yml"
  pull_request:
    branches: [main]
    paths:
      - "controlplane/**"
      - "dataplane-common/**"
      - ".github/workflows/ci-controlplane.yml"

concurrency:
  group: ci-controlplane-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: controlplane
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: controlplane/go.mod
      - run: make lint

  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: controlplane
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: controlplane/go.mod
      - run: make test-cov
      - uses: actions/upload-artifact@v4
        with:
          name: controlplane-coverage
          path: controlplane/coverage.out

  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        goos: [linux, darwin]
        goarch: [amd64, arm64]
    defaults:
      run:
        working-directory: controlplane
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: controlplane/go.mod
      - run: make build GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }}

  docker:
    if: github.ref == 'refs/heads/main'
    needs: [lint, test, build]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: controlplane/Dockerfile
          push: false
          tags: defenseclaw-controlplane:${{ github.sha }}
```

### Pipeline: Data Plane Common (Replicated)

`dataplane-common` is deployed to customer environments via Replicated. CI
builds the container image, packages the Helm chart, and on merges to `main`
pushes a release to the Replicated vendor portal. PRs create a temporary
Replicated channel so the change can be validated on a test instance before
merge.

```yaml
# .github/workflows/ci-dataplane-common.yml
name: "CI: Data Plane Common"

on:
  push:
    branches: [main]
    paths:
      - "dataplane-common/**"
      - ".github/workflows/ci-dataplane-common.yml"
  pull_request:
    branches: [main]
    paths:
      - "dataplane-common/**"
      - ".github/workflows/ci-dataplane-common.yml"

concurrency:
  group: ci-dataplane-common-${{ github.ref }}
  cancel-in-progress: true

env:
  REPLICATED_APP: defenseclaw-dataplane
  IMAGE_REGISTRY: ghcr.io/cisco-ai-defense
  IMAGE_NAME: defenseclaw-dataplane-common

jobs:
  lint:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dataplane-common
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-common/go.mod
      - run: make lint

  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dataplane-common
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-common/go.mod
      - run: make test-cov
      - uses: actions/upload-artifact@v4
        with:
          name: dataplane-common-coverage
          path: dataplane-common/coverage.out

  proto:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dataplane-common
    steps:
      - uses: actions/checkout@v4
      - uses: bufbuild/buf-action@v1
        with:
          input: dataplane-common/proto
      - run: make proto-check

  # -------------------------------------------------------------------
  # Build container image + Helm chart, push to GHCR
  # -------------------------------------------------------------------
  build-image:
    needs: [lint, test]
    runs-on: ubuntu-latest
    outputs:
      image-tag: ${{ steps.meta.outputs.version }}
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v4

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.IMAGE_REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=sha,prefix=
            type=ref,event=branch
            type=ref,event=pr

      - id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          file: dataplane-common/Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  # -------------------------------------------------------------------
  # Lint the Helm chart
  # -------------------------------------------------------------------
  helm-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
      - run: helm lint dataplane-common/chart

  # -------------------------------------------------------------------
  # PR: push a Replicated release to a temporary PR channel for testing
  # -------------------------------------------------------------------
  replicated-pr-channel:
    if: github.event_name == 'pull_request'
    needs: [build-image, helm-lint]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Replicated CLI
        run: |
          curl -s https://api.github.com/repos/replicatedhq/replicated/releases/latest \
            | grep "browser_download_url.*linux_amd64.tar.gz" \
            | cut -d '"' -f 4 \
            | xargs curl -sL | tar xz -C /usr/local/bin replicated

      - name: Package Helm chart
        run: |
          helm package dataplane-common/chart \
            --version 0.0.0-pr${{ github.event.number }} \
            --app-version ${{ needs.build-image.outputs.image-tag }} \
            -d dist/

      - name: Create PR channel and push release
        env:
          REPLICATED_API_TOKEN: ${{ secrets.REPLICATED_API_TOKEN }}
        run: |
          CHANNEL="pr-${{ github.event.number }}"
          replicated channel create --name "$CHANNEL" --app "$REPLICATED_APP" 2>/dev/null || true
          replicated release create \
            --app "$REPLICATED_APP" \
            --chart dist/dataplane-common-*.tgz \
            --yaml-dir dataplane-common/replicated \
            --promote "$CHANNEL" \
            --version "0.0.0-pr${{ github.event.number }}"
          echo "### Replicated PR Channel" >> "$GITHUB_STEP_SUMMARY"
          echo "Release pushed to channel \`$CHANNEL\`." >> "$GITHUB_STEP_SUMMARY"
          echo "Install on a test instance:" >> "$GITHUB_STEP_SUMMARY"
          echo '```' >> "$GITHUB_STEP_SUMMARY"
          echo "replicated customer download --app $REPLICATED_APP --channel $CHANNEL" >> "$GITHUB_STEP_SUMMARY"
          echo '```' >> "$GITHUB_STEP_SUMMARY"

  # -------------------------------------------------------------------
  # Main: push Replicated release to the Stable channel
  # -------------------------------------------------------------------
  replicated-stable:
    if: github.ref == 'refs/heads/main'
    needs: [build-image, helm-lint]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Replicated CLI
        run: |
          curl -s https://api.github.com/repos/replicatedhq/replicated/releases/latest \
            | grep "browser_download_url.*linux_amd64.tar.gz" \
            | cut -d '"' -f 4 \
            | xargs curl -sL | tar xz -C /usr/local/bin replicated

      - name: Package Helm chart
        run: |
          VERSION="${GITHUB_SHA::8}"
          helm package dataplane-common/chart \
            --version "$VERSION" \
            --app-version ${{ needs.build-image.outputs.image-tag }} \
            -d dist/

      - name: Push release to Stable channel
        env:
          REPLICATED_API_TOKEN: ${{ secrets.REPLICATED_API_TOKEN }}
        run: |
          VERSION="${GITHUB_SHA::8}"
          replicated release create \
            --app "$REPLICATED_APP" \
            --chart dist/dataplane-common-*.tgz \
            --yaml-dir dataplane-common/replicated \
            --promote Stable \
            --version "$VERSION"
          echo "### Replicated Stable Release" >> "$GITHUB_STEP_SUMMARY"
          echo "Version \`$VERSION\` promoted to **Stable** channel." >> "$GITHUB_STEP_SUMMARY"
```

#### Replicated Deployment Flow

```
PR opened/updated
  │
  ├─ lint, test, proto (parallel)
  ├─ build-image → push to GHCR
  ├─ helm-lint
  │
  └─ replicated-pr-channel
       │  Create temp channel "pr-<N>"
       │  Push Helm chart + KOTS manifests
       │  → Team can test on a staging instance
       │
PR merged to main
  │
  ├─ (same CI jobs)
  │
  └─ replicated-stable
       │  Package Helm chart with commit SHA version
       │  Push to Stable channel
       │  → Customer instances auto-update (if configured)
       │     or manual upgrade via KOTS admin console
```

#### Required Secrets

| Secret                    | Source                           | Used by                  |
|---------------------------|----------------------------------|--------------------------|
| `REPLICATED_API_TOKEN`    | Replicated vendor portal → API tokens | `replicated release create` |
| `GITHUB_TOKEN` (built-in) | GitHub Actions                   | GHCR image push          |

#### Replicated Manifests (`dataplane-common/replicated/`)

| File                   | Purpose                                                     |
|------------------------|-------------------------------------------------------------|
| `kots-app.yaml`        | Application metadata: name, icon, status informers, ports   |
| `kots-config.yaml`     | Customer-facing config screen (e.g., registry endpoint, resource limits, feature flags) |
| `kots-preflight.yaml`  | Pre-install checks: K8s version >= 1.27, available memory, storage class exists |
| `support-bundle.yaml`  | Troubleshooting: pod logs, cluster info, resource usage collectors |

### Pipeline: Data Plane Pulse

```yaml
# .github/workflows/ci-dataplane-pulse.yml
name: "CI: Data Plane Pulse"

on:
  push:
    branches: [main]
    paths:
      - "dataplane-pulse/**"
      - "dataplane-common/**"
      - ".github/workflows/ci-dataplane-pulse.yml"
  pull_request:
    branches: [main]
    paths:
      - "dataplane-pulse/**"
      - "dataplane-common/**"
      - ".github/workflows/ci-dataplane-pulse.yml"

concurrency:
  group: ci-dataplane-pulse-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dataplane-pulse
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-pulse/go.mod
      - run: make lint

  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dataplane-pulse
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-pulse/go.mod
      - run: make test-cov
      - uses: actions/upload-artifact@v4
        with:
          name: dataplane-pulse-coverage
          path: dataplane-pulse/coverage.out

  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        goos: [linux, darwin]
        goarch: [amd64, arm64]
    defaults:
      run:
        working-directory: dataplane-pulse
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-pulse/go.mod
      - run: make build GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }}

  docker:
    if: github.ref == 'refs/heads/main'
    needs: [lint, test, build]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: dataplane-pulse/Dockerfile
          push: false
          tags: defenseclaw-dataplane-pulse:${{ github.sha }}
```

## Release Strategy

### Weekly Cadence

All three components release together on a fixed weekly schedule. This keeps
versions aligned across control plane and data plane and simplifies upgrade
compatibility.

| Item              | Detail                                                        |
|-------------------|---------------------------------------------------------------|
| **Cadence**       | Weekly — every Wednesday                                      |
| **Tag format**    | `v<YYYY>.<week>.<patch>` (e.g., `v2026.18.0`)                |
| **Cut-off**       | Tuesday EOD — only changes merged by cut-off enter the release|
| **Release branch**| `release/v2026.18` created from `main` at cut-off            |
| **Hotfix**        | Cherry-pick to release branch, bump patch: `v2026.18.1`      |

### Why CalVer?

Calendar versioning (`YYYY.WW.patch`) makes it immediately obvious when a
release was produced and avoids the semantic ambiguity of SemVer for a system
with three independently-evolving components sharing one version number. The
week number directly maps to the release cadence.

SemVer remains an option if the team prefers it (e.g., `0.4.0`, `0.5.0`). The
pipeline design works with either scheme.

### Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - "v*.*.*"

permissions:
  contents: write
  id-token: write
  packages: write

jobs:
  # ---------------------------------------------------------------
  # Determine which components changed since the last release tag
  # ---------------------------------------------------------------
  detect-changes:
    runs-on: ubuntu-latest
    outputs:
      controlplane: ${{ steps.filter.outputs.controlplane }}
      dataplane-common: ${{ steps.filter.outputs.dataplane-common }}
      dataplane-pulse: ${{ steps.filter.outputs.dataplane-pulse }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          base: ${{ github.event.before }}
          filters: |
            controlplane:
              - 'controlplane/**'
            dataplane-common:
              - 'dataplane-common/**'
            dataplane-pulse:
              - 'dataplane-pulse/**'

  # ---------------------------------------------------------------
  # Build & push control plane artifacts
  # ---------------------------------------------------------------
  release-controlplane:
    needs: detect-changes
    if: needs.detect-changes.outputs.controlplane == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: controlplane/go.mod
      - uses: sigstore/cosign-installer@v3
      - uses: anchore/sbom-action/download-syft@v0
      - name: Build control plane binaries
        working-directory: controlplane
        run: make dist
      - name: Build and push container image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: controlplane/Dockerfile
          push: true
          tags: |
            ghcr.io/cisco-ai-defense/defenseclaw-controlplane:${{ github.ref_name }}
            ghcr.io/cisco-ai-defense/defenseclaw-controlplane:latest
      - uses: actions/upload-artifact@v4
        with:
          name: controlplane-dist
          path: controlplane/dist/

  # ---------------------------------------------------------------
  # Build data plane common + push Replicated release
  # ---------------------------------------------------------------
  release-dataplane-common:
    needs: detect-changes
    if: needs.detect-changes.outputs.dataplane-common == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-common/go.mod

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push container image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: dataplane-common/Dockerfile
          push: true
          tags: |
            ghcr.io/cisco-ai-defense/defenseclaw-dataplane-common:${{ github.ref_name }}
            ghcr.io/cisco-ai-defense/defenseclaw-dataplane-common:latest

      - uses: azure/setup-helm@v4

      - name: Package Helm chart
        run: |
          TAG="${GITHUB_REF#refs/tags/}"
          helm package dataplane-common/chart \
            --version "$TAG" \
            --app-version "$TAG" \
            -d dist/

      - name: Install Replicated CLI
        run: |
          curl -s https://api.github.com/repos/replicatedhq/replicated/releases/latest \
            | grep "browser_download_url.*linux_amd64.tar.gz" \
            | cut -d '"' -f 4 \
            | xargs curl -sL | tar xz -C /usr/local/bin replicated

      - name: Push Replicated release to Stable
        env:
          REPLICATED_API_TOKEN: ${{ secrets.REPLICATED_API_TOKEN }}
        run: |
          TAG="${GITHUB_REF#refs/tags/}"
          replicated release create \
            --app defenseclaw-dataplane \
            --chart dist/dataplane-common-*.tgz \
            --yaml-dir dataplane-common/replicated \
            --promote Stable \
            --version "$TAG"

      - uses: actions/upload-artifact@v4
        with:
          name: dataplane-common-dist
          path: dist/

  # ---------------------------------------------------------------
  # Build & push data plane Pulse artifacts
  # ---------------------------------------------------------------
  release-dataplane-pulse:
    needs: [detect-changes, release-dataplane-common]
    if: |
      always() &&
      (needs.detect-changes.outputs.dataplane-pulse == 'true' ||
       needs.detect-changes.outputs.dataplane-common == 'true')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: dataplane-pulse/go.mod
      - uses: sigstore/cosign-installer@v3
      - uses: anchore/sbom-action/download-syft@v0
      - name: Build Pulse binaries
        working-directory: dataplane-pulse
        run: make dist
      - name: Build and push container image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: dataplane-pulse/Dockerfile
          push: true
          tags: |
            ghcr.io/cisco-ai-defense/defenseclaw-dataplane-pulse:${{ github.ref_name }}
            ghcr.io/cisco-ai-defense/defenseclaw-dataplane-pulse:latest
      - uses: actions/upload-artifact@v4
        with:
          name: dataplane-pulse-dist
          path: dataplane-pulse/dist/

  # ---------------------------------------------------------------
  # Publish unified GitHub release with all artifacts
  # ---------------------------------------------------------------
  publish:
    needs:
      - release-controlplane
      - release-dataplane-common
      - release-dataplane-pulse
    if: always() && !cancelled()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          path: dist/
          merge-multiple: true
      - name: Generate checksums
        run: |
          cd dist
          find . -type f \( -name '*.tar.gz' -o -name '*.whl' -o -name '*.sbom.json' \) \
            -exec shasum -a 256 {} + > checksums.txt
      - name: Publish GitHub release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          TAG="${GITHUB_REF#refs/tags/}"
          shopt -s nullglob
          assets=(dist/*)
          gh release create "$TAG" \
            --repo "$GITHUB_REPOSITORY" \
            --title "$TAG" \
            --generate-notes \
            "${assets[@]}"
```

### Release Process

```
1. Tuesday EOD: Code freeze for the week's release
2. Create release branch:
     git checkout main && git pull
     git checkout -b release/v2026.18
     git push origin release/v2026.18
3. Tag the release:
     git tag v2026.18.0
     git push origin v2026.18.0
4. Workflow runs automatically:
     - Builds all changed components
     - Pushes container images to GHCR
     - Pushes dataplane-common Helm chart to Replicated Stable channel
     - Creates GitHub release with all artifacts
5. Verify:
     gh release view v2026.18.0
     replicated release ls --app defenseclaw-dataplane
```

## Dependency Graph

```
                    ┌─────────────────────┐
                    │  dataplane-common   │
                    │  (shared libs,      │
                    │   proto, policies)  │
                    │                     │
                    │  Deployed via       │
                    │  Replicated         │
                    └────────┬────────────┘
                             │
               ┌─────────────┼─────────────┐
               │                           │
               ▼                           ▼
    ┌──────────────────┐       ┌──────────────────────┐
    │  controlplane    │       │  dataplane-pulse     │
    │  (management     │       │  (scanning,          │
    │   API, UI,       │       │   inspection,        │
    │   orchestration) │       │   enforcement)       │
    └──────────────────┘       └──────────────────────┘
```

## Replicated Deployment Model (dataplane-common)

`dataplane-common` is the component deployed into customer-managed
infrastructure. Replicated provides the packaging, distribution, and lifecycle
management layer.

### How It Works

```
CI builds image + Helm chart
        │
        ▼
┌──────────────────────────────┐
│  Replicated Vendor Portal    │
│                              │
│  Channels:                   │
│    Stable  ← weekly release  │
│    Beta    ← pre-release     │
│    pr-<N>  ← PR testing      │
│                              │
│  Each release contains:      │
│    • Helm chart (.tgz)       │
│    • KOTS manifests          │
│    • Container image ref     │
└──────────┬───────────────────┘
           │
           │  Customer pulls via:
           │  • KOTS admin console (airgapped or online)
           │  • Helm install (connected environments)
           │
           ▼
┌──────────────────────────────┐
│  Customer K8s Cluster        │
│                              │
│  ┌────────────────────────┐  │
│  │  KOTS Admin Console    │  │
│  │  (if airgapped)        │  │
│  │                        │  │
│  │  • Pre-flight checks   │  │
│  │  • Config UI           │  │
│  │  • Upgrade management  │  │
│  │  • Support bundles     │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │  dataplane-common      │  │
│  │  (Helm release)        │  │
│  └────────────────────────┘  │
└──────────────────────────────┘
```

### Replicated Channel Strategy

| Channel   | Promoted from         | Audience               | Auto-update |
|-----------|-----------------------|------------------------|-------------|
| **Stable**| Weekly release tag    | Production customers   | Optional (customer-controlled) |
| **Beta**  | RC tags (`-rc.N`)     | Internal QA, early adopters | Yes      |
| **pr-N**  | PR CI builds          | Dev team testing       | N/A (ephemeral) |

### Release Artifacts per Channel

Each Replicated release bundles:

| Artifact              | Source                              |
|-----------------------|-------------------------------------|
| Helm chart (`.tgz`)  | `dataplane-common/chart/` — packaged by `helm package` |
| KOTS app manifest     | `dataplane-common/replicated/kots-app.yaml`             |
| Config screen         | `dataplane-common/replicated/kots-config.yaml`          |
| Preflight checks      | `dataplane-common/replicated/kots-preflight.yaml`       |
| Support bundle spec   | `dataplane-common/replicated/support-bundle.yaml`       |
| Container image       | `ghcr.io/cisco-ai-defense/defenseclaw-dataplane-common:<tag>` (referenced in Helm values) |

### Airgapped Delivery

For customers without internet access, Replicated supports airgapped bundles:

1. CI pushes the release to the vendor portal as usual
2. A Replicated-hosted bundle builder produces an airgap bundle (`.airgap` file)
   containing all container images + Helm chart + KOTS manifests
3. Customer downloads the bundle from a pre-authenticated download portal
4. Customer uploads the bundle to their KOTS admin console
5. KOTS unpacks images into the customer's local registry and deploys the Helm chart

No changes to the CI pipeline are needed — Replicated handles airgap bundle
generation automatically from the same release.

### Customer Upgrade Path

```
Replicated detects new version on Stable channel
        │
        ▼
KOTS admin console shows "Update available"
        │
        ▼
Customer clicks "Deploy" (or auto-update if enabled)
        │
        ▼
Preflight checks run (K8s version, memory, storage)
        │
        ├─ Pass → Helm upgrade executes
        │           │
        │           └─ Rolling update of dataplane-common pods
        │
        └─ Fail → Blocked with actionable error message
                   (e.g., "Requires K8s >= 1.27, found 1.26")
```

## Branching Strategy

```
main ─────●────●────●────●────●────●────●─── (always releasable)
           \              \
            release/v2026.17    release/v2026.18
            │                   │
            v2026.17.0          v2026.18.0
            v2026.17.1 (hotfix) │
```

- **`main`**: Integration branch. PRs merge here after passing CI.
- **`release/v<YYYY>.<WW>`**: Cut weekly from `main` at Tuesday EOD cut-off.
  Only hotfix cherry-picks land here after the cut.
- **Feature branches**: Short-lived, scoped to a component when possible
  (e.g., `feature/controlplane-rbac`).

## Implementation Plan (1 Week)

All work is compressed into a single week. Tasks are parallelized across the
team where possible. The schedule assumes a Monday start with the first release
cut on Friday.

```
Mon         Tue         Wed         Thu         Fri
 │           │           │           │           │
 ├─ Repo     ├─ CI       ├─ Replicated├─ Release ├─ First
 │  scaffold │  pipelines│  setup +   │  workflow │  release
 │  + Go     │  + branch │  Helm      │  + dry   │  cut
 │  modules  │  protect  │  chart     │  run RC  │  v2026.18.0
 │  + Docker │           │  + KOTS    │           │
 │  + Make   │           │  manifests │           │
```

### Day 1 (Monday): Repository Scaffolding

| # | Task | Owner |
|---|------|-------|
| 1 | Create `controlplane/`, `dataplane-common/`, `dataplane-pulse/` directories | Dev |
| 2 | Set up each component's `go.mod` with proper module paths | Dev |
| 3 | Add local `replace` directives for cross-component dependencies | Dev |
| 4 | Add `go.work` for local development (not committed to git) | Dev |
| 5 | Create per-component `Makefile` (`lint`, `test-cov`, `build`, `dist`) | Dev |
| 6 | Create per-component `Dockerfile` | Dev |
| 7 | Add top-level `Makefile` with orchestrator targets (`build-all`, `test-all`, `lint-all`) | Dev |
| 8 | Verify `make test-all` passes from root | Dev |

**Exit criteria**: All three components build, lint, and test independently.

### Day 2 (Tuesday): CI Pipelines + Branch Protection

| # | Task | Owner |
|---|------|-------|
| 1 | Add `ci-controlplane.yml`, `ci-dataplane-common.yml`, `ci-dataplane-pulse.yml` | Dev |
| 2 | Open test PRs touching each component to verify path filters fire correctly | Dev |
| 3 | Confirm concurrency groups cancel stale runs | Dev |
| 4 | Set up branch protection rules requiring per-component CI to pass | Repo admin |

*Parallel*: Begin Replicated vendor portal setup (Day 3 prep) — create app, generate API token.

**Exit criteria**: PRs trigger only the relevant component's CI; branch protection enforced.

### Day 3 (Wednesday): Replicated + Helm Chart

| # | Task | Owner |
|---|------|-------|
| 1 | Create Replicated app (`defenseclaw-dataplane`) on vendor portal | Infra |
| 2 | Create channels: Stable, Beta | Infra |
| 3 | Author KOTS manifests in `dataplane-common/replicated/`: `kots-app.yaml`, `kots-config.yaml`, `kots-preflight.yaml`, `support-bundle.yaml` | Dev |
| 4 | Create Helm chart in `dataplane-common/chart/` (`Chart.yaml`, `values.yaml`, `templates/`) | Dev |
| 5 | Add `REPLICATED_API_TOKEN` to GitHub repo secrets | Repo admin |
| 6 | Manual test: `helm package` + `replicated release create` to Beta channel | Dev |
| 7 | Validate install on a test cluster from the Beta channel | QA |

**Exit criteria**: `dataplane-common` installs successfully on a test cluster via Replicated Beta.

### Day 4 (Thursday): Release Workflow + Dry Run

| # | Task | Owner |
|---|------|-------|
| 1 | Add `release.yml` workflow | Dev |
| 2 | Set up GHCR push credentials (if not already done) | Repo admin |
| 3 | Tag a release candidate: `v2026.18.0-rc.1` | Dev |
| 4 | Verify workflow runs end-to-end: controlplane + dataplane-pulse binaries build, dataplane-common pushes to Replicated Beta, GitHub release created | Dev |
| 5 | Validate customer upgrade flow from Replicated Beta on test cluster | QA |
| 6 | Fix any workflow failures and re-tag `rc.2` if needed | Dev |

**Exit criteria**: Full release workflow succeeds end-to-end on an RC tag.

### Day 5 (Friday): First Release

| # | Task | Owner |
|---|------|-------|
| 1 | Create release branch: `release/v2026.18` | Dev |
| 2 | Tag first production release: `v2026.18.0` | Dev |
| 3 | Verify: `gh release view v2026.18.0` + `replicated release ls --app defenseclaw-dataplane` | Dev |
| 4 | Promote dataplane-common from Beta to Stable on Replicated | Infra |
| 5 | Smoke-test customer install from Stable channel | QA |
| 6 | Document any issues or adjustments for next week's release | Dev |

**Exit criteria**: First production release shipped. All three components have artifacts on GitHub. `dataplane-common` available on Replicated Stable.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Monorepo** | Single repo with three top-level folders | Shared code in `dataplane-common` is tightly coupled to both consumers; a monorepo avoids version skew and cross-repo PR coordination |
| **Per-component CI** | Path-filtered GitHub Actions workflows | Only affected components build on each change, keeping feedback loops fast (~3-4 min) while sharing a single repo |
| **Replicated for dataplane-common** | Helm + KOTS via Replicated vendor portal | Customer environments are diverse (airgapped, on-prem, cloud); Replicated handles all delivery modes from a single pipeline |
| **Weekly cadence** | All components release together | Aligned versions simplify compatibility testing; weekly is frequent enough for continuous delivery without release fatigue |
| **CalVer** | `v<YYYY>.<WW>.<patch>` | Immediately communicates when a release was produced; avoids SemVer ambiguity for a multi-component system |
| **Ephemeral PR channels** | Replicated channel per PR | Allows testing Replicated releases before merge without polluting Stable/Beta channels |

## Open Questions

| # | Question | Options |
|---|----------|---------|
| 1 | **Version scheme** | CalVer (`v2026.18.0`) vs. SemVer (`v0.4.0`) |
| 2 | **Container registry** | GHCR vs. ECR vs. both |
| 3 | **`dataplane-common` as a tagged Go module?** | Use `replace` in dev + tagged versions for release, or always use `replace` with monorepo tooling |
| 4 | **Release day** | Wednesday (proposed) vs. another day |
| 5 | **Additional data planes** | Will there be `dataplane-<other>` components? If so, the pattern is ready to extend |
| 6 | **Replicated auto-update policy** | Should Stable channel enable auto-update for customers, or require manual approval via KOTS admin console? |
| 7 | **Replicated app scope** | One Replicated app for `dataplane-common` only, or a single app that bundles all data plane components? |
| 8 | **Airgap bundle testing** | Should CI generate and validate an airgap bundle on every release, or only for tagged releases? |
| 9 | **Replicated license tiers** | Will different customers get different feature sets via Replicated license entitlements? |
