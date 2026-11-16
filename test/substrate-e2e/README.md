# Substrate kind E2E

A scripted smoke test of DefenseClaw on Agent Substrate. CI runs it as the `Substrate Kind E2E` workflow (`.github/workflows/substrate-kind-e2e.yml`) on a hosted runner, using Substrate release images and gVisor only (hosted runners have no KVM).

It checks, in order:

1. Substrate installs on a new kind cluster and its API answers.
2. A worker pool and an atespace come up, and a stub agent image is built and pushed to the local registry.
3. A new actor has no egress. A policy naming a host opens that host, and removing the policy closes it again.
4. The DefenseClaw chart installs, actor creation writes the policy, and a hook event from the stub agent is denied by the real gateway (`defenseclaw.sh`).
5. Uninstalling the chart leaves no DefenseClaw policy and no open egress.

## Run it

On a machine with docker, kubectl, helm, git and kind:

    test/substrate-e2e/run.sh                # every phase, then cleanup
    test/substrate-e2e/run.sh egress         # one phase (phases: tools substrate workers stub egress defenseclaw uninstall cleanup)

Against a cluster that already runs Substrate (a dev cluster), in your own namespace and atespace:

    E2E_CLUSTER_MODE=existing E2E_NAMESPACE=mine E2E_ATESPACE=mine-gv test/substrate-e2e/run.sh

The settings are the `E2E_*` variables at the top of `run.sh`. Results go to `$E2E_ARTIFACTS/results.tsv`, and a failure writes pod logs and events to `$E2E_ARTIFACTS/diagnostics/`. The script exits non-zero when any check fails.

The stub agent in `stub/` is test code. It holds no credentials and is never shipped.
