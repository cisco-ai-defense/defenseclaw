# OpenShell sandbox events

The OpenShell integration and its events are being rebuilt for NVIDIA
OpenShell 0.1 and will be documented when that support ships.

The legacy standalone sandbox's events were retired with it: the
`init-sandbox` audit action and the `defenseclaw.openshell.exit` metric
(`metric.defenseclaw.openshell.exit` family, with its
`defenseclaw.metric.command` attribute) are no longer emitted.

See [SANDBOX.md](SANDBOX.md) for how to remove a legacy install.
