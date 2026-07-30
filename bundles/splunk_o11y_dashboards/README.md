# Splunk Observability dashboard bundle

User setup, flags, destination configuration, and troubleshooting are
maintained in the
[published Splunk guide](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/splunk/).

This directory contains the Terraform source imported by
`defenseclaw setup splunk dashboards apply`:

- [`terraform/main.tf`](terraform/main.tf) defines the dashboard group,
  dashboard variables, charts, and seven dashboard layouts.
- [`terraform/detectors.tf`](terraform/detectors.tf) defines the optional
  detector catalog, notification inputs, and detector URL outputs.

The CLI can import matching remote resources before Terraform applies the
bundle. That reconciliation, credential handling, apply flags, and temporary
workspace lifecycle are implemented in
[`cli/defenseclaw/commands/cmd_setup.py`](../../cli/defenseclaw/commands/cmd_setup.py);
the Terraform files are the resource definitions, not a standalone operator
entry point.

Detector changes should remain semantically aligned with the local Prometheus
rules in
[`bundles/local_observability_stack/prometheus/rules/alerts.yml`](../local_observability_stack/prometheus/rules/alerts.yml).
Tests under `cli/tests/` validate the rendered Terraform and CLI integration.
