# Guardrail quickstart

Use the published
[first-guardrail walkthrough](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/first-guardrail/)
and
[guardrail setup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/guardrail/).

Those pages are the source of truth for installation, connector setup, modes,
verification, tuning, disabling, and upgrades. This repository file preserves
older links without duplicating mutable operator commands.

Engineering entry points are indexed in [`GUARDRAIL.md`](GUARDRAIL.md).

If OpenClaw agent turns succeed while `:4000` looks healthy, run
`defenseclaw doctor` and confirm the **OpenClaw interception** row. That
self-test is the version-drift check for OpenClaw ≥2026.6.8; do not treat
a liveliness 200 or a stale `INCOMING REQUEST` count as proof that agent
traffic is being rewritten.
