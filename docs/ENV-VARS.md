# Environment variables

The generated, canonical catalog is published on the
[DefenseClaw environment-variable reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/env-vars/).

The code-level source of truth is
[`../internal/envvars/registry.json`](../internal/envvars/registry.json).
[`../scripts/gen_envvars_docs.py`](../scripts/gen_envvars_docs.py) validates that
registry, synchronizes the bundled runtime copy, and renders the website page.
CI also checks that every supported `DEFENSECLAW_*` callsite has a registry
entry.

This repository file is intentionally a pointer so the generated table is not
published twice.
