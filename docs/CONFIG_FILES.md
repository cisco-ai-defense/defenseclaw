# Configuration files

The canonical operator reference is the
[published configuration page](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/configuration/).
The complete environment-variable catalog is maintained separately on the
[published environment-variable page](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/env-vars/).

Repository implementation authorities are:

- [`../schemas/config/v8/defenseclaw-config.schema.json`](../schemas/config/v8/defenseclaw-config.schema.json)
  for the v8 source shape;
- [`../internal/config/config.go`](../internal/config/config.go) for Go loading,
  defaults, validation, and effective configuration;
- [`../cli/defenseclaw/config.py`](../cli/defenseclaw/config.py) for Python
  configuration mutation and migration;
- [`../internal/envvars/registry.json`](../internal/envvars/registry.json) for
  every supported `DEFENSECLAW_*` environment variable.

This file is a stable repository pointer, not a second operator configuration
guide.
