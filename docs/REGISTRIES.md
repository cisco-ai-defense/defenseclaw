# Registries

Registry setup, source kinds, policy behavior, and operator workflows are
maintained on the
[published registries page](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/registries/).

The implementation is under
[`../cli/defenseclaw/registries/`](../cli/defenseclaw/registries/), with CLI
registration in
[`../cli/defenseclaw/commands/cmd_registry.py`](../cli/defenseclaw/commands/cmd_registry.py)
and policy logic in
[`../cli/defenseclaw/registry_policy.py`](../cli/defenseclaw/registry_policy.py).
Tests beside those modules define supported parser and security behavior.

This file remains as a stable link target and deliberately contains no
operator command copy.
