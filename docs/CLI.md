# CLI

The
[published CLI reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/cli/)
is the operator source of truth. It is reviewed with the current Click and
Cobra command trees and should be preferred over version-pinned repository
links.

For code review, the Python command tree is registered from
[`../cli/defenseclaw/main.py`](../cli/defenseclaw/main.py) and
[`../cli/defenseclaw/commands/`](../cli/defenseclaw/commands/). The Go gateway
commands are under [`../cmd/`](../cmd/). `<binary> --help` is authoritative for
the exact installed binary.

## Upgrade

Use the
[published upgrade guide](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/).
This heading intentionally preserves the historical `docs/CLI.md#upgrade`
anchor while keeping mutable resolver instructions in one place.
