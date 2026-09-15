# Infrastructure destruction protection

This opt-in guardrail profile extends the embedded balanced defaults with five
exact protected-environment rules. Assign it only to connectors whose selected
host, workspace, or stack can reach production; names are not treated as
production evidence.

The v1 claim covers filesystem creation or destructive writes against literal
device paths, protected security-material permission weakening, `terraform
destroy`, `tofu destroy`, their explicit `apply -destroy` forms, and `pulumi
destroy` when no resource target is present. It also blocks an exact `mount
--bind STATIC_SOURCE STATIC_TARGET` when the literal target is strictly beneath
`/proc/sys/kernel`, `/proc/sys/net`, or `/proc/sys/vm`. Every rule is
ActionFacts-gated; dynamic paths, remounts, reversed operands, namespace roots,
and lexical lookalikes abstain.

Plans, previews, targeted destroys, ordinary applies, quoted examples,
non-device files, permission changes outside protected security material, and
unsupported option grammars do not block.
