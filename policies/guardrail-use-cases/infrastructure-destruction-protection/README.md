# Infrastructure destruction protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
full infrastructure destruction through Terraform, OpenTofu, or Pulumi. Assign
it only to connectors whose selected workspace or stack can reach production;
workspace and stack names are not treated as production evidence.

The v1 claim covers `terraform destroy`, `tofu destroy`, their explicit
`apply -destroy` forms, and `pulumi destroy` when no resource target is present.
Plans, previews, targeted destroys, ordinary applies, quoted examples, and
unsupported option grammars do not block.
