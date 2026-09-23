# SSH authorized keys protection

This directory defines the contract for an opt-in SSH `authorized_keys`
protection pack. It is intentionally not activatable yet.

The deterministic ActionFacts helper accepts only one unconditional,
successful write or append of one literal, parseable SSH public key to the
active user's exact `$HOME/.ssh/authorized_keys` path. It computes the OpenSSH
`SHA256:` fingerprint locally and blocks only when trusted policy context
supplies `approved_key_fingerprints` and the computed fingerprint is absent.

Dynamic paths or content, malformed keys, unresolved homes, read-only access,
failed or conditional writes, missing policy, and malformed policy all
abstain. An explicitly present empty allowlist means that no key is approved.

## Current binding gap

The current CEL activation deliberately omits file-content values, and the
guardrail rule-pack schema has no parameter channel for an approved-key
fingerprint allowlist or a trusted post-action outcome. Adding a CEL rule now
would therefore either match every `authorized_keys` write or trust raw regex
text, both of which violate this pack's proof boundary.

`approved-keys.example.yaml` documents the intended trusted policy input. Do
not point `policy_dir` at this directory: it is a contract and conformance
artifact until the content-fingerprint, allowlist, and outcome fields are
bound into the private CEL activation.
