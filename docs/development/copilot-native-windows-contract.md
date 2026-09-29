# GitHub Copilot CLI managed Windows contract

This document records the DefenseClaw `managed_enterprise` contract for native
Windows. It does not enable ordinary user-scoped `defenseclaw setup copilot` on
Windows and does not add a macOS enterprise policy.

## Eligibility and discovery

- Minimum reviewed Copilot CLI version: `1.0.83`.
- Discovery is static and bounded. The installer may authenticate supported
  npm, Bun, or Yarn package metadata, or the official signed `GitHub.Copilot`
  WinGet image. It never launches a user-controlled client to obtain a version.
- An observed native WinGet candidate whose path, signature, product identity,
  or exact version cannot be authenticated fails closed for enrollment; it does
  not fall back to mutable package metadata or a minimum-version placeholder.

## Machine policy

DefenseClaw owns exactly:

`C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json`

The canonical schema-version-1 policy registers one direct command for each of
these events: `sessionStart`, `sessionEnd`, `userPromptSubmitted`,
`userPromptTransformed`, `preToolUse`, `postToolUse`, `postToolUseFailure`,
`permissionRequest`, `agentStop`, `subagentStart`, `subagentStop`,
`errorOccurred`, `preCompact`, and `notification`.

Each command directly executes the protected `defenseclaw-hook.exe` with the
exact event and `copilot-hooks-v2` contract in argv. It contains no shell, no
command string, and no token. DefenseClaw validates the policy byte-for-byte.

## Per-user runtime and decisions

The machine policy selects the caller by Windows token SID. The authenticated
SID maps to one canonical user data directory, connector-scoped token, gateway
identity, contract lock, and immutable generation. A user cannot select or
borrow another user's runtime.

- `preToolUse`: a valid block becomes Copilot's native deny response.
- `permissionRequest`: a valid block becomes deny plus interrupt.
- `userPromptTransformed`: in action mode, a raw block requests a fixed
  `modifiedTransformedPrompt` replacement.
- `postToolUse`: in action mode, a raw block requests a fixed
  `modifiedResult.textResultForLlm` replacement.

Prompt and result replacement preserve accounting as raw block, effective
allow, and `would_block=true`, with `model_input_rewrite_requested` in audit.
Only a closed catalog of Cisco AI Defense labels can appear in replacement
text; raw prompts, tool results, evidence, and unrestricted findings cannot.
Observe mode never rewrites.

## Availability boundary

Copilot can treat a non-timeout `preToolUse` command failure as a denial.
Therefore missing enrollment, invalid local runtime, gateway/authentication
failure, malformed response, and timeout return exit 0 with no decision JSON.
This is an explicit fail-open availability boundary, not a fail-closed claim.
Valid policy blocks and rewrites still use the documented Copilot response.

## Lifecycle

Install and reconcile prepare and verify the per-user immutable generation
before publishing its machine-policy target. Deferred users are recorded but
receive no selected generation until eligible activation. Repair, upgrade,
rollback, interrupted recovery, uninstall, and purge include Copilot in the
same protected journals and compare-and-swap boundaries as the other managed
connectors. Removal deletes only DefenseClaw-owned policy/state/selectors and
generations; unrelated GitHub policy files remain untouched.

The Windows status and deployment metadata expose
`copilot_target_enabled`. That target flag alone is not production security
attestation; the existing application-control, hardening, Guardian, and
readiness proofs still determine `security_complete`.
