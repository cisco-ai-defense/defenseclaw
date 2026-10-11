# Active branch context

Branch: `fix/unverified-hook-contract-fail-open`
Draft PR: https://github.com/cisco-ai-defense/defenseclaw/pull/1163
Base: `release-defenseclaw-enterprise-26.8.4`

## Current contract

Spec 007 combines version fallback and default-open hook delivery for macOS and
native Windows on this branch. Unverified versions install the reviewed event
union in open delivery mode; compatible verified versions retain configured
policy. Unset policy is open; explicit closed and malformed non-empty settings
remain closed. Policy denials and strict availability still block.

Windows mode is carried in the authenticated immutable generation. Protected
enrollment, SID/executable identity, bounded readers, peer authentication,
credential custody, digests and rollback remain mandatory. Legacy closed bundles
and Cursor protected state still validate without being silently reinterpreted.
Static discovery accepts presence without a version and refreshes stale version
evidence without changing existing authorization flags. Speculative provisioning
for arbitrary installation paths remains parked.

CI run 38033971486 failed its Python shard and parity leaf jobs because the
catalog checker imported LiteLLM's mutable remote registry despite documenting a
locked bundled registry. The checker now reads the installed wheel's JSON via
package metadata without importing LiteLLM, with regression coverage.

The first updated CI run passed Schema & Parity but Connector Matrix exposed an
old `init` test still expecting a closed fresh-install default. Align that test
with open delivery and additionally verify a repeated init without the flag
preserves an existing explicit closed setting.

## Verification / remaining environment checks

- macOS Go config, connector, hook executor, enterprise-hook and CLI tests passed.
- Focused Python suite: 379 passed, 6 skipped, 12 subtests passed.
- Python connector matrix: 483 passed, 20 skipped, 128 subtests passed with
  isolated DefenseClaw state; init defaults and closed-policy preservation pass.
- Go vet passed for macOS and Windows; Windows packages and tests cross-compiled.
- Schema/reference and catalog checks passed. Full local `make check` stopped at
  npm E401 in provider-coverage dependency installation, not a code assertion.
- Native Windows execution is not available on this macOS host; run the added
  Windows installation/runtime/enumeration tests on an elevated Windows runner.
- No local installation or dist build was replaced or removed.
