# Spec 002 — AVC-driven Windows enterprise packaging

**Status:** Implemented.

This specification records the build-kit and signing boundary used to produce
`DefenseClawSetup-Enterprise-x64.exe`. The operator-facing contract is
[Windows AVC packaging handoff](../../WINDOWS-AVC-PACKAGING-HANDOFF.md).

- [Requirements](requirements.md)
- [Design](design.md)
- [Implemented tasks](tasks.md)

The old native-Windows enterprise builder is retired. DefenseClaw prepares an
unsigned offline kit; AVC signs the inner payload, runs the shipped assembler,
signs the outer Setup, and finalizes its hash and provenance.
