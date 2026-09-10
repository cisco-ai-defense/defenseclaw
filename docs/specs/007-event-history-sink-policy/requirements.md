# Requirements

- REQ-01: Mandatory local event-history persistence must accept the same
  request-scoped sink-policy profile selected by the local log pipeline.
- REQ-02: `default`, `raw`, and `redact` must resolve respectively to the
  configured profile, built-in `none`, and built-in `sensitive`.
- REQ-03: Unknown sink policies and invalid configured profiles must fail
  closed before SQLite persistence.
- REQ-04: The event-history writer must continue validating projection origin,
  profile fingerprint, correlation-key identity, detector-catalog version, and
  canonical-record correspondence.
- REQ-05: Applying a request-scoped override must not mutate the compiled plan,
  its configured profiles, or another request's resolution.
