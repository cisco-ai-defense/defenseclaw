# Privacy high assurance

This opt-in guardrail profile extends the embedded balanced defaults and raises
the highest-confidence structured PII families to `CRITICAL`, which blocks in
balanced, permissive, and strict action postures.

The profile intentionally omits loose email, phone, passport, driver's-license,
unformatted SSN, and NHS-number patterns. Email and phone values are covered
only when they share a bounded field or clause with an explicit English label.
Unlabeled addresses and numbers remain better suited to detection or
organization-specific tuning.

Network-specific credit-card candidates continue through the gateway's
deterministic validity checks. The profile also covers 13--19 digit values that
immediately follow an explicit credit/debit-card field label. This latter rule
is deliberately label-bound because synthetic and private-label card records
do not always carry a recognizable issuer prefix or valid checksum.

The SSN rule accepts structurally valid hyphenated or space-delimited US SSNs
only when the surrounding record context is credible. DOB values require an
explicit DOB/date-of-birth label or a direct “born on” statement and a numeric
slash, dot, dash, or ISO date. Medical-record values require an MRN/patient
label plus identifier structure; schema prose such as “medical record number
field” is not a value.
