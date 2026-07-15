# Operations

Readiness is fail-closed: broker, gateway, policy, release manifest, audit database, and required MCP forwarder must all attest to the same hashes. Collector delivery is asynchronous, but local broker/audit commits are synchronous.

The broker denies new work below 5 GiB or 10% free space, over 100,000 or 512 MiB undelivered outbox events, or when the oldest event exceeds 24 hours. Crash recovery marks uncertain work ORPHANED and never retries it.

Rollback may select only a previously verified mandatory-AXIS release. If none starts cleanly, disable the managed launcher and use explicit human sudo break-glass.
