# Bifrost core v1.7.3

This directory contains the source files from `github.com/maximhq/bifrost/core`
v1.7.3, whose checksum is retained in the root `go.sum`. The upstream license is
in `LICENSE`. Test support and media fixtures are omitted.

The local change is in `providers/utils/utils.go`,
`providers/utils/roundtripper.go` and the new `providers/utils/proxy_conn.go`:
requests now carry their context through the provider transport, which closes
the model connection when a call ends, and an HTTP proxy connection is
returned before its TCP dial and CONNECT exchange so that a cancelled call
also closes it during either step.
`roundtripper.go` is adapted from Bifrost core v1.9.0 for the pinned dependency
versions. `TestGAP0564RealProviderCancellationReason`,
`TestGAP0564RealProviderDeadlineDisconnect`, and
`TestGAP0564RealProviderBenignAnswer` cover the local change.
A second local change is in `bifrost.go` (`tryRequest`, `handleRequest`): a call
whose context ended returns while the provider worker still owns the request and
writes the resolved model into it, so the caller no longer reads the request
after that point (the timeout error is named from the provider and model read
before the hand-off, and no fallback decision is made on an ended context).
`TestGAP0359TimedOutModelCallKeepsItsRequestUntilTheWorkerIsDone` (run it with
`-race`) covers it.
`bifrost.go` also sets `BifrostContextKeyProviderAccepted` (a new key in
`schemas/bifrost.go`) when a provider returns a stream, that is, after its
HTTP status check passed. It is never cleared for retries or fallbacks, so
the DefenseClaw gateway can tell a call that a provider accepted (and may
bill) from one every provider refused with an error status, even when the
stream then fails with a status of its own or a later attempt is refused.
`providers/replicate/replicate.go` sets the same key once a stream's
prediction is created, before its stream URL is read.
`TestTranslatedChatStreamAcceptedRequestIsUnknownCost` covers it.
The copied Go sources are formatted with the pinned toolchain.
