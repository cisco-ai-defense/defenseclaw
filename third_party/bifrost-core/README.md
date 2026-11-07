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
The copied Go sources are formatted with the pinned toolchain.
