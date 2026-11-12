// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"io"
)

// managedHookInternalErrorReason is the stable reason of a managed hook that
// panicked. The value and stack are never recorded: they can carry payload
// or path fragments.
const managedHookInternalErrorReason = "managed hook internal error"

// HookPanicExit is the decision of a hook entrypoint that recovered a panic,
// for os.Exit. A managed hook records a boundary decision and fails closed
// with the connector's fail-closed output and one fixed sentence, and prints
// no stack: agents show hook stderr to the user. The failure path's own
// diagnostic is discarded. An unmanaged hook prints one line and exits 2, the
// exit status an unrecovered panic had.
//
// The caller's Secure Client host check (opts.SecureClient) chooses only the
// sentence, as on every other managed failure path
// (quietManagedFailureStderr): ManagedHookBlockMessage on a Secure Client
// hook, DefenseClaw's own text otherwise (GAP-0074). The decision, exit
// status, stdout and record do not depend on it: they are computed without
// SecureClient, as before the host check was passed in, so a Secure Client
// host answers a panic exactly as it did (a Hermes panic stays closed).
func HookPanicExit(opts Options, recovered any) int {
	opts = withDefaults(opts)
	if !opts.ManagedEnterprise {
		fmt.Fprintf(opts.Stderr, "defenseclaw: hook internal error: %q\n", fmt.Sprint(recovered))
		return blockExit
	}
	message := managedHookPanicMessage(opts)
	opts.SecureClient = false
	stderr := opts.Stderr
	sp, ok := specFor(opts.Connector)
	if !ok {
		fmt.Fprintln(stderr, message)
		return blockExit
	}
	opts.Stderr = io.Discard
	code := failUnreachable(opts, sp, "closed", managedHookInternalErrorReason)
	fmt.Fprintln(stderr, message)
	return code
}

// managedHookPanicMessage is the block sentence of a managed hook that
// panicked: the Secure Client sentence on a Secure Client hook, otherwise
// DefenseClaw's own text that the check failed internally. It is not one of
// managedStandaloneFailClosedText's causes: that text is also the stdout
// reason some connectors (Hermes) give on every managed host.
func managedHookPanicMessage(opts Options) string {
	if quietManagedFailureStderr(opts) {
		return ManagedHookBlockMessage
	}
	return "DefenseClaw blocked this " + hookEventSubject(opts.Event) +
		": the DefenseClaw hook stopped on an internal error before it could finish checking it." +
		" Try again; if this continues, contact your administrator."
}
