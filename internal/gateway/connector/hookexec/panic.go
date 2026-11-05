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
// no stack: agents show hook stderr to the user. The panic may come before
// the hook knew its profile, so the sentence follows only the caller's
// Secure Client host check (opts.SecureClient), as every other managed
// failure path does (quietManagedFailureStderr): a Secure Client hook prints
// ManagedHookBlockMessage, any other managed hook names DefenseClaw
// (GAP-0074). The failure path's own diagnostic is discarded. An unmanaged
// hook prints one line and exits 2, the exit status an unrecovered panic had.
func HookPanicExit(opts Options, recovered any) int {
	opts = withDefaults(opts)
	if !opts.ManagedEnterprise {
		fmt.Fprintf(opts.Stderr, "defenseclaw: hook internal error: %q\n", fmt.Sprint(recovered))
		return blockExit
	}
	stderr := opts.Stderr
	sp, ok := specFor(opts.Connector)
	if !ok {
		fmt.Fprintln(stderr, managedHookPanicMessage(opts))
		return blockExit
	}
	opts.Stderr = io.Discard
	code := failUnreachable(opts, sp, "closed", managedHookInternalErrorReason)
	fmt.Fprintln(stderr, managedHookPanicMessage(opts))
	return code
}

// managedHookPanicMessage is the block sentence of a managed hook that
// panicked: the Secure Client sentence on a Secure Client hook, otherwise
// DefenseClaw's own text that the check failed internally.
func managedHookPanicMessage(opts Options) string {
	if quietManagedFailureStderr(opts) {
		return ManagedHookBlockMessage
	}
	return managedStandaloneFailClosedText(opts.Event, "internal", managedHookInternalErrorReason)
}
