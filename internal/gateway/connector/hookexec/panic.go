// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "fmt"

// managedHookInternalErrorReason is the stable reason of a managed hook that
// panicked. The value and stack are never recorded: they can carry payload
// or path fragments.
const managedHookInternalErrorReason = "managed hook internal error"

// HookPanicExit is the decision of a hook entrypoint that recovered a panic,
// for os.Exit. A managed hook records a boundary decision and fails closed
// with the connector's fail-closed output and the fixed block sentence, and
// prints no stack: agents show hook stderr to the user. An unmanaged hook
// prints one line and exits 2, the exit status an unrecovered panic had.
func HookPanicExit(opts Options, recovered any) int {
	opts = withDefaults(opts)
	if !opts.ManagedEnterprise {
		fmt.Fprintf(opts.Stderr, "defenseclaw: hook internal error: %q\n", fmt.Sprint(recovered))
		return blockExit
	}
	sp, ok := specFor(opts.Connector)
	if !ok {
		fmt.Fprintln(opts.Stderr, ManagedHookBlockMessage)
		return blockExit
	}
	return failUnreachable(opts, sp, "closed", managedHookInternalErrorReason)
}
