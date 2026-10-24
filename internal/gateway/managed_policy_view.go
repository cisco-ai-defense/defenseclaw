// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// managedPolicyView is the gateway's published proof of the vendor machine
// policy its managed hooks enforce, per machine-policy connector. The
// gateway computes it at start and when a policy source or the runtime
// descriptor changes (managed_policy_view_unix.go). A hook call only reads
// it: a managed hook does no policy-view work, and the gateway adds one
// pointer load and two map lookups to a call (review loop round 1, P1).
type managedPolicyView struct {
	connectors map[string]managedPolicyViewConnector
}

type managedPolicyViewConnector struct {
	// shared: the shared vendor sources differ from the descriptor's pin,
	// have no pin (a descriptor from before pins), or can not be read.
	shared bool
	// allAccounts: the macOS managed-preferences folder can not be read,
	// so no account's own preference is proven.
	allAccounts bool
	// accounts are the macOS accounts whose own managed preference the
	// descriptor's per-account pins do not prove.
	accounts map[string]bool
}

// unproven reports whether a call by account through connector runs under a
// vendor policy view the gateway can not prove. Such a call is still served
// and inspected under the managed policy; it only raises the alert. A nil
// view (no descriptor, or none computed) alerts nothing: a hook without a
// trusted descriptor refuses its call itself.
func (v *managedPolicyView) unproven(connector, account string) bool {
	if v == nil || connector == "" {
		return false
	}
	state, ok := v.connectors[connector]
	return ok && (state.shared || state.allAccounts || state.accounts[account])
}
