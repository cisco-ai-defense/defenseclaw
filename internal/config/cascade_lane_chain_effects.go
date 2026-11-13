// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

// The two scope chains of S7 chain-effects (internal/gateway/chain_effects.go)
// are lanes under guardrail.cascade.lanes. Both ship in shadow: a hit is
// recorded in the session's explain ring and the audit row and no answer
// changes; on adds one finding (alert by default, block in strict and managed
// where the sensitive material is proven).
func init() {
	RegisterCascadeLane(CascadeLane{
		Name:    "chain_effects",
		Default: CascadeLaneShadow,
		Description: "chain.sensitive_read_then_unscoped_send: the session holds sensitive material (a result the content rules name, or the answer of a read tool) and a later " +
			"call sends to a destination no prompt of the session named",
	})
	RegisterCascadeLane(CascadeLane{
		Name:    "chain_effects_value",
		Default: CascadeLaneShadow,
		Description: "chain.sensitive_value_then_unscoped_send: the call sends a value or file secret flow labelled from an earlier sensitive read to a destination " +
			"no prompt of the session named (needs guardrail.secret_flow not off)",
	})
}
