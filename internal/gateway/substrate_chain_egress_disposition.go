// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// The chain egress disposition of Agent Substrate actors (owner decision
// 2026-11-13): actors are unattended, so a verified actor's hook call that
// completes a chain the callout refuses (chainstate.RefusesEgress: a secret
// read, or a secret-manager read, then external egress) is refused in every
// tier, the open source default pack as well as strict and managed. The one
// setting is the config key substrate.chain_egress_action: block (the
// default) or alert (an opt-in that only alerts), set with the chart value
// config.substrate.chain_egress_action, which the gateway and the leader both
// read (cfg.Substrate.EffectiveChainEgressAction, GAP-0250). Host and
// OpenShell hooks keep the pack's disposition: an alert in the default pack.

// substrateChainEgressAlert is true only after the gateway role read
// substrate.chain_egress_action=alert. Unset is block.
var substrateChainEgressAlert atomic.Bool

// SetSubstrateChainEgressAction sets the chain egress action of verified
// actors' hook calls from cfg.Substrate.EffectiveChainEgressAction(): "" or
// block refuses, alert alerts.
func SetSubstrateChainEgressAction(action string) error {
	switch action {
	case "", chainstate.EgressBlock:
		substrateChainEgressAlert.Store(false)
	case chainstate.EgressAlert:
		substrateChainEgressAlert.Store(true)
	default:
		return fmt.Errorf("chain egress action %q is not block or alert", action)
	}
	return nil
}

// substrateChainEgressIntent is the hook intent of a chain result: block for
// a verified Substrate actor whose result detects a chain the callout
// refuses, unless the operator chose alert; intent otherwise. The hook
// profile still maps a block to what the event and mode allow (a would-block
// in observe mode, an alert on an event that cannot block).
func substrateChainEgressIntent(
	ctx context.Context,
	intent string,
	result audit.ToolChainObserveResult,
) string {
	if intent == guardrailActionBlock || substrateChainEgressAlert.Load() ||
		!isSubstrateActorRequest(ctx) {
		return intent
	}
	for _, id := range result.DetectedChainIDs {
		if chainstate.RefusesEgress(id) {
			return guardrailActionBlock
		}
	}
	return intent
}
