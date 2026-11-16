//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// Machine-policy reporting, tolerant policy reads and the user-disabled
// hooks repair are macOS managed-mode behaviour; elsewhere these keep the
// established strict behaviour.

const cursorHooksLockedWriter = false

func reportAgentPolicyBlocksUserHooks(string, string, string, string) {}

func agentPolicyReadRetryable(error) bool { return false }

func agentPolicyReadTolerated(string, string, string, error) bool { return false }

func reportUserDisabledHooksRepair(string, string) {}

func userDisabledHooksRepairEnabled(SetupOpts) bool { return false }

func codexPlatformManagedPolicy(policy codexEffectivePolicy, err error) (codexEffectivePolicy, error) {
	return policy, err
}

func codexAttributePolicy(policy codexEffectivePolicy) codexEffectivePolicy { return policy }

func codexRequirementsUntrustedAccepted(string, error) bool { return false }

func codexPreinspectedPolicy(string, string) (codexEffectivePolicy, bool) {
	return codexEffectivePolicy{}, false
}

func codexPolicySpawnUnsafe() bool { return false }
