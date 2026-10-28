// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// GAP-2343 (GAP-2173): while an enterprise lifecycle run (a package upgrade, ensure,
// repair) has the managed gateway stopped or restarting, a managed hook's
// refusal says that DefenseClaw is being installed or upgraded. It said
// "the DefenseClaw gateway is not available" or "is restarting to apply a
// change", which did not name the upgrade.
func TestManagedRefusalNamesTheUpgradeDuringALifecycleRun(t *testing.T) {
	previous := managedLifecycleHeld
	t.Cleanup(func() { managedLifecycleHeld = previous })
	held := true
	managedLifecycleHeld = func(Options) bool { return held }
	opts := Options{ManagedEnterprise: true, Event: "PreToolUse"}
	const upgrade = "DefenseClaw is being installed or upgraded on this computer"

	for _, reason := range []string{
		managedGatewayNotRunningReason, managedGatewayRestartingReason, managedGatewayNoAnswerReason,
		managedGatewayPeerUnverifiedReason, "gateway unreachable",
	} {
		got := managedFailClosedText(opts, "transport", reason)
		if !strings.Contains(got, upgrade) || !strings.HasPrefix(got, "DefenseClaw blocked this tool call: ") ||
			!strings.Contains(got, "Try again in a moment") {
			t.Fatalf("%s during a lifecycle run: %q", reason, got)
		}
	}
	// A refusal with a cause of its own keeps its text in the window.
	for _, reason := range []string{
		managedGatewayPortHeldReason, managedUIDUnregisteredReason, managedSIDUnregisteredReason,
		managedHookSocketSELinuxDeniedReason, ManagedUserNamespaceReason, managedRuntimeHomeMissingReason,
		MalformedHookPayloadReason, "",
	} {
		if got := managedFailClosedText(opts, "transport", reason); strings.Contains(got, upgrade) ||
			got != managedStandaloneFailClosedText(opts.Event, "transport", reason) {
			t.Fatalf("%q kept its own text: %q", reason, got)
		}
	}
	// Only transport failures: a bad answer or an oversized call is no outage.
	for _, layer := range []string{"response", "oversized", "input"} {
		if got := managedFailClosedText(opts, layer, managedGatewayNotRunningReason); strings.Contains(got, upgrade) {
			t.Fatalf("layer %s: %q", layer, got)
		}
	}
	// No lifecycle run: the outage texts are unchanged.
	held = false
	for _, reason := range []string{managedGatewayNotRunningReason, managedGatewayRestartingReason, "gateway unreachable"} {
		if got := managedFailClosedText(opts, "transport", reason); got != managedStandaloneFailClosedText(opts.Event, "transport", reason) {
			t.Fatalf("%s outside a lifecycle run: %q", reason, got)
		}
	}
	// A Secure Client hook has no standalone lifecycle.
	held = true
	sc := Options{ManagedEnterprise: true, SecureClient: true, Event: "PreToolUse"}
	if got := managedFailClosedText(sc, "transport", managedGatewayNotRunningReason); strings.Contains(got, upgrade) {
		t.Fatalf("Secure Client hook: %q", got)
	}
}
