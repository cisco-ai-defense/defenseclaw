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

// GAP-2462 (GAP-2459): a managed hook whose runtime state a Setup or
// package run is rewriting (the 1.0.3 Codex registration still in place
// while the new runtime generation is written) refused with "DefenseClaw is
// not set up correctly on this computer. Contact your administrator." for 72
// s of a Windows Setup /ensure. Inside the run it names the upgrade; outside
// the run, and for a refusal with a cause of its own, it keeps its text.
func TestManagedRuntimeStateRefusalNamesTheUpgradeDuringALifecycleRun(t *testing.T) {
	previous := managedLifecycleHeld
	t.Cleanup(func() { managedLifecycleHeld = previous })
	held := true
	var sawService string
	managedLifecycleHeld = func(opts Options) bool { sawService = opts.ManagedGatewayServiceName; return held }
	opts := Options{ManagedEnterprise: true, Event: "PreToolUse"}
	const upgrade = "DefenseClaw is being installed or upgraded on this computer"
	const generic = "DefenseClaw is not set up correctly on this computer"

	runtimeState := []string{
		"enterprise_managed_runtime_state_invalid", "enterprise_managed_runtime_descriptor_missing",
		"enterprise_managed_hook_socket_missing", "enterprise_machine_policy_summary_untrusted",
	}
	for _, reason := range runtimeState {
		if got := managedStandaloneFailClosedText(opts.Event, "transport", reason); !strings.Contains(got, generic) {
			t.Fatalf("%s outside the run is no longer the generic refusal: %q", reason, got)
		}
		sawService = ""
		got := managedFailClosedText(opts, "transport", reason)
		if !strings.Contains(got, upgrade) || strings.Contains(got, generic) ||
			!strings.HasPrefix(got, "DefenseClaw blocked this tool call: ") {
			t.Fatalf("%s during a lifecycle run: %q", reason, got)
		}
		// The refusal resolved no service: the Windows marker is read on the
		// standalone gateway service.
		if sawService != "DefenseClawGateway" {
			t.Fatalf("%s: lifecycle marker read on service %q", reason, sawService)
		}
	}
	// A refusal with a cause of its own keeps its text in the run.
	for _, reason := range []string{managedRuntimeHomeMissingReason, "enterprise_managed_runtime_disable_sentinel_forbidden",
		managedSIDUnregisteredReason, managedEnrollmentPendingReason} {
		if got := managedFailClosedText(opts, "transport", reason); strings.Contains(got, upgrade) {
			t.Fatalf("%s took the upgrade text: %q", reason, got)
		}
	}
	// A resolved service name is kept.
	named := opts
	named.ManagedGatewayServiceName = "OtherGateway"
	_ = managedFailClosedText(named, "transport", runtimeState[0])
	if sawService != "OtherGateway" {
		t.Fatalf("resolved service replaced: %q", sawService)
	}
	// Outside a run, and on Secure Client, the generic refusal is unchanged.
	held = false
	for _, reason := range runtimeState {
		if got := managedFailClosedText(opts, "transport", reason); got != managedStandaloneFailClosedText(opts.Event, "transport", reason) {
			t.Fatalf("%s outside a lifecycle run: %q", reason, got)
		}
	}
	held = true
	sc := Options{ManagedEnterprise: true, SecureClient: true, Event: "PreToolUse"}
	if got := managedFailClosedText(sc, "transport", runtimeState[0]); strings.Contains(got, upgrade) {
		t.Fatalf("Secure Client hook: %q", got)
	}
	// Only the transport layer.
	if got := managedFailClosedText(opts, "response", runtimeState[0]); strings.Contains(got, upgrade) {
		t.Fatalf("response layer: %q", got)
	}
}
