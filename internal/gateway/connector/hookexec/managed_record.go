// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Stable reasons of managed hook failures that the hook always records as an
// integrity boundary rather than a degraded subsystem.
const (
	managedRuntimeStateInvalidReason        = "enterprise_managed_runtime_state_invalid"
	managedRuntimeHomeMissingReason         = "enterprise_managed_runtime_home_missing"
	managedRuntimeDisableSentinelReason     = "enterprise_managed_runtime_disable_sentinel_forbidden"
	managedRuntimeTokenEmptyReason          = "authenticated managed runtime token is empty"
	managedHookTokenUnreadableReason        = "managed hook token unreadable"
	managedHookTokenEmptyReason             = "managed hook token empty"
	managedHookOversizedReason              = "stdin body exceeded cap"
	managedHookRecordEventMaxBytes          = 128
	managedHookDecisionRecordDefaultSource  = "DefenseClawGateway"
	managedHookDecisionRecordComponentValue = "hook"
)

// managedHookDecisionRecorder persists one formatted managed hook decision
// line under source. It is a seam for tests; the platform default writes the
// Windows Application event log and is a no-op elsewhere.
var managedHookDecisionRecorder = writeManagedHookDecisionRecord

// recordManagedHookDecision leaves a durable record of every fail-open and
// fail-closed decision a managed hook takes, so a bypass is never silent
// while the services report healthy. The record carries stable reasons only:
// never payloads, response bodies, tokens or transport error text.
func recordManagedHookDecision(opts Options, sp spec, reason, category, failMode string, blocked bool) {
	marker := managed.MarkerDegraded
	if managedHookBoundaryReason(reason) {
		marker = managed.MarkerBoundary
	}
	decision := "allow"
	if blocked {
		decision = "block"
	}
	fields := map[string]string{
		"component": managedHookDecisionRecordComponentValue,
		"connector": sp.connector,
		"hook":      sp.hookName,
		"event":     boundedManagedRecordField(opts.Event, managedHookRecordEventMaxBytes),
		"reason":    reason,
		"category":  category,
		"fail_mode": failMode,
		"decision":  decision,
	}
	// Written straight to the durable recorder, never through the standard
	// logger: agents surface hook stderr, and Claude Code turns it into the
	// block message shown to the user and the model.
	managedHookDecisionRecorder(
		managedHookDecisionRecordSource(opts.ManagedGatewayServiceName),
		marker,
		managed.FormatResilienceEvent(marker, fields),
	)
}

// InstallManagedHookDiagnosticSinks routes the managed package's resilience
// events and trust advisories to the durable recorder for the rest of the
// process, so nothing a managed check reports during hook resolution reaches
// the agent through stdout or stderr. A hook entrypoint calls it once at
// startup, before any managed check runs.
func InstallManagedHookDiagnosticSinks() {
	source := managedHookDecisionRecordSource("")
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		managedHookDecisionRecorder(source, marker, managed.FormatResilienceEvent(marker, fields))
	}
	managed.ReportTrustAdvisory = func(path, label, reason string) {
		managedHookDecisionRecorder(source, managed.TrustAdvisoryMarker, managed.FormatResilienceEvent(
			managed.TrustAdvisoryMarker,
			map[string]string{"path": path, "label": label, "reason": reason},
		))
	}
	managed.ReportTrustDrift = func(path, label, reason string) {
		managedHookDecisionRecorder(source, managed.TrustDriftAdvisoryMarker, managed.FormatResilienceEvent(
			managed.TrustDriftAdvisoryMarker,
			map[string]string{"path": path, "label": label, "reason": reason},
		))
	}
}

// managedHookBoundaryReason reports the managed failures that are integrity
// findings: tampered or missing runtime state, an identified foreign
// listener, a refused credential and a payload over the cap.
func managedHookBoundaryReason(reason string) bool {
	switch reason {
	case managedRuntimeStateInvalidReason,
		managedRuntimeHomeMissingReason,
		managedRuntimeDisableSentinelReason,
		managedRuntimeTokenEmptyReason,
		managedHookTokenUnreadableReason,
		managedHookTokenEmptyReason,
		managedHookOversizedReason,
		managedGatewayPortHeldReason,
		managedGatewayPeerUnverifiedReason:
		return true
	}
	if strings.HasPrefix(reason, missingGatewayTokenReason) {
		return true
	}
	return strings.HasPrefix(reason, "gateway returned HTTP 401") ||
		strings.HasPrefix(reason, "gateway returned HTTP 403")
}

func boundedManagedRecordField(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
