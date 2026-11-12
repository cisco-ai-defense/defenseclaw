// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// The endpoint health report is the periodic, self-contained health summary a
// managed-enterprise gateway sends to Cisco AI Defense and keeps in its local
// diagnostics folder. This file builds it:
//
//   - endpointHealthSources holds plain values already read from the
//     gateway's health snapshot, the managed AI Defense destination, the
//     inspection and CMID state, the guardian state file, the live policy
//     generation, discovery and the host AVC module;
//   - buildEndpointHealthReport is a pure function of those sources: it
//     applies every reason rule, derives the overall status and bounds the
//     result;
//   - (*Sidecar).collectEndpointHealthSources reads the sources, each one
//     with a timeout, and turns a source it cannot read into a
//     SUBSYSTEM_DEGRADED reason naming that source instead of an error.
//
// Privacy: the report carries states, closed codes, counts, timestamps and
// versions only. It never carries a path, prompt or tool content, a token,
// an email address or free-form error text: every error string is mapped to
// a closed error class and never copied. The only user identity is the
// user.id (SID or uid) of at most endpointHealthMaxFailingTargets failing
// guardian targets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Bounds and thresholds of the report.
const (
	endpointHealthMaxReasons        = 32
	endpointHealthMaxFailingTargets = 16
	endpointHealthMaxConnectors     = 16
	endpointHealthMaxSubsystems     = 16
	// endpointHealthMaxBytes is the hard cap on the serialized report body.
	endpointHealthMaxBytes = 32 << 10

	// endpointHealthStartupGrace is how long after gateway start a missing
	// configuration or guardian state is "starting" rather than a fault.
	endpointHealthStartupGrace = 10 * time.Minute
	// endpointHealthGuardianPassInterval is the guardian's reconcile cadence;
	// its state file is stale after endpointHealthGuardianStaleAfter.
	endpointHealthGuardianPassInterval = time.Minute
	endpointHealthGuardianStaleAfter   = 5 * endpointHealthGuardianPassInterval
	// endpointHealthCloudDeliveryFailures is the consecutive-failure count at
	// which delivery to AI Defense counts as degraded.
	endpointHealthCloudDeliveryFailures = 3
	// endpointHealthDiscoveryMissedIntervals full-scan intervals without a
	// completed full scan make discovery failing.
	endpointHealthDiscoveryMissedIntervals = 2
	// endpointHealthDefaultInterval is the managed full-scan cadence, used
	// when no interval is known.
	endpointHealthDefaultInterval = 30 * time.Minute

	// endpointHealthSourceTimeout bounds each source read that does I/O.
	endpointHealthSourceTimeout = 2 * time.Second
	// endpointHealthGuardianStateMaxBytes bounds the guardian state read.
	endpointHealthGuardianStateMaxBytes = 4 << 20
	// endpointHealthGuardianStateFile is the guardian's state file in
	// data_dir.
	endpointHealthGuardianStateFile = "hook_guardian_state.json"
)

// Triggers.
const (
	endpointHealthTriggerStartup      = "startup"
	endpointHealthTriggerScheduled    = "scheduled"
	endpointHealthTriggerConfigReload = "config_reload"
)

// Overall statuses, and the reason severities that share their names.
const (
	endpointHealthStatusHealthy   = "healthy"
	endpointHealthStatusStarting  = "starting"
	endpointHealthStatusDegraded  = "degraded"
	endpointHealthStatusUnhealthy = "unhealthy"
)

// Reason codes. Adding a code is a minor change; renaming or removing one
// is a breaking change of the report contract.
const (
	endpointHealthReasonConfigWaiting         = "CONFIG_WAITING"
	endpointHealthReasonConfigNotReady        = "CONFIG_NOT_READY"
	endpointHealthReasonSubsystemError        = "SUBSYSTEM_ERROR"
	endpointHealthReasonSubsystemDegraded     = "SUBSYSTEM_DEGRADED"
	endpointHealthReasonHooksNone             = "HOOKS_NONE"
	endpointHealthReasonHooksPartial          = "HOOKS_PARTIAL"
	endpointHealthReasonGuardianStale         = "GUARDIAN_STALE"
	endpointHealthReasonGuardianAbsent        = "GUARDIAN_ABSENT"
	endpointHealthReasonEnumeratorError       = "ENUMERATOR_ERROR"
	endpointHealthReasonInspectionUnavailable = "INSPECTION_UNAVAILABLE"
	endpointHealthReasonCMIDUnavailable       = "CMID_UNAVAILABLE"
	endpointHealthReasonFailOpenOccurred      = "FAIL_OPEN_OCCURRED"
	endpointHealthReasonCloudDeliveryDegraded = "CLOUD_DELIVERY_DEGRADED"
	endpointHealthReasonDiscoveryFailing      = "DISCOVERY_FAILING"
	endpointHealthReasonAuditStoreUnavailable = "AUDIT_STORE_UNAVAILABLE"
	endpointHealthReasonPolicyMissing         = "POLICY_MISSING"
)

// Reason components that are not a subsystem name.
const (
	endpointHealthComponentConfiguration = "configuration"
	endpointHealthComponentHooks         = "hooks"
	endpointHealthComponentGuardian      = "guardian"
	endpointHealthComponentInspection    = "inspection"
	endpointHealthComponentCMID          = "cmid"
	endpointHealthComponentCloudDelivery = "cloud_delivery"
	endpointHealthComponentAuditStore    = "audit_store"
	endpointHealthComponentPolicy        = "policy"
	// Source components: a source the collector could not read.
	endpointHealthSourceGatewayHealth = "gateway_health"
	endpointHealthSourceGuardianState = "guardian_state"
	endpointHealthSourceCloudDelivery = "cloud_delivery"
)

// Error classes: the closed set every error string maps to. The input text
// is never copied into the report.
const (
	endpointHealthErrorClassNone               = ""
	endpointHealthErrorClassPermissionDenied   = "PERMISSION_DENIED"
	endpointHealthErrorClassConfigWriteDenied  = "CONFIG_WRITE_DENIED"
	endpointHealthErrorClassNotFound           = "NOT_FOUND"
	endpointHealthErrorClassAccountSignedOut   = "ACCOUNT_SIGNED_OUT"
	endpointHealthErrorClassAccountUnavailable = "ACCOUNT_UNAVAILABLE"
	endpointHealthErrorClassUserPath           = "USER_PATH"
	endpointHealthErrorClassTimeout            = "TIMEOUT"
	endpointHealthErrorClassCanceled           = "CANCELED"
	endpointHealthErrorClassUnreachable        = "UNREACHABLE"
	endpointHealthErrorClassAuthFailed         = "AUTH_FAILED"
	endpointHealthErrorClassInvalidConfig      = "INVALID_CONFIG"
	endpointHealthErrorClassBusy               = "BUSY"
	endpointHealthErrorClassDiskFull           = "DISK_FULL"
	endpointHealthErrorClassContractUnverified = "HOOK_CONTRACT_UNVERIFIED"
	endpointHealthErrorClassOther              = "OTHER"
)

// Values of the guardian, inspection, CMID, delivery and audit store fields.
const (
	endpointHealthGuardianRunning = "running"
	endpointHealthGuardianStale   = "stale"
	endpointHealthGuardianAbsent  = "absent"

	endpointHealthInspectionOK          = "ok"
	endpointHealthInspectionUnavailable = "unavailable"
	endpointHealthInspectionUnknown     = "unknown"
	endpointHealthInspectionDisabled    = "disabled"

	endpointHealthCMIDOK          = "ok"
	endpointHealthCMIDUnavailable = "unavailable"

	endpointHealthCloudDeliveryAbsent = "absent"

	endpointHealthAuditStoreOK          = "ok"
	endpointHealthAuditStoreDegraded    = "degraded"
	endpointHealthAuditStoreUnavailable = "unavailable"
	endpointHealthAuditStoreUnknown     = "unknown"
)

var (
	// endpointHealthVersionPattern is the accepted shape of a version value;
	// anything else is omitted.
	endpointHealthVersionPattern = lazyregexp.New(`^[0-9A-Za-z.+_-]{1,64}$`)
	// endpointHealthPolicyVersionPattern also admits a short "sha256:<hex>"
	// effective policy digest.
	endpointHealthPolicyVersionPattern = lazyregexp.New(`^[0-9A-Za-z.:+_-]{1,64}$`)
	// endpointHealthTokenPattern is the shape of a connector name.
	endpointHealthTokenPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	// endpointHealthIdentifierPattern is the shape of a reason component
	// and a subsystem name.
	endpointHealthIdentifierPattern = lazyregexp.New(`^[a-z][a-z0-9_]{0,63}$`)
	// endpointHealthStatePattern is the shape of a state or class token
	// copied from a source.
	endpointHealthStatePattern = lazyregexp.New(`^[a-z][a-z0-9_]{0,31}$`)
	// endpointHealthModePattern is the shape of a tool inspection mode.
	endpointHealthModePattern = lazyregexp.New(`^[a-z][a-z0-9_-]{0,31}$`)
)

// endpointHealthReport is the report body. The JSON keys are the
// defenseclaw.health.* attribute names of the registry contract, so the same
// value is both the log record body and the local diagnostics file.
type endpointHealthReport struct {
	ReportID         string                 `json:"defenseclaw.health.report_id"`
	Sequence         uint64                 `json:"defenseclaw.health.sequence"`
	Trigger          string                 `json:"defenseclaw.health.trigger"`
	ObservedAt       string                 `json:"defenseclaw.health.observed_at"`
	ReportIntervalS  int64                  `json:"defenseclaw.health.report_interval_s"`
	Status           string                 `json:"defenseclaw.health.status"`
	Reasons          []endpointHealthReason `json:"defenseclaw.health.reasons"`
	ReasonsTruncated bool                   `json:"defenseclaw.health.reasons_truncated"`

	ProductVersion       string `json:"defenseclaw.health.version.product,omitempty"`
	PolicyBundleVersion  string `json:"defenseclaw.health.version.policy_bundle,omitempty"`
	AVCVersion           string `json:"defenseclaw.health.version.avc,omitempty"`
	OSVersion            string `json:"defenseclaw.health.os.version,omitempty"`
	GatewayStartedAt     string `json:"defenseclaw.health.gateway.started_at,omitempty"`
	GatewayUptimeS       int64  `json:"defenseclaw.health.gateway.uptime_s"`
	GatewayConfiguration string `json:"defenseclaw.health.gateway.configuration,omitempty"`

	Subsystems          []endpointHealthSubsystem `json:"defenseclaw.health.subsystems"`
	SubsystemsTruncated bool                      `json:"defenseclaw.health.subsystems_truncated"`
	GuardianState       string                    `json:"defenseclaw.health.guardian.state,omitempty"`
	GuardianLastPassAt  string                    `json:"defenseclaw.health.guardian.last_pass_at,omitempty"`

	HooksTargets                 int                           `json:"defenseclaw.health.hooks.targets"`
	HooksOK                      int                           `json:"defenseclaw.health.hooks.ok"`
	HooksFailed                  int                           `json:"defenseclaw.health.hooks.failed"`
	HooksPending                 int                           `json:"defenseclaw.health.hooks.pending"`
	HooksConnectors              []endpointHealthConnector     `json:"defenseclaw.health.hooks.connectors"`
	HooksConnectorsTruncated     bool                          `json:"defenseclaw.health.hooks.connectors_truncated"`
	HooksFailingTargets          []endpointHealthFailingTarget `json:"defenseclaw.health.hooks.failing_targets"`
	HooksFailingTargetsTruncated bool                          `json:"defenseclaw.health.hooks.failing_targets_truncated"`

	InspectionAIDefense         string `json:"defenseclaw.health.inspection.ai_defense"`
	InspectionUnavailableCode   string `json:"defenseclaw.health.inspection.unavailable_code,omitempty"`
	InspectionCMIDToken         string `json:"defenseclaw.health.inspection.cmid_token"`
	InspectionCMIDLastSuccessAt string `json:"defenseclaw.health.inspection.cmid_last_success_at,omitempty"`
	InspectionFailOpenSinceLast uint64 `json:"defenseclaw.health.inspection.fail_open_since_last"`

	CloudDeliveryState               string `json:"defenseclaw.health.cloud_delivery.state"`
	CloudDeliveryCircuit             string `json:"defenseclaw.health.cloud_delivery.circuit,omitempty"`
	CloudDeliveryConsecutiveFailures uint64 `json:"defenseclaw.health.cloud_delivery.consecutive_failures"`
	CloudDeliveryLastSuccessAt       string `json:"defenseclaw.health.cloud_delivery.last_success_at,omitempty"`
	CloudDeliveryLastFailureClass    string `json:"defenseclaw.health.cloud_delivery.last_failure_class,omitempty"`
	CloudDeliveryDroppedSinceLast    uint64 `json:"defenseclaw.health.cloud_delivery.dropped_since_last"`

	LocalStoreAuditStore string `json:"defenseclaw.health.local_store.audit_store"`
}

// endpointHealthReason is one reason code with the component it names.
type endpointHealthReason struct {
	Code      string `json:"code"`
	Component string `json:"component"`
	Severity  string `json:"severity"`
	Connector string `json:"connector,omitempty"`
}

// endpointHealthSubsystem is one present /health subsystem.
type endpointHealthSubsystem struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Since      string `json:"since,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

// endpointHealthConnector is one connector's guardian target counts and
// live hook activity.
type endpointHealthConnector struct {
	Connector          string `json:"connector"`
	Targets            int    `json:"targets"`
	OK                 int    `json:"ok"`
	Failed             int    `json:"failed"`
	Pending            int    `json:"pending"`
	LastActivityAt     string `json:"last_activity_at,omitempty"`
	ToolInspectionMode string `json:"tool_inspection_mode,omitempty"`
}

// endpointHealthFailingTarget is one guardian target that failed or is
// pending. UserID is the account's SID or uid, never a name or email.
type endpointHealthFailingTarget struct {
	Connector  string `json:"connector"`
	UserID     string `json:"user.id,omitempty"`
	UserIDKind string `json:"user.id_kind,omitempty"`
	ErrorClass string `json:"error_class"`
	Pending    bool   `json:"pending"`
}

// endpointHealthReportMeta is what the reporter, not a source, decides.
type endpointHealthReportMeta struct {
	ReportID string
	Sequence uint64
	Trigger  string
	// Interval is the effective report interval, including an operator
	// override.
	Interval time.Duration
}

// endpointHealthGuardianTarget is one row of the guardian's last reconcile,
// reduced to what the report may carry. Error is the guardian's raw text;
// the builder maps it to an error class and never copies it.
type endpointHealthGuardianTarget struct {
	Connector string
	UserID    string
	OK        bool
	Pending   bool
	Error     string
}

// endpointHealthGuardianSource is the guardian state file as read.
type endpointHealthGuardianSource struct {
	// Present is false when the state file does not exist.
	Present   bool
	UpdatedAt time.Time
	// ReadAt is when the file was read; staleness is measured from it.
	ReadAt  time.Time
	Targets []endpointHealthGuardianTarget
}

// endpointHealthSources are the plain, already-read inputs of one report.
type endpointHealthSources struct {
	Now time.Time
	// PreviousReportAt is when the previous report was collected; zero for
	// the first report of this gateway process.
	PreviousReportAt time.Time

	Health HealthSnapshot

	// CloudDelivery is the managed AI Defense destination's delivery health,
	// nil when it could not be read or is not configured.
	CloudDelivery                 *observabilityruntime.DestinationHealth
	CloudDeliveryDroppedSinceLast uint64

	InspectionEnabled   bool
	InspectionAvailable bool
	// InspectionObserved is false while a newly built client has had no
	// request answered.
	InspectionObserved bool
	// InspectionDetail is the raw unavailability text; mapped to a code.
	InspectionDetail  string
	FailOpenSinceLast uint64

	CMIDTokenOK     bool
	CMIDLastSuccess time.Time

	Guardian endpointHealthGuardianSource
	// HooksPendingSince is when the reporter first saw pending guardian
	// targets without a break; zero when none are pending.
	HooksPendingSince time.Time

	ProductVersion      string
	PolicyApplied       bool
	PolicyBundleVersion string

	DiscoveryEnabled        bool
	DiscoveryLastFullScanAt time.Time
	DiscoveryInterval       time.Duration

	AVCVersion string
	OSVersion  string

	// SourceErrors names each source that could not be read. Each one adds
	// SUBSYSTEM_DEGRADED with that source as the component.
	SourceErrors []string
}

// endpointHealthProtectionSubsystems are the subsystems whose error or stop
// leaves the endpoint unprotected.
var endpointHealthProtectionSubsystems = map[string]bool{
	"guardrail": true, "routing": true, "api": true, "managed": true,
}

func endpointHealthSeverityRank(severity string) int {
	switch severity {
	case endpointHealthStatusUnhealthy:
		return 3
	case endpointHealthStatusDegraded:
		return 2
	case endpointHealthStatusStarting:
		return 1
	default:
		return 0
	}
}

// buildEndpointHealthReport derives the report from src. It is pure: the
// same sources and meta always give the same report.
//
// Overall status is the worst reason severity, unhealthy > degraded >
// starting, and healthy when there is no reason. Reasons are sorted by
// severity (worst first), then code, component and connector; at most
// endpointHealthMaxReasons are kept. Where a specific rule covers a
// subsystem's error (ai_discovery, enumerator, the telemetry local store),
// that rule's code is reported instead of a generic SUBSYSTEM_DEGRADED.
func buildEndpointHealthReport(src endpointHealthSources, meta endpointHealthReportMeta) endpointHealthReport {
	now := src.Now.UTC()
	uptime := time.Duration(src.Health.UptimeMs) * time.Millisecond
	if uptime < 0 {
		uptime = 0
	}
	interval := meta.Interval
	if interval <= 0 {
		interval = endpointHealthDefaultInterval
	}
	report := endpointHealthReport{
		ReportID:            endpointHealthReportID(meta.ReportID),
		Sequence:            meta.Sequence,
		Trigger:             endpointHealthTrigger(meta.Trigger),
		ObservedAt:          now.Format(time.RFC3339Nano),
		ReportIntervalS:     int64(interval / time.Second),
		ProductVersion:      endpointHealthVersion(src.ProductVersion),
		PolicyBundleVersion: endpointHealthPolicyVersion(src.PolicyBundleVersion),
		AVCVersion:          endpointHealthVersion(src.AVCVersion),
		OSVersion:           endpointHealthVersion(src.OSVersion),
		GatewayStartedAt:    endpointHealthTime(src.Health.StartedAt),
		GatewayUptimeS:      int64(uptime / time.Second),
		Reasons:             []endpointHealthReason{},
		Subsystems:          []endpointHealthSubsystem{},
		HooksConnectors:     []endpointHealthConnector{},
		HooksFailingTargets: []endpointHealthFailingTarget{},
	}
	reasons := make([]endpointHealthReason, 0, 8)
	add := func(code, component, severity, connector string) {
		reasons = append(reasons, endpointHealthReason{
			Code: code, Component: endpointHealthIdentifier(component), Severity: severity,
			Connector: endpointHealthOptionalToken(connector),
		})
	}

	// Configuration readiness.
	if configuration := src.Health.Configuration; configuration != nil {
		report.GatewayConfiguration = endpointHealthOptionalState(string(configuration.State))
		if configuration.State != ConfigStateReady {
			if uptime < endpointHealthStartupGrace {
				add(endpointHealthReasonConfigWaiting, endpointHealthComponentConfiguration, endpointHealthStatusStarting, "")
			} else {
				add(endpointHealthReasonConfigNotReady, endpointHealthComponentConfiguration, endpointHealthStatusUnhealthy, "")
			}
		}
	}

	// Subsystems.
	for _, entry := range endpointHealthSubsystemEntries(src.Health) {
		subsystem := endpointHealthSubsystem{
			Name:       entry.name,
			State:      endpointHealthState(string(entry.health.State)),
			Since:      endpointHealthTime(entry.health.Since),
			ErrorClass: endpointHealthErrorClass(entry.health.LastError),
		}
		report.Subsystems = append(report.Subsystems, subsystem)
		switch entry.health.State {
		case StateError, StateStopped:
			if endpointHealthProtectionSubsystems[entry.name] {
				add(endpointHealthReasonSubsystemError, entry.name, endpointHealthStatusUnhealthy, "")
				continue
			}
			if entry.health.State != StateError {
				continue
			}
			switch entry.name {
			case "ai_discovery":
				add(endpointHealthReasonDiscoveryFailing, entry.name, endpointHealthStatusDegraded, "")
			case "enumerator":
				add(endpointHealthReasonEnumeratorError, entry.name, endpointHealthStatusDegraded, "")
			case "telemetry":
				// The telemetry subsystem errors only for the local audit
				// store; AUDIT_STORE_UNAVAILABLE below reports it.
			default:
				add(endpointHealthReasonSubsystemDegraded, entry.name, endpointHealthStatusDegraded, "")
			}
		case StateDegraded, StateReconnecting:
			if entry.name == "telemetry" {
				continue
			}
			add(endpointHealthReasonSubsystemDegraded, entry.name, endpointHealthStatusDegraded, "")
		}
	}

	// Guardian and hooks.
	applyEndpointHealthGuardian(&report, src, now, uptime, add)

	// Inspection, CMID and fail-open.
	switch {
	case !src.InspectionEnabled:
		report.InspectionAIDefense = endpointHealthInspectionDisabled
	case src.InspectionAvailable && src.InspectionObserved:
		report.InspectionAIDefense = endpointHealthInspectionOK
	case src.InspectionAvailable || strings.TrimSpace(src.InspectionDetail) == "":
		// Built but unproven, or never built yet.
		report.InspectionAIDefense = endpointHealthInspectionUnknown
	default:
		report.InspectionAIDefense = endpointHealthInspectionUnavailable
		report.InspectionUnavailableCode = endpointHealthState(aiDefenseUnavailableCode(src.InspectionDetail))
		add(endpointHealthReasonInspectionUnavailable, endpointHealthComponentInspection, endpointHealthStatusUnhealthy, "")
	}
	since := src.PreviousReportAt
	if since.IsZero() {
		since = src.Health.StartedAt
	}
	tokenSinceLast := !src.CMIDLastSuccess.IsZero() && !src.CMIDLastSuccess.Before(since)
	report.InspectionCMIDToken = endpointHealthCMIDUnavailable
	if src.CMIDTokenOK {
		report.InspectionCMIDToken = endpointHealthCMIDOK
	}
	report.InspectionCMIDLastSuccessAt = endpointHealthTime(src.CMIDLastSuccess)
	if !src.CMIDTokenOK && !tokenSinceLast {
		add(endpointHealthReasonCMIDUnavailable, endpointHealthComponentCMID, endpointHealthStatusUnhealthy, "")
	}
	report.InspectionFailOpenSinceLast = src.FailOpenSinceLast
	if src.FailOpenSinceLast > 0 && report.InspectionAIDefense != endpointHealthInspectionUnavailable {
		add(endpointHealthReasonFailOpenOccurred, endpointHealthComponentInspection, endpointHealthStatusDegraded, "")
	}

	// Delivery to AI Defense.
	if destination := src.CloudDelivery; destination == nil {
		report.CloudDeliveryState = endpointHealthCloudDeliveryAbsent
	} else {
		report.CloudDeliveryState = endpointHealthState(string(destination.State))
		report.CloudDeliveryCircuit = endpointHealthOptionalState(string(destination.CircuitState))
		report.CloudDeliveryConsecutiveFailures = destination.ConsecutiveFailures
		report.CloudDeliveryLastSuccessAt = endpointHealthTime(destination.LastSuccess)
		report.CloudDeliveryLastFailureClass = endpointHealthOptionalState(string(destination.LastFailureClass))
		report.CloudDeliveryDroppedSinceLast = src.CloudDeliveryDroppedSinceLast
		if destination.CircuitState == delivery.CircuitOpen ||
			destination.ConsecutiveFailures >= endpointHealthCloudDeliveryFailures ||
			src.CloudDeliveryDroppedSinceLast > 0 {
			add(endpointHealthReasonCloudDeliveryDegraded, endpointHealthComponentCloudDelivery, endpointHealthStatusDegraded, "")
		}
	}

	// Discovery: no completed full scan in two intervals. Before the first
	// scan the gateway start is the reference.
	if src.DiscoveryEnabled {
		discoveryInterval := src.DiscoveryInterval
		if discoveryInterval <= 0 {
			discoveryInterval = interval
		}
		reference := src.DiscoveryLastFullScanAt
		if reference.IsZero() {
			reference = src.Health.StartedAt
		}
		if !reference.IsZero() && now.Sub(reference) > endpointHealthDiscoveryMissedIntervals*discoveryInterval {
			add(endpointHealthReasonDiscoveryFailing, "ai_discovery", endpointHealthStatusDegraded, "")
		}
	}

	// Local audit store: the telemetry subsystem reports the local store.
	switch src.Health.Telemetry.State {
	case StateRunning:
		report.LocalStoreAuditStore = endpointHealthAuditStoreOK
	case StateDegraded, StateReconnecting:
		report.LocalStoreAuditStore = endpointHealthAuditStoreDegraded
	case StateError, StateStopped:
		report.LocalStoreAuditStore = endpointHealthAuditStoreUnavailable
	default:
		report.LocalStoreAuditStore = endpointHealthAuditStoreUnknown
	}
	if report.LocalStoreAuditStore == endpointHealthAuditStoreDegraded ||
		report.LocalStoreAuditStore == endpointHealthAuditStoreUnavailable {
		add(endpointHealthReasonAuditStoreUnavailable, endpointHealthComponentAuditStore, endpointHealthStatusDegraded, "")
	}

	// Policy.
	if !src.PolicyApplied {
		add(endpointHealthReasonPolicyMissing, endpointHealthComponentPolicy, endpointHealthStatusUnhealthy, "")
	}

	// Sources that could not be read.
	for _, source := range src.SourceErrors {
		add(endpointHealthReasonSubsystemDegraded, source, endpointHealthStatusDegraded, "")
	}

	reasons = endpointHealthSortReasons(reasons)
	report.Status = endpointHealthStatusHealthy
	if len(reasons) > 0 {
		report.Status = reasons[0].Severity
	}
	if len(reasons) > endpointHealthMaxReasons {
		reasons = reasons[:endpointHealthMaxReasons]
		report.ReasonsTruncated = true
	}
	report.Reasons = reasons
	if len(report.Subsystems) > endpointHealthMaxSubsystems {
		report.Subsystems = report.Subsystems[:endpointHealthMaxSubsystems]
		report.SubsystemsTruncated = true
	}
	enforceEndpointHealthReportSize(&report)
	return report
}

// applyEndpointHealthGuardian fills the guardian and hooks fields and their
// reasons.
func applyEndpointHealthGuardian(
	report *endpointHealthReport,
	src endpointHealthSources,
	now time.Time,
	uptime time.Duration,
	add func(code, component, severity, connector string),
) {
	connectors := map[string]*endpointHealthConnector{}
	connectorFor := func(name string) *endpointHealthConnector {
		name = endpointHealthToken(name)
		entry := connectors[name]
		if entry == nil {
			entry = &endpointHealthConnector{Connector: name}
			connectors[name] = entry
		}
		return entry
	}
	for _, live := range src.Health.Connectors {
		entry := connectorFor(live.Name)
		if live.LastActivityAt != nil {
			entry.LastActivityAt = endpointHealthTime(*live.LastActivityAt)
		}
		if mode := strings.ToLower(strings.TrimSpace(string(live.ToolInspectionMode))); endpointHealthModePattern.MatchString(mode) {
			entry.ToolInspectionMode = mode
		}
	}

	guardian := src.Guardian
	sourceFailed := false
	for _, source := range src.SourceErrors {
		if source == endpointHealthSourceGuardianState {
			sourceFailed = true
		}
	}
	switch {
	case sourceFailed:
		// SUBSYSTEM_DEGRADED names the unreadable guardian state.
	case !guardian.Present:
		report.GuardianState = endpointHealthGuardianAbsent
		if uptime >= endpointHealthStartupGrace {
			add(endpointHealthReasonGuardianAbsent, endpointHealthComponentGuardian, endpointHealthStatusUnhealthy, "")
		}
	default:
		readAt := guardian.ReadAt
		if readAt.IsZero() {
			readAt = now
		}
		report.GuardianLastPassAt = endpointHealthTime(guardian.UpdatedAt)
		report.GuardianState = endpointHealthGuardianRunning
		if guardian.UpdatedAt.IsZero() || readAt.Sub(guardian.UpdatedAt) > endpointHealthGuardianStaleAfter {
			report.GuardianState = endpointHealthGuardianStale
			add(endpointHealthReasonGuardianStale, endpointHealthComponentGuardian, endpointHealthStatusDegraded, "")
		}
		for _, target := range guardian.Targets {
			entry := connectorFor(target.Connector)
			entry.Targets++
			report.HooksTargets++
			switch {
			case target.Pending:
				entry.Pending++
				report.HooksPending++
			case target.OK:
				entry.OK++
				report.HooksOK++
			default:
				entry.Failed++
				report.HooksFailed++
			}
			if target.OK && !target.Pending {
				continue
			}
			failing := endpointHealthFailingTarget{
				Connector: entry.Connector,
				Pending:   target.Pending,
			}
			if kind := useridentity.KindForID(target.UserID); kind != "" {
				failing.UserID, failing.UserIDKind = strings.TrimSpace(target.UserID), kind
			}
			// A pending target waits for its account's session.
			failing.ErrorClass = endpointHealthErrorClassAccountSignedOut
			if !target.Pending {
				failing.ErrorClass = endpointHealthErrorClass(target.Error)
				if failing.ErrorClass == endpointHealthErrorClassNone {
					failing.ErrorClass = endpointHealthErrorClassOther
				}
			}
			report.HooksFailingTargets = append(report.HooksFailingTargets, failing)
		}
		if report.HooksTargets > 0 && report.HooksOK == 0 {
			add(endpointHealthReasonHooksNone, endpointHealthComponentHooks, endpointHealthStatusUnhealthy, "")
		}
		pendingOverdue := !src.HooksPendingSince.IsZero() &&
			now.Sub(src.HooksPendingSince) > endpointHealthGuardianPassInterval
		for _, entry := range connectors {
			if entry.Failed > 0 || (entry.Pending > 0 && pendingOverdue) {
				add(endpointHealthReasonHooksPartial, endpointHealthComponentHooks, endpointHealthStatusDegraded, entry.Connector)
			}
		}
	}

	names := make([]string, 0, len(connectors))
	for name := range connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		report.HooksConnectors = append(report.HooksConnectors, *connectors[name])
	}
	if len(report.HooksConnectors) > endpointHealthMaxConnectors {
		report.HooksConnectors = report.HooksConnectors[:endpointHealthMaxConnectors]
		report.HooksConnectorsTruncated = true
	}
	sort.SliceStable(report.HooksFailingTargets, func(i, j int) bool {
		a, b := report.HooksFailingTargets[i], report.HooksFailingTargets[j]
		if a.Pending != b.Pending {
			return !a.Pending
		}
		if a.Connector != b.Connector {
			return a.Connector < b.Connector
		}
		return a.UserID < b.UserID
	})
	if len(report.HooksFailingTargets) > endpointHealthMaxFailingTargets {
		report.HooksFailingTargets = report.HooksFailingTargets[:endpointHealthMaxFailingTargets]
		report.HooksFailingTargetsTruncated = true
	}
}

type endpointHealthSubsystemEntry struct {
	name   string
	health SubsystemHealth
}

// endpointHealthSubsystemEntries lists the present subsystems in a fixed
// order. Optional subsystems that are absent, and subsystems that never
// published a state, are left out.
func endpointHealthSubsystemEntries(snapshot HealthSnapshot) []endpointHealthSubsystemEntry {
	entries := make([]endpointHealthSubsystemEntry, 0, 13)
	addValue := func(name string, health SubsystemHealth) {
		if health.State != "" {
			entries = append(entries, endpointHealthSubsystemEntry{name: name, health: health})
		}
	}
	addPointer := func(name string, health *SubsystemHealth) {
		if health != nil {
			addValue(name, *health)
		}
	}
	addValue("gateway", snapshot.Gateway)
	addValue("watcher", snapshot.Watcher)
	addValue("config", snapshot.Config)
	addValue("api", snapshot.API)
	addValue("guardrail", snapshot.Guardrail)
	addValue("routing", snapshot.Routing)
	addValue("telemetry", snapshot.Telemetry)
	addValue("ai_discovery", snapshot.AIDiscovery)
	addValue("ai_runtime", snapshot.AIRuntime)
	addValue("application_protection", snapshot.ApplicationProtection)
	addPointer("sandbox", snapshot.Sandbox)
	addPointer("managed", snapshot.Managed)
	addPointer("enumerator", snapshot.Enumerator)
	return entries
}

// endpointHealthSortReasons removes duplicates and sorts by severity (worst
// first), code, component and connector.
func endpointHealthSortReasons(reasons []endpointHealthReason) []endpointHealthReason {
	seen := make(map[endpointHealthReason]bool, len(reasons))
	out := make([]endpointHealthReason, 0, len(reasons))
	for _, reason := range reasons {
		if seen[reason] {
			continue
		}
		seen[reason] = true
		out = append(out, reason)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := endpointHealthSeverityRank(a.Severity), endpointHealthSeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.Connector < b.Connector
	})
	return out
}

// enforceEndpointHealthReportSize keeps the serialized report within
// endpointHealthMaxBytes by halving, in turn, the failing targets, the
// connectors, the subsystems and the reasons, and setting the matching
// truncated flag. Reasons go last: they are sorted worst first, so the
// status-deciding reasons survive.
func enforceEndpointHealthReportSize(report *endpointHealthReport) {
	for range 256 {
		encoded, err := json.Marshal(report)
		if err == nil && len(encoded) <= endpointHealthMaxBytes {
			return
		}
		switch {
		case len(report.HooksFailingTargets) > 0:
			report.HooksFailingTargets = report.HooksFailingTargets[:len(report.HooksFailingTargets)/2]
			report.HooksFailingTargetsTruncated = true
		case len(report.HooksConnectors) > 0:
			report.HooksConnectors = report.HooksConnectors[:len(report.HooksConnectors)/2]
			report.HooksConnectorsTruncated = true
		case len(report.Subsystems) > 0:
			report.Subsystems = report.Subsystems[:len(report.Subsystems)/2]
			report.SubsystemsTruncated = true
		case len(report.Reasons) > 0:
			report.Reasons = report.Reasons[:len(report.Reasons)/2]
			report.ReasonsTruncated = true
		default:
			return
		}
	}
}

// endpointHealthErrorClass maps an error string to its closed error class.
// It returns "" for an empty string and OTHER for anything unrecognized; the
// input is never part of the result.
func endpointHealthErrorClass(text string) string {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return endpointHealthErrorClassNone
	}
	has := func(needles ...string) bool {
		for _, needle := range needles {
			if strings.Contains(text, needle) {
				return true
			}
		}
		return false
	}
	switch {
	case has("next sign-in", "signed out", "signed-out", "not signed in", "no active session", "wtsactive"):
		return endpointHealthErrorClassAccountSignedOut
	case has("context canceled", "operation was canceled"):
		return endpointHealthErrorClassCanceled
	case has("deadline exceeded", "timed out", "timeout"):
		return endpointHealthErrorClassTimeout
	case has("no space left", "disk full", "not enough space", "quota exceeded"):
		return endpointHealthErrorClassDiskFull
	case has("sharing violation", "being used by another process", "resource busy", "device or resource busy", "locked"):
		return endpointHealthErrorClassBusy
	case has("symlink", "symbolic link", "reparse point", "not a directory", "is a directory"):
		return endpointHealthErrorClassUserPath
	case has("hook contract", "unverified"):
		return endpointHealthErrorClassContractUnverified
	case has("access is denied", "access denied", "permission denied", "operation not permitted", "eacces", "eperm"):
		if has("write", "rename", "create", "replace") {
			return endpointHealthErrorClassConfigWriteDenied
		}
		return endpointHealthErrorClassPermissionDenied
	case has("unauthorized", "forbidden", "api key was rejected", "authentication", "status 401", "status 403", "http 401", "http 403"):
		return endpointHealthErrorClassAuthFailed
	case has("unknown user", "no such user", "account does not exist", "account was removed", "is not available yet", "user home"):
		return endpointHealthErrorClassAccountUnavailable
	case has("connection refused", "no route to host", "unreachable", "network is down", "no such host", "connection reset"):
		return endpointHealthErrorClassUnreachable
	case has("no such file", "cannot find", "not found", "does not exist", "missing"):
		return endpointHealthErrorClassNotFound
	case has("invalid", "malformed", "parse", "unmarshal", "syntax", "unsupported", "unexpected"):
		return endpointHealthErrorClassInvalidConfig
	default:
		return endpointHealthErrorClassOther
	}
}

// normalizeEndpointHealthVersion turns a PE resource version such as
// "5, 1, 21, 4204" into "5.1.21.4204" and reports whether the result is an
// acceptable version value.
func normalizeEndpointHealthVersion(raw string) (string, bool) {
	value := strings.TrimSpace(strings.TrimRight(raw, "\x00"))
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		for index, part := range parts {
			parts[index] = strings.TrimSpace(part)
		}
		value = strings.Join(parts, ".")
	}
	if !endpointHealthVersionPattern.MatchString(value) {
		return "", false
	}
	return value, true
}

func endpointHealthVersion(raw string) string {
	value, _ := normalizeEndpointHealthVersion(raw)
	return value
}

func endpointHealthPolicyVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if !endpointHealthPolicyVersionPattern.MatchString(raw) {
		return ""
	}
	return raw
}

// endpointHealthToken returns raw as a lower-case token, "other" when it is
// not one.
func endpointHealthToken(raw string) string {
	if token := endpointHealthOptionalToken(raw); token != "" {
		return token
	}
	return "other"
}

// endpointHealthOptionalToken is endpointHealthToken with "" for an empty
// value.
func endpointHealthOptionalToken(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if !endpointHealthTokenPattern.MatchString(raw) {
		return "other"
	}
	return raw
}

// endpointHealthIdentifier returns raw as a component or subsystem name,
// "other" when it is not one.
func endpointHealthIdentifier(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if !endpointHealthIdentifierPattern.MatchString(raw) {
		return "other"
	}
	return raw
}

// endpointHealthState returns raw as a state token, "other" when it is not
// one.
func endpointHealthState(raw string) string {
	if state := endpointHealthOptionalState(raw); state != "" {
		return state
	}
	return "other"
}

// endpointHealthOptionalState is endpointHealthState with "" for an empty
// value.
func endpointHealthOptionalState(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if !endpointHealthStatePattern.MatchString(raw) {
		return "other"
	}
	return raw
}

func endpointHealthTrigger(raw string) string {
	switch raw {
	case endpointHealthTriggerStartup, endpointHealthTriggerConfigReload:
		return raw
	default:
		return endpointHealthTriggerScheduled
	}
}

// endpointHealthReportID keeps a report id only when it is a lower-case
// UUID.
var endpointHealthReportIDPattern = lazyregexp.New(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func endpointHealthReportID(raw string) string {
	if endpointHealthReportIDPattern.MatchString(raw) {
		return raw
	}
	return ""
}

func endpointHealthTime(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}

// endpointHealthServiceExecutable is the executable of a Windows service
// ImagePath: the quoted path, or the path up to ".exe" or the first space,
// without the NT "\??\" prefix. Arguments are dropped.
func endpointHealthServiceExecutable(image string) string {
	image = strings.TrimSpace(image)
	image = strings.TrimPrefix(image, `\??\`)
	if strings.HasPrefix(image, `"`) {
		end := strings.IndexByte(image[1:], '"')
		if end < 0 {
			return ""
		}
		return image[1 : end+1]
	}
	if end := strings.Index(strings.ToLower(image), ".exe"); end >= 0 {
		return image[:end+len(".exe")]
	}
	if end := strings.IndexAny(image, " \t"); end >= 0 {
		return image[:end]
	}
	return image
}

// errEndpointHealthSourceUnavailable reports a source the gateway has not
// bound.
var errEndpointHealthSourceUnavailable = errors.New("endpoint health source unavailable")

// endpointHealthRead runs read with a timeout. A read that outlives it is
// abandoned; its result is discarded.
func endpointHealthRead[T any](
	ctx context.Context,
	timeout time.Duration,
	read func(context.Context) (T, error),
) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := read(ctx)
		done <- result{value: value, err: err}
	}()
	select {
	case out := <-done:
		return out.value, out.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// endpointHealthLookupUserID resolves a guardian target's account name to
// its uid (Unix) or SID (Windows) when the state row carries neither. A
// seam for tests.
var endpointHealthLookupUserID = func(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	account, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return account.Uid
}

// readEndpointHealthGuardianState reads the guardian state file in dataDir.
// A missing file is not an error (Present false); an unreadable or
// malformed one is.
func readEndpointHealthGuardianState(dataDir string, now time.Time) (endpointHealthGuardianSource, error) {
	out := endpointHealthGuardianSource{ReadAt: now}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return out, errEndpointHealthSourceUnavailable
	}
	path := filepath.Join(dataDir, endpointHealthGuardianStateFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !info.Mode().IsRegular() {
		return out, errors.New("guardian state is not a regular file")
	}
	file, err := os.Open(path) // #nosec G304 -- data_dir is the install-time runtime directory.
	if err != nil {
		return out, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, endpointHealthGuardianStateMaxBytes+1))
	if err != nil {
		return out, err
	}
	if len(body) > endpointHealthGuardianStateMaxBytes {
		return out, errors.New("guardian state is too large")
	}
	var state struct {
		UpdatedAt string `json:"updated_at"`
		Results   []struct {
			User      string `json:"user"`
			SID       string `json:"sid"`
			UID       int    `json:"uid"`
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Pending   bool   `json:"pending"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return out, errors.New("guardian state is not valid JSON")
	}
	out.Present = true
	if at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(state.UpdatedAt)); err == nil {
		out.UpdatedAt = at
	}
	out.Targets = make([]endpointHealthGuardianTarget, 0, len(state.Results))
	for _, row := range state.Results {
		target := endpointHealthGuardianTarget{
			Connector: row.Connector, OK: row.OK, Pending: row.Pending, Error: row.Error,
		}
		// Only failing and pending targets carry a user id.
		if !row.OK || row.Pending {
			switch {
			case useridentity.KindForID(row.SID) != "":
				target.UserID = row.SID
			case row.UID > 0:
				target.UserID = strconv.Itoa(row.UID)
			default:
				target.UserID = endpointHealthLookupUserID(row.User)
			}
		}
		out.Targets = append(out.Targets, target)
	}
	return out, nil
}

// endpointHealthCursor is the reporter's memory between two reports: the
// running totals the "since last report" counts are taken from and when
// pending guardian targets were first seen. The reporter owns one and
// passes it to every collection.
type endpointHealthCursor struct {
	previousReportAt time.Time

	failOpenTotal uint64
	failOpenRead  bool

	droppedGeneration uint64
	droppedTotal      uint64
	droppedRead       bool

	hooksPendingSince time.Time
}

// endpointHealthSinceLast is current minus previous for a running total; a
// total that went backwards (a new delivery generation) counts from zero.
func endpointHealthSinceLast(current, previous uint64, read bool) uint64 {
	if !read || current < previous {
		return current
	}
	return current - previous
}

// endpointHealthAVCLogOnce logs an unreadable AVC version once per process.
var endpointHealthAVCLogOnce sync.Once

// collectEndpointHealthSources reads every source of one report. Each read
// that does I/O has a timeout; a source that cannot be read is named in
// SourceErrors and never fails the collection. cursor carries the previous
// report's totals and is advanced.
func (s *Sidecar) collectEndpointHealthSources(ctx context.Context, cursor *endpointHealthCursor) endpointHealthSources {
	if ctx == nil {
		ctx = context.Background()
	}
	if cursor == nil {
		cursor = &endpointHealthCursor{}
	}
	now := time.Now().UTC()
	src := endpointHealthSources{Now: now, PreviousReportAt: cursor.previousReportAt}
	cfg := s.currentConfig()

	if s.health != nil {
		src.Health = s.health.Snapshot()
	} else {
		src.SourceErrors = append(src.SourceErrors, endpointHealthSourceGatewayHealth)
	}

	// Delivery health of the managed AI Defense destination.
	if destination, err := s.readEndpointHealthCloudDelivery(ctx); err != nil {
		src.SourceErrors = append(src.SourceErrors, endpointHealthSourceCloudDelivery)
	} else {
		src.CloudDelivery = &destination.health
		src.CloudDeliveryDroppedSinceLast = endpointHealthSinceLast(
			destination.health.Counters.Dropped, cursor.droppedTotal,
			cursor.droppedRead && cursor.droppedGeneration == destination.generation,
		)
		cursor.droppedTotal, cursor.droppedGeneration, cursor.droppedRead =
			destination.health.Counters.Dropped, destination.generation, true
	}

	// Inspection availability and fail-open decisions. Managed enterprise
	// inspection always goes through AI Defense.
	src.InspectionEnabled = cfg != nil
	s.inspectionMu.RLock()
	src.InspectionAvailable = s.inspectionAvailable
	src.InspectionDetail = s.inspectionDetail
	src.InspectionObserved = s.inspectionObserved
	s.inspectionMu.RUnlock()
	failOpen := managedAIDFailOpenAvailabilityDecisionCount()
	src.FailOpenSinceLast = endpointHealthSinceLast(failOpen, cursor.failOpenTotal, cursor.failOpenRead)
	cursor.failOpenTotal, cursor.failOpenRead = failOpen, true

	// CMID: a bounded token probe on the cached provider, and when any
	// consumer last got a token.
	src.CMIDTokenOK, src.CMIDLastSuccess = s.readEndpointHealthCMID(ctx)

	// Guardian state.
	if cfg != nil {
		guardian, err := endpointHealthRead(ctx, endpointHealthSourceTimeout,
			func(context.Context) (endpointHealthGuardianSource, error) {
				return readEndpointHealthGuardianState(cfg.DataDir, time.Now().UTC())
			})
		if err != nil {
			src.SourceErrors = append(src.SourceErrors, endpointHealthSourceGuardianState)
		} else {
			src.Guardian = guardian
		}
	} else {
		src.SourceErrors = append(src.SourceErrors, endpointHealthSourceGuardianState)
	}
	pending := false
	for _, target := range src.Guardian.Targets {
		pending = pending || target.Pending
	}
	switch {
	case !pending:
		cursor.hooksPendingSince = time.Time{}
	case cursor.hooksPendingSince.IsZero():
		cursor.hooksPendingSince = now
	}
	src.HooksPendingSince = cursor.hooksPendingSince

	// Versions. The installed product version falls back to the running
	// binary's, which the managed installer placed.
	src.ProductVersion = version.Current().BinaryVersion
	if installed, err := endpointHealthRead(ctx, endpointHealthSourceTimeout,
		func(context.Context) (string, error) { return readInstalledProductVersion() }); err == nil {
		if normalized, ok := normalizeEndpointHealthVersion(installed); ok {
			src.ProductVersion = normalized
		}
	}
	if generation := currentGeneration(); generation != nil {
		src.PolicyApplied = generation.Digest != "" || generation.BundleVersion != 0
		src.PolicyBundleVersion = endpointHealthShortDigest(generation.Digest)
		if generation.BundleVersion != 0 {
			src.PolicyBundleVersion = strconv.FormatUint(generation.BundleVersion, 10)
		}
	}
	avc, err := readAVCVersion(ctx)
	if err != nil {
		endpointHealthAVCLogOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "[health-report] host AVC version unavailable (%s)\n",
				endpointHealthErrorClass(err.Error()))
		})
	} else {
		src.AVCVersion = avc
	}
	src.OSVersion = readOSVersion()

	// Discovery.
	if discovery := s.aiDiscoverySnapshot(); discovery != nil && cfg != nil && cfg.AIDiscovery.Enabled &&
		src.Health.AIDiscovery.State != StateDisabled {
		src.DiscoveryEnabled = true
		src.DiscoveryLastFullScanAt = discovery.LastFullScanAt()
		src.DiscoveryInterval = discovery.FullScanInterval()
	}

	cursor.previousReportAt = now
	return src
}

// endpointHealthShortDigest shortens a "sha256:<hex>" effective policy
// digest to its first 16 hex digits, the policy version of a deployment
// without signed bundles.
func endpointHealthShortDigest(digest string) string {
	const prefix = "sha256:"
	digest = strings.TrimSpace(digest)
	if !strings.HasPrefix(digest, prefix) || len(digest) < len(prefix)+16 {
		return digest
	}
	return digest[:len(prefix)+16]
}

type endpointHealthCloudDeliveryRead struct {
	generation uint64
	health     observabilityruntime.DestinationHealth
}

// readEndpointHealthCloudDelivery reads the managed AI Defense destination
// from the bound v8 runtime.
func (s *Sidecar) readEndpointHealthCloudDelivery(ctx context.Context) (endpointHealthCloudDeliveryRead, error) {
	if s.health == nil {
		return endpointHealthCloudDeliveryRead{}, errEndpointHealthSourceUnavailable
	}
	s.health.mu.RLock()
	source := s.health.observabilityV8Source
	s.health.mu.RUnlock()
	if source == nil {
		return endpointHealthCloudDeliveryRead{}, errEndpointHealthSourceUnavailable
	}
	snapshot, err := endpointHealthRead(ctx, endpointHealthSourceTimeout, source.DestinationHealthSnapshot)
	if err != nil {
		return endpointHealthCloudDeliveryRead{}, err
	}
	for _, destination := range snapshot.Destinations {
		if destination.Name == config.ObservabilityV8ManagedAIDDestinationName {
			return endpointHealthCloudDeliveryRead{generation: snapshot.Generation, health: destination}, nil
		}
	}
	return endpointHealthCloudDeliveryRead{}, errEndpointHealthSourceUnavailable
}

// readEndpointHealthCMID probes the cached CMID provider for a token, with a
// timeout, and returns whether it got one and when any consumer last did.
// It never builds the provider; while a build holds the provider lock the
// probe is skipped and only the last-token time counts.
func (s *Sidecar) readEndpointHealthCMID(ctx context.Context) (bool, time.Time) {
	if !s.cmidProviderMu.TryLock() {
		return false, time.Time{}
	}
	provider := s.cmidProviderInst
	s.cmidProviderMu.Unlock()
	if provider == nil {
		return false, time.Time{}
	}
	_, err := endpointHealthRead(ctx, endpointHealthSourceTimeout, func(ctx context.Context) (struct{}, error) {
		// The token itself is discarded here.
		_, err := provider.Token(ctx)
		return struct{}{}, err
	})
	return err == nil, cloudreg.LastTokenAt(provider)
}
