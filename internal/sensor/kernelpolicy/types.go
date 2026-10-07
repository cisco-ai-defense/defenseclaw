// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package kernelpolicy builds, loads, watches and retires the fixed set of
// DefenseClaw kernel controls that the root sensor helper hands to the
// Tetragon the customer already runs.
//
// It is defensive code. The controls protect a user's SSH private keys and
// shell startup files from the descendants of an AI agent the administrator
// enrolled, and nothing else: the user's own shell is never in scope. The
// package errs toward less enforcement at every decision point. A missing
// input, a failed call, a stale approval, a pause or an operator's change in
// Tetragon all leave policies in monitor mode, and an empty anchor list is
// never emitted, because Tetragon reads an empty matchBinaries as "match
// everything" and that would widen a deny to the whole host.
//
// The package has four parts that the sensor helper wires together:
//
//   - Compile and Lint turn the enrolled users, their resolved agent
//     installs and the live agent processes into TracingPolicy YAML, and
//     refuse any shape the design forbids.
//   - Controller is the reconciler. It owns the desired state (mode, approval,
//     per-user burn-in, pause, operator overrides) and applies it with
//     add-before-delete calls that only ever touch names it recorded itself.
//   - The state files under the helper's state directory are the only
//     interface to the root CLI, and Cleanup is the only thing that runs
//     without a Controller (uninstall, rollback, downgrade).
//   - Digest names the control set an administrator approves.
//
// Nothing here talks to Tetragon directly. Sensors is the narrow seam the
// helper satisfies with the verified unix-socket client.
package kernelpolicy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	kernel "github.com/defenseclaw/defenseclaw/policies/kernel"
)

// Mode is the effective enterprise.tetragon.mode the lifecycle rendered.
type Mode string

const (
	// ModeOff never talks to Tetragon, except to retire names it recorded.
	ModeOff Mode = "off"
	// ModeConsume reads events only (and retires recorded names).
	ModeConsume Mode = "consume"
	// ModeObserve loads the observe and connect policies and the controls
	// policy in monitor mode.
	ModeObserve Mode = "observe"
	// ModeEnforce additionally lets the controls deny, once the
	// administrator's approval matches and a user finished burn-in.
	ModeEnforce Mode = "enforce"
)

// ParseMode maps the drop-in value to a Mode. The empty value is the
// default, consume.
func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ModeConsume, nil
	case "off":
		return ModeOff, nil
	case "consume":
		return ModeConsume, nil
	case "observe":
		return ModeObserve, nil
	case "enforce":
		return ModeEnforce, nil
	}
	return ModeConsume, fmt.Errorf("kernelpolicy: unknown mode %q", value)
}

// LoadsPolicies reports whether the mode may add policies to Tetragon.
func (m Mode) LoadsPolicies() bool { return m == ModeObserve || m == ModeEnforce }

// Family is a DefenseClaw policy family. The loaded name is
// defenseclaw-<family>-<render8>.
type Family string

const (
	FamilyObserve  Family = "observe"
	FamilyConnect  Family = "connect"
	FamilyControls Family = "controls"
	FamilyBurnin   Family = "controls-burnin"
)

// Families lists every family in load order.
var Families = []Family{FamilyObserve, FamilyConnect, FamilyControls, FamilyBurnin}

// PolicyMode is a loaded policy's mode. Monitor elides Override; a deny only
// happens in enforce.
type PolicyMode string

const (
	PolicyMonitor PolicyMode = "monitor"
	PolicyEnforce PolicyMode = "enforce"
)

// Limits and defaults from the design.
const (
	// DefaultBurnIn is the covered time a user needs before it is enforced.
	DefaultBurnIn = 168 * time.Hour
	// MinBurnIn and MaxBurnIn bound a non-zero burn_in.
	MinBurnIn = 24 * time.Hour
	MaxBurnIn = 2160 * time.Hour
	// DefaultPauseFor and MaxPauseFor bound the break-glass pause.
	DefaultPauseFor = 4 * time.Hour
	MaxPauseFor     = 7 * 24 * time.Hour

	// MaxPIDs is how many pids one matchPIDs selector carries (pids_limit.out).
	MaxPIDs = 64
	// MaxSelectors is Tetragon's per-hook selector budget (selector_limit.out).
	MaxSelectors = 5
	// maxValues bounds any one value list, so a very large enrollment is
	// refused rather than loaded half-understood.
	maxValues = 512
	// maxPathLen and maxBinaryLen bound a matched path (Tetragon rejects
	// binaries of 256 bytes or more).
	maxPathLen   = 1024
	maxBinaryLen = 255

	// hostNamespace is Tetragon's name for the host's pid namespace.
	hostNamespace = "host_ns"
	// eperm is the Override argError for -EPERM.
	eperm = -1
)

// Environment variable names of the helper's drop-in (rendered by the
// enterprise lifecycle, read only by defenseclaw-sensor-helper
// --managed-enterprise).
const (
	EnvMode              = "DEFENSECLAW_SENSOR_TETRAGON_MODE"
	EnvBurnIn            = "DEFENSECLAW_SENSOR_TETRAGON_BURN_IN"
	EnvEnforceAck        = "DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_ACK"
	EnvEnforceConnectors = "DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_CONNECTORS"
)

// policyNamePattern is the only shape of name the helper may ever delete,
// and only when its own state also recorded it.
var policyNamePattern = regexp.MustCompile(`^defenseclaw-(observe|connect|controls|controls-burnin)-[0-9a-f]{8}$`)

// IsDefenseClawName reports whether name has the shape of a policy this
// package loads. Matching the shape is necessary, never sufficient, to touch
// a name: the helper's own record decides.
func IsDefenseClawName(name string) bool { return policyNamePattern.MatchString(name) }

// FamilyOfName returns the family a DefenseClaw-shaped name belongs to.
func FamilyOfName(name string) (Family, bool) {
	if !IsDefenseClawName(name) {
		return "", false
	}
	trimmed := strings.TrimPrefix(name, "defenseclaw-")
	trimmed = trimmed[:len(trimmed)-len("-00000000")]
	return Family(trimmed), true
}

// Warning and reason codes. They are free-form strings in the lifecycle
// schemas; the names are the contract between the helper, the root CLI,
// doctor and the dashboards.
const (
	WarnTetragonUnavailable = "tetragon_unavailable"
	WarnUnsupportedVersion  = "tetragon_unsupported_version"
	WarnPersistentSensors   = "tetragon_persistent_sensors"
	WarnEnforceAckMissing   = "kernel_enforce_ack_missing"
	WarnEnforceAckStale     = "kernel_enforce_ack_stale"
	WarnEnforcePaused       = "kernel_enforce_paused"
	WarnEnforceInactive     = "kernel_enforce_inactive"
	WarnBurnInSkipped       = "kernel_burn_in_skipped"
	WarnOperatorOverride    = "kernel_policy_operator_override"
	WarnForeignName         = "tetragon_foreign_defenseclaw_name"
	WarnReconcileFailed     = "kernel_reconcile_failed"
	WarnRootsOverLimit      = "kernel_roots_over_limit"
	WarnGuardrailObserve    = "kernel_enforce_guardrail_observe"
	WarnPolicyLoadError     = "kernel_policy_load_error"
	WarnLSMUnavailable      = "kernel_lsm_unavailable"
	WarnPauseInvalid        = "kernel_pause_file_invalid"
	WarnConfigInvalid       = "tetragon_config_invalid"
	ReasonNoAnchors         = "kernel_enforce_inactive: no anchors"
	ReasonNoReadyUsers      = "kernel_enforce_inactive: no user finished burn-in"
	ReasonIdentityUnknown   = "tetragon_identity_unknown"
	ReasonHeuristicRoot     = "heuristic_root"
	ReasonIDEHosted         = "ide_hosted"
	ReasonNotEnrolled       = "not_enrolled"
	ReasonGuardrailObserve  = "guardrail_observe"
)

// Dirs locates the helper's state (survives reboots) and runtime (does not)
// directories.
type Dirs struct {
	State string
	Run   string
}

// Default directory names: the helper's systemd StateDirectory and
// RuntimeDirectory.
const (
	DefaultStateDir = "/var/lib/defenseclaw-sensor"
	DefaultRunDir   = "/run/defenseclaw-sensor"
)

// DefaultDirs returns the production locations.
func DefaultDirs() Dirs { return Dirs{State: DefaultStateDir, Run: DefaultRunDir} }

// Loaded is the file recording the exact names this helper loaded, one per
// line. It is the retire and cleanup source.
func (d Dirs) Loaded() string { return d.State + "/tetragon-loaded" }

// StateFile is the helper's applied-state snapshot.
func (d Dirs) StateFile() string { return d.State + "/tetragon-state.json" }

// BurnIn is the per-user burn-in record.
func (d Dirs) BurnIn() string { return d.State + "/burnin.json" }

// Pause is the durable break-glass file.
func (d Dirs) Pause() string { return d.State + "/tetragon-pause" }

// RuntimePause is the until-reboot break-glass file.
func (d Dirs) RuntimePause() string { return d.Run + "/tetragon-pause" }

// PolicyCopies is where the rendered policies are copied for an operator.
func (d Dirs) PolicyCopies() string { return d.Run + "/tetragon" }

// Lock is the reconciler lock file (see LockForCleanup).
func (d Dirs) Lock() string { return d.State + "/tetragon.lock" }

// Digest is the kernel_policy digest an administrator approves: "sha256:"
// and 12 hex. It covers the embedded control set and the Tetragon schema
// they are rendered for, and no per-host input.
func Digest() string { return kernel.Digest() }

// AckMatches reports whether ack approves this build's control set.
func AckMatches(ack string) bool { return kernel.AckMatches(ack) }

// Intent is what the drop-in asks for. Only root-owned inputs reach it.
type Intent struct {
	Mode Mode
	// BurnIn is the covered time a user needs before it is enforced: 0, or
	// MinBurnIn..MaxBurnIn.
	BurnIn time.Duration
	// EnforceAck is the kernel_policy digest the administrator approved.
	EnforceAck string
	// EnforceConnectors are the enrolled connectors whose effective
	// guardrail mode is action. Only they can be anchored for a deny.
	EnforceConnectors []string
	// Problems lists malformed drop-in values. Each one fell back to the
	// narrower default.
	Problems []string
}

// Key identifies the intent for the purpose of clearing operator overrides:
// an override lasts until the mode or the approval changes.
func (i Intent) Key() string { return string(i.Mode) + "|" + i.EnforceAck }

// Lookup is the environment read seam (envvars.Lookup in the helper).
type Lookup func(name string) (string, bool)

// IntentFromLookup reads the drop-in. It never fails: every malformed value
// falls back to the safe side and is returned as a note, so a bad drop-in
// cannot stop the helper, loosen anything or enforce anything.
//
//   - a bad mode is consume (read only);
//   - a bad burn_in is the default 168h (longer is safer);
//   - a bad enforce_ack is empty (no approval).
func IntentFromLookup(lookup Lookup) Intent {
	intent := Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn}
	if lookup == nil {
		return intent
	}
	notes := &intent.Problems
	if value, ok := lookup(EnvMode); ok {
		mode, err := ParseMode(value)
		if err != nil {
			*notes = append(*notes, WarnConfigInvalid+":"+EnvMode)
		}
		intent.Mode = mode
	}
	if value, ok := lookup(EnvBurnIn); ok && strings.TrimSpace(value) != "" {
		duration, err := time.ParseDuration(strings.TrimSpace(value))
		switch {
		case err != nil, duration < 0,
			duration != 0 && (duration < MinBurnIn || duration > MaxBurnIn):
			*notes = append(*notes, WarnConfigInvalid+":"+EnvBurnIn)
		default:
			intent.BurnIn = duration
		}
	}
	if value, ok := lookup(EnvEnforceAck); ok {
		value = strings.TrimSpace(value)
		if kernel.ValidAck(value) {
			intent.EnforceAck = value
		} else {
			*notes = append(*notes, WarnConfigInvalid+":"+EnvEnforceAck)
		}
	}
	if value, ok := lookup(EnvEnforceConnectors); ok {
		seen := map[string]bool{}
		for _, part := range strings.Split(value, ",") {
			connector := strings.ToLower(strings.TrimSpace(part))
			if connector != "" && !seen[connector] {
				seen[connector] = true
				intent.EnforceConnectors = append(intent.EnforceConnectors, connector)
			}
		}
	}
	sort.Strings(intent.EnforceConnectors)
	return intent
}
