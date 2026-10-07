// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	stateVersion = 1
	stateLimit   = 4 << 20
	// maxChanges bounds the change ring the gateway drains into
	// log.ai.runtime.kernel_policy records.
	maxChanges = 64
)

// PolicyStatus is one DefenseClaw policy as the last pass saw it.
type PolicyStatus struct {
	Name         string      `json:"name"`
	Family       Family      `json:"family"`
	DesiredMode  PolicyMode  `json:"desired_mode,omitempty"`
	ObservedMode LoadedMode  `json:"observed_mode,omitempty"`
	State        LoadedState `json:"state,omitempty"`
	Error        string      `json:"error,omitempty"`
	ChangedAt    time.Time   `json:"changed_at"`
}

// Applied is the write-ahead record of a call the helper made (or is about to
// make). Comparing it with what Tetragon reports is how the helper tells its
// own changes from an operator's.
type Applied struct {
	Family Family     `json:"family"`
	Mode   PolicyMode `json:"mode,omitempty"`
	PID    int        `json:"tetragon_pid"`
	At     time.Time  `json:"at"`
	// Pending marks a call recorded before it was made; nothing is inferred
	// from a pending record found after a restart.
	Pending bool `json:"pending,omitempty"`
}

// OverrideKind is what an operator did to a family.
type OverrideKind string

const (
	OverrideMonitor OverrideKind = "monitor"
	OverrideDeleted OverrideKind = "deleted"
)

// Override records that a human moved a family to monitor or deleted it. The
// helper never undoes it; it lasts until the intent (mode or approval)
// changes.
type Override struct {
	Kind OverrideKind `json:"kind"`
	At   time.Time    `json:"at"`
}

// TetragonStatus is what the helper knows about the agent it talks to.
type TetragonStatus struct {
	Reachable         bool      `json:"reachable"`
	Version           string    `json:"version,omitempty"`
	PID               int       `json:"pid,omitempty"`
	LSM               *bool     `json:"lsm,omitempty"`
	KeepSensorsOnExit *bool     `json:"keep_sensors_on_exit,omitempty"`
	SeenAt            time.Time `json:"seen_at,omitempty"`
	Reason            string    `json:"reason,omitempty"`
}

// UIDStatus is one enrolled user's place in the rollout.
type UIDStatus struct {
	UID        int      `json:"uid"`
	User       string   `json:"user,omitempty"`
	Connectors []string `json:"connectors,omitempty"`
	// State is enforcing, burn_in, monitor or inactive.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// AnchoredRoots is how many live roots of the user are in a pid anchor.
	AnchoredRoots int `json:"anchored_roots"`
	// CoveredSeconds and NeededSeconds are the user's burn-in progress;
	// WouldBlock counts monitor-mode hits since the last reset.
	CoveredSeconds int64 `json:"covered_seconds"`
	NeededSeconds  int64 `json:"needed_seconds"`
	WouldBlock     int   `json:"would_block"`
}

// RootsStatus summarizes the live agent processes.
type RootsStatus struct {
	Anchored  int        `json:"anchored"`
	OverLimit int        `json:"over_limit,omitempty"`
	Observed  []Observed `json:"observed_only,omitempty"`
}

// IntentStatus is the drop-in as the helper read it.
type IntentStatus struct {
	Mode              Mode     `json:"mode"`
	BurnIn            string   `json:"burn_in"`
	EnforceAck        string   `json:"enforce_ack,omitempty"`
	EnforceConnectors []string `json:"enforce_connectors,omitempty"`
	Problems          []string `json:"problems,omitempty"`
}

// Change is one state change, for log.ai.runtime.kernel_policy. The gateway
// drains the ring by Seq; the helper itself emits no telemetry.
type Change struct {
	Seq    uint64     `json:"seq"`
	At     time.Time  `json:"at"`
	Event  string     `json:"event"`
	Policy string     `json:"policy,omitempty"`
	Family Family     `json:"family,omitempty"`
	Mode   PolicyMode `json:"mode,omitempty"`
	State  string     `json:"state,omitempty"`
	UID    *int       `json:"uid,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

// Change event names (the enum of log.ai.runtime.kernel_policy).
const (
	EventLoaded            = "loaded"
	EventModeChanged       = "mode_changed"
	EventRemoved           = "removed"
	EventOperatorOverride  = "operator_override"
	EventPaused            = "paused"
	EventResumed           = "resumed"
	EventOrphaned          = "orphaned"
	EventReconcileFailed   = "reconcile_failed"
	EventAckStale          = "ack_stale"
	EventUIDReady          = "uid_ready"
	EventUIDBurnIn         = "uid_burnin"
	EventTetragonRestarted = "tetragon_restarted"
	EventFallback          = "fallback"
)

// FileState is tetragon-state.json: everything the helper applied and why.
type FileState struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	HelperPID int       `json:"helper_pid"`
	// KernelPolicy is the control-set digest of the running build.
	KernelPolicy string       `json:"kernel_policy"`
	Intent       IntentStatus `json:"intent"`
	// IntentKey is the intent the recorded overrides belong to.
	IntentKey string `json:"intent_key,omitempty"`
	// Effective is what runs: off, consume, observe, or enforce. A mode that
	// was capped (no approval, paused, no LSM) reports observe here.
	Effective string `json:"effective_mode"`
	// InSync is true when the last pass left Tetragon with the policies the
	// intent and the caps call for: every planned policy loaded, enabled and
	// in the planned mode, and nothing failed. The gateway's
	// kernel_policy_not_applied check reads it beside the digest.
	InSync    bool                `json:"in_sync"`
	Tetragon  TetragonStatus      `json:"tetragon"`
	Policies  []PolicyStatus      `json:"policies,omitempty"`
	Applied   map[string]Applied  `json:"applied,omitempty"`
	Overrides map[Family]Override `json:"overrides,omitempty"`
	UIDs      []UIDStatus         `json:"uids,omitempty"`
	Roots     RootsStatus         `json:"roots"`
	Warnings  []string            `json:"warnings,omitempty"`
	Seq       uint64              `json:"seq"`
	Changes   []Change            `json:"changes,omitempty"`
}

// State is the helper's whole published state, read by the root CLI, verify
// and the gateway. It is the shape of `enterprise linux tetragon status
// --json` and of the kernel_status reply.
type State struct {
	FileState
	BurnIn BurnInFile  `json:"burn_in"`
	Pause  *PauseState `json:"pause,omitempty"`
	// Loaded are the names the helper recorded as loaded (tetragon-loaded).
	Loaded []string `json:"loaded,omitempty"`
}

// ReadState reads the published state. Missing files are an empty state, not
// an error: a helper that has not run yet has published nothing.
func ReadState(dirs Dirs) (State, error) {
	var out State
	if err := readJSON(dirs.StateFile(), &out.FileState); err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	burn, err := readBurnIn(dirs)
	if err != nil {
		return State{}, err
	}
	out.BurnIn = burn
	if pause := ReadPause(dirs, time.Now()); pause.Active() {
		out.Pause = &pause
	}
	loaded, err := readLoaded(dirs)
	if err != nil {
		return State{}, err
	}
	out.Loaded = loaded
	return out, nil
}

func readJSON(path string, into any) error {
	data, err := safefile.ReadRegularFileBounded(path, stateLimit)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("kernelpolicy: %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safefile.Write(path, append(data, '\n'))
}

// readLoaded returns the recorded names, deduplicated and sorted. A line that
// does not have the DefenseClaw shape is ignored: the record can only ever
// name a policy this package could have loaded.
func readLoaded(dirs Dirs) ([]string, error) {
	data, err := safefile.ReadRegularFileBounded(dirs.Loaded(), stateLimit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if IsDefenseClawName(name) {
			seen[name] = true
		}
	}
	return sortedKeys(seen), scanner.Err()
}

func writeLoaded(dirs Dirs, names []string) error {
	if err := os.MkdirAll(dirs.State, 0o700); err != nil {
		return err
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	var buf bytes.Buffer
	for _, name := range sorted {
		if IsDefenseClawName(name) {
			buf.WriteString(name + "\n")
		}
	}
	return safefile.Write(dirs.Loaded(), buf.Bytes())
}

// removePolicyCopy deletes the operator's copy of a policy.
func removePolicyCopy(dirs Dirs, name string) {
	if IsDefenseClawName(name) {
		_ = os.Remove(filepath.Join(dirs.PolicyCopies(), name+".yaml"))
	}
}

// writePolicyCopy keeps a copy of the policy as loaded, for an operator to
// read next to the `# defenseclaw-derived:` header.
func writePolicyCopy(dirs Dirs, name string, data []byte) {
	if !IsDefenseClawName(name) {
		return
	}
	if err := os.MkdirAll(dirs.PolicyCopies(), 0o700); err == nil {
		_ = safefile.Write(filepath.Join(dirs.PolicyCopies(), name+".yaml"), data)
	}
}
