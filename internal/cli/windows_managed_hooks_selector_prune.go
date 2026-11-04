// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsManagedHooksLifecycleSelectorConnectors is the fixed order in which
// lifecycle actions visit the three machine-wide runtime selectors.
var windowsManagedHooksLifecycleSelectorConnectors = [...]string{
	"claudecode",
	"codex",
	"cursor",
}

const (
	windowsManagedHooksSelectorPrunePruned        = "pruned"
	windowsManagedHooksSelectorPruneNonePresent   = "none_present"
	windowsManagedHooksSelectorPruneRecordedState = "skipped_recorded_state"
	windowsManagedHooksSelectorPruneMachinePolicy = "skipped_machine_policy"
)

// windowsManagedHooksPrunedSelector is the secretless evidence for one removed
// selector. Selector entries never hold a token; only the SIDs are reported.
type windowsManagedHooksPrunedSelector struct {
	Connector  string   `json:"connector"`
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	TargetSIDs []string `json:"target_sids"`
}

type windowsManagedHooksSelectorPruneResult struct {
	Phase           string
	PrunedSelectors []windowsManagedHooksPrunedSelector
	SelectorPaths   []string
	SkipConnector   string
	SkipReason      string
}

// windowsManagedHooksSelectorPrune removes machine-wide runtime selectors left
// behind by an earlier purge that did not delete them. A selector is removed
// only when nothing can vouch for or consult it: no Guardian activation,
// authorization or state, no lifecycle journal or quarantine, and no connector
// machine policy that still enrolls a user. Every dependency is injected so
// the decision is testable off Windows.
type windowsManagedHooksSelectorPrune struct {
	// transactionID is the authenticated pending lifecycle transaction. The
	// action refuses to run without one, like every other lifecycle action.
	transactionID  string
	journalPath    string
	quarantinePath string

	guardianRecords func() (activation, authorization, state bool, err error)
	// machinePolicyEnrollment returns the first connector whose machine
	// policy still enrolls a user, or "" when none does.
	machinePolicyEnrollment func() (connectorName, reason string, err error)
	selectorPaths           func() (map[string]string, error)
	pathExists              func(string) (bool, error)
	capture                 func(string) (enterprisehooks.WindowsManagedRuntimeSelectorSnapshot, error)
	restore                 func(enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions) error
	verifyAbsent            func(path, connectorName string) error
}

func (prune windowsManagedHooksSelectorPrune) run() (windowsManagedHooksSelectorPruneResult, error) {
	var result windowsManagedHooksSelectorPruneResult
	if prune.transactionID == "" {
		return result, errors.New(
			"managed-hook lifecycle snapshot requires an authenticated pending lifecycle transaction",
		)
	}
	// Resolve the selector paths first so a failure later in the action still
	// tells the installer exactly which files its fallback may touch.
	paths, err := prune.selectorPaths()
	if err != nil {
		return result, err
	}
	for _, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		path := paths[connectorName]
		if path == "" {
			return result, fmt.Errorf("%s managed runtime selector path is unresolved", connectorName)
		}
		result.SelectorPaths = append(result.SelectorPaths, path)
	}

	// Any Guardian record means a deployment may still own these selectors.
	// A record that cannot be read is not evidence of absence.
	activation, authorization, state, err := prune.guardianRecords()
	if err != nil {
		return result, err
	}
	if activation || authorization || state {
		result.Phase = windowsManagedHooksSelectorPruneRecordedState
		return result, nil
	}
	for _, recoveryPath := range []string{prune.journalPath, prune.quarantinePath} {
		if recoveryPath == "" {
			continue
		}
		exists, err := prune.pathExists(recoveryPath)
		if err != nil {
			return result, fmt.Errorf("inspect managed-hook lifecycle recovery record: %w", err)
		}
		if exists {
			result.Phase = windowsManagedHooksSelectorPruneRecordedState
			return result, nil
		}
	}
	// With machine policy still enrolling someone, a hook can resolve a
	// selector entry, so the host is not purged. Keep the fail-closed path.
	enrolled, reason, err := prune.machinePolicyEnrollment()
	if err != nil {
		return result, err
	}
	if enrolled != "" {
		result.Phase = windowsManagedHooksSelectorPruneMachinePolicy
		result.SkipConnector = enrolled
		result.SkipReason = reason
		return result, nil
	}

	for index, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		path := result.SelectorPaths[index]
		snapshot, err := prune.capture(connectorName)
		if err != nil {
			return result, fmt.Errorf(
				"capture %s managed runtime selector %s: %w",
				connectorName,
				path,
				err,
			)
		}
		if !snapshot.Existed {
			continue
		}
		sids, err := windowsManagedHooksSelectorTargetSIDs(snapshot.Selector)
		if err != nil {
			return result, fmt.Errorf("%s managed runtime selector %s: %w", connectorName, path, err)
		}
		// Restoring to absent removes the file under the selector lock, and
		// only while its bytes still match what was captured. A concurrent
		// writer means the selector is not orphaned; never retry over it.
		if err := prune.restore(enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions{
			Snapshot: enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
				SchemaVersion: 1,
				Connector:     connectorName,
				Existed:       false,
			},
			ExpectedCurrent: snapshot.CAS,
		}); err != nil {
			return result, fmt.Errorf(
				"remove orphaned %s managed runtime selector %s: %w",
				connectorName,
				path,
				err,
			)
		}
		result.PrunedSelectors = append(result.PrunedSelectors, windowsManagedHooksPrunedSelector{
			Connector:  connectorName,
			Path:       path,
			SHA256:     snapshot.SelectorSHA256,
			TargetSIDs: sids,
		})
		managed.EmitResilienceEvent(managed.MarkerRecover, map[string]string{
			"connector": connectorName,
			"path":      path,
			"sha256":    snapshot.SelectorSHA256,
			"targets":   strings.Join(sids, ","),
			"reason":    "orphaned runtime selector with no Guardian activation, authorization or state",
		})
	}
	for index, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		if err := prune.verifyAbsent(result.SelectorPaths[index], connectorName); err != nil {
			return result, fmt.Errorf("verify %s managed runtime selector removal: %w", connectorName, err)
		}
	}
	if len(result.PrunedSelectors) == 0 {
		result.Phase = windowsManagedHooksSelectorPruneNonePresent
	} else {
		result.Phase = windowsManagedHooksSelectorPrunePruned
	}
	return result, nil
}

// windowsManagedHooksSelectorTargetSIDs reads only the SID column of an
// already authenticated selector. Selector entries carry paths, generation
// IDs and bundle digests, never bundle bytes or tokens.
func windowsManagedHooksSelectorTargetSIDs(selector []byte) ([]string, error) {
	var decoded struct {
		Targets []struct {
			SID string `json:"sid"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(selector, &decoded); err != nil {
		return nil, fmt.Errorf("decode selector targets: %w", err)
	}
	sids := make([]string, 0, len(decoded.Targets))
	for _, target := range decoded.Targets {
		if target.SID == "" {
			return nil, errors.New("selector target has no SID")
		}
		sids = append(sids, target.SID)
	}
	sort.Strings(sids)
	return sids, nil
}
