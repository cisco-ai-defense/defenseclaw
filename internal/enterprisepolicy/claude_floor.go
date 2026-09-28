// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Claude Code refuses to start when its version is below the managed
// requiredMinimumVersion. The check runs at each new session start (running
// sessions continue), an invalid value is ignored, and builds that predate
// the setting ignore it: Claude Code reads it only from 2.1.163
// (claudeFloorSettingVersion). The standalone profile sets it to the lowest
// Claude Code version with a verified DefenseClaw hook contract; while that
// is below 2.1.163 the floor stops no build (residual R15, issue #920).
//
// The floor lives in a drop-in of its own that holds nothing else, so the
// hook drop-in (90-defenseclaw.json, and the Windows lifecycle's rendering of
// it) never changes. DefenseClaw writes it only while no administrator source
// (managed-settings.json, another drop-in, HKLM Settings, the managed
// preferences plist) sets the key, and withdraws it at the next reconcile
// once one does: managed-settings.json merges before every drop-in, so
// leaving the floor in place would override an administrator value there.
// An administrator value that is not a version does not count when it merges
// before the drop-in: Claude Code ignores it, so the drop-in stays and its
// later value applies. Administrator drop-ins whose names sort after
// 00-defenseclaw-version-floor.json override it anyway.
//
// A higher-precedence source (HKLM Settings, the managed preferences plist)
// replaces the files for every Claude Code build older than 2.1.242, which
// honors managedSourcesBehavior: merge, and every build the floor is meant to
// stop is older than that. While such a source is in force without the key,
// the floor in the files does not apply; verify says so.
//
// A file under the drop-in name is DefenseClaw's only while its ownership
// record names it and the file's SHA-256 is the recorded postimage, or while
// the record names it and the file is DefenseClaw's rendering of the current
// floor (a replacement whose record save was interrupted). Any other file
// there, including the `version-floor` export an administrator deployed (the
// same bytes DefenseClaw writes) without a record of DefenseClaw's, is an
// administrator source: DefenseClaw reads it and never rewrites, removes or
// claims it, so it cannot place its own floor there either. The first write
// saves the record before the drop-in, so a crash between the two steps
// never leaves DefenseClaw's floor unrecorded.
const ClaudeVersionFloorDropInName = "00-defenseclaw-version-floor.json"

const (
	claudeVersionFloorKey = "requiredMinimumVersion"
	// claudeFloorSettingVersion is the first Claude Code release that reads
	// requiredMinimumVersion; every older build ignores it.
	claudeFloorSettingVersion = "2.1.163"
	// claudeVersionFloorRecord names the floor drop-in's ownership record.
	claudeVersionFloorRecord = "claudecode-version-floor"
)

// Who sets Claude Code's requiredMinimumVersion.
const (
	VersionFloorOwnerDefenseClaw   = "defenseclaw"
	VersionFloorOwnerAdministrator = "administrator"
	VersionFloorOwnerNone          = "none"
)

// claudeVersionPattern is a major.minor.patch version, optionally with a
// pre-release or build suffix.
var claudeVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)

// VersionFloorState is Claude Code's requiredMinimumVersion as the
// claudecode machine policy report shows it.
type VersionFloorState struct {
	// Mode is enterprise.machine_policy.connectors.claudecode.version_floor.
	Mode string `json:"mode"`
	// Floor is the lowest Claude Code version with a verified hook contract.
	Floor string `json:"floor"`
	// Path is DefenseClaw's floor drop-in.
	Path string `json:"path"`
	// Owner says who sets requiredMinimumVersion (defenseclaw,
	// administrator or none).
	Owner string `json:"owner"`
	// Value and Source are the effective value and where it is set.
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
	// BelowFloor marks an administrator value below Floor; Invalid one that
	// is not a version, which Claude Code ignores.
	BelowFloor bool `json:"below_floor,omitempty"`
	Invalid    bool `json:"invalid,omitempty"`
	// IgnoredBy names a higher-precedence source (HKLM Settings, the
	// managed preferences plist) that does not set requiredMinimumVersion.
	// The Claude Code builds the floor is meant to stop read only that
	// source, so a value in the managed settings files does not reach them.
	IgnoredBy string `json:"ignored_by,omitempty"`
	// Overridden is an administrator value DefenseClaw's drop-in replaces:
	// one that is not a version, in a file that merges before the drop-in.
	Overridden       string `json:"overridden,omitempty"`
	OverriddenSource string `json:"overridden_source,omitempty"`
	// Missing marks DefenseClaw's drop-in as wanted but absent: the next
	// publish writes it.
	Missing bool `json:"missing,omitempty"`
}

// Summary is the one-line form `enterprise policy show` prints.
func (s VersionFloorState) Summary() string {
	ignored := ""
	if s.IgnoredBy != "" {
		ignored = "; not applied: " + s.IgnoredBy + " outranks the managed settings files"
	}
	switch s.Owner {
	case VersionFloorOwnerDefenseClaw:
		note := ""
		if s.Overridden != "" {
			note = fmt.Sprintf("; replaces %s from %s", s.Overridden, s.OverriddenSource)
			if claudeVersionPattern.MatchString(strings.TrimSpace(s.Overridden)) {
				note += " until DefenseClaw withdraws its drop-in"
			} else {
				note += ", which is not a version"
			}
		}
		return fmt.Sprintf("requiredMinimumVersion %s set by DefenseClaw (%s%s%s), version_floor=%s", s.Value, s.Source, note, ignored, s.Mode)
	case VersionFloorOwnerAdministrator:
		note := ""
		switch {
		case s.Invalid:
			note = "; not a version, so no floor applies"
		case s.BelowFloor:
			note = "; below DefenseClaw's floor " + s.Floor
		}
		return fmt.Sprintf("requiredMinimumVersion %s set by the administrator (%s%s%s), version_floor=%s", s.Value, s.Source, note, ignored, s.Mode)
	default:
		return fmt.Sprintf("requiredMinimumVersion not set (DefenseClaw's floor is %s), version_floor=%s", dashIfBlank(s.Floor), s.Mode)
	}
}

// claudeFloorReach says which Claude Code builds a requiredMinimumVersion of
// value stops.
func claudeFloorReach(value string) string {
	if compareVersions(value, claudeFloorSettingVersion) <= 0 {
		return fmt.Sprintf("Claude Code reads the setting only from %s, so this value stops no build: every build below %s predates it", claudeFloorSettingVersion, value)
	}
	return fmt.Sprintf("Claude Code builds from %s and below %s refuse to start from their next session; builds before %s predate the setting and ignore it", claudeFloorSettingVersion, value, claudeFloorSettingVersion)
}

func dashIfBlank(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// ClaudeVersionFloor is the lowest Claude Code version DefenseClaw has a
// verified hook contract for: the requiredMinimumVersion it sets. Empty when
// no contract has a lower bound.
func ClaudeVersionFloor() string {
	floor := ""
	for _, contract := range connector.KnownHookContracts(claudeConnector) {
		minimum := connector.NormalizeAgentVersion(claudeConnector, contract.MinAgentVersion)
		if minimum == "" {
			continue
		}
		if floor == "" || compareVersions(minimum, floor) < 0 {
			floor = minimum
		}
	}
	return floor
}

func (o Options) claudeVersionFloorMode() string {
	if mode := strings.ToLower(strings.TrimSpace(o.ClaudeVersionFloor)); mode != "" {
		return mode
	}
	return config.ClaudeVersionFloorEnforce
}

// ClaudeVersionFloorPath is DefenseClaw's Claude Code version floor drop-in.
func ClaudeVersionFloorPath(opts Options) (string, error) {
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		return "", err
	}
	return joinFor(opts, joinFor(opts, dir, "managed-settings.d"), ClaudeVersionFloorDropInName), nil
}

func renderClaudeVersionFloor(floor string) ([]byte, error) {
	doc := newObject()
	doc.set(claudeVersionFloorKey, floor)
	return encodeOrdered(doc)
}

// claudeVersionFloorStrip never claims content: the floor drop-in is
// DefenseClaw's only as the exact bytes its record holds, which
// restoreOrStrip checks by hash. A file under the drop-in name that is not
// what DefenseClaw last wrote is left byte for byte, whatever it contains.
func claudeVersionFloorStrip() stripFunc {
	return wholeFileStrip(func([]byte) bool { return false })
}

// claudeFloorSetting is one administrator source that sets the key.
type claudeFloorSetting struct {
	source string
	value  any
	higher bool
}

// claudeFloorPlan is what DefenseClaw finds for the floor on disk.
type claudeFloorPlan struct {
	mode    string
	floor   string
	path    string
	current []byte
	exists  bool
	record  *ownershipRecord
	// owned: the drop-in at path is the one DefenseClaw last wrote (its
	// ownership record names path and the file's hash is the recorded
	// postimage). A file at path that is not owned is an administrator
	// source that DefenseClaw never edits (occupied).
	owned bool
	// admin is the effective administrator setting; nil when none sets it.
	admin *claudeFloorSetting
	// adminInvalid: admin's value is not a major.minor.patch version, which
	// Claude Code ignores. adminOutranks: DefenseClaw's drop-in cannot
	// replace admin's value: admin merges after the drop-in (a
	// higher-precedence source, or a drop-in whose name sorts after it), or
	// it is the administrator's own file under the drop-in name.
	adminInvalid  bool
	adminOutranks bool
	// ignoredBy names the first higher-precedence source when none of them
	// sets the key. Claude Code honors managedSourcesBehavior: merge only
	// from 2.1.242, and every build the floor is meant to stop is older:
	// those builds read only the higher-precedence source, so a floor in
	// the managed settings files never reaches them.
	ignoredBy string
}

// effectiveAdmin reports whether the administrator's value is the one
// Claude Code applies. An invalid value that merges before DefenseClaw's
// drop-in is not: Claude Code takes the drop-in's later, valid value.
func (p claudeFloorPlan) effectiveAdmin() bool {
	return p.admin != nil && !(p.adminInvalid && !p.adminOutranks)
}

// occupied reports whether the drop-in name holds a file DefenseClaw did not
// write (or that changed since): an administrator source that DefenseClaw
// never rewrites or removes, so it cannot place its floor there.
func (p claudeFloorPlan) occupied() bool {
	return p.exists && !p.owned
}

func planClaudeVersionFloor(opts Options, sources []claudeSource, higher []higherClaudeSource) (claudeFloorPlan, error) {
	plan := claudeFloorPlan{mode: opts.claudeVersionFloorMode(), floor: ClaudeVersionFloor()}
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return plan, err
	}
	plan.path = path
	if plan.current, plan.exists, err = readPolicyFile(opts, path); err != nil {
		return plan, err
	}
	if plan.record, err = loadRecord(opts, claudeVersionFloorRecord); err != nil {
		return plan, err
	}
	plan.owned = plan.exists && plan.record != nil && plan.record.Path == path &&
		sha256Hex(plan.current) == plan.record.PostimageSHA256 ||
		claudeFloorAdoptable(plan.record, path, plan.current, plan.exists)
	for _, source := range sources {
		if plan.owned && source.name == path {
			continue
		}
		if value, ok := source.doc.get(claudeVersionFloorKey); ok && value != nil {
			plan.admin = &claudeFloorSetting{source: source.name, value: value}
		}
	}
	anyHigherSetsKey := false
	for _, source := range higher {
		if plan.ignoredBy == "" {
			plan.ignoredBy = source.name
		}
		if value, ok := source.doc.get(claudeVersionFloorKey); ok && value != nil {
			anyHigherSetsKey = true
			if plan.admin == nil || !plan.admin.higher {
				plan.admin = &claudeFloorSetting{source: source.name, value: value, higher: true}
			}
		}
	}
	if anyHigherSetsKey {
		plan.ignoredBy = ""
	}
	if plan.admin != nil {
		version, _ := plan.admin.value.(string)
		plan.adminInvalid = !claudeVersionPattern.MatchString(strings.TrimSpace(version))
		plan.adminOutranks = plan.admin.higher || plan.admin.source == path || claudeDropInSortsAfterFloor(opts, plan.admin.source)
	}
	return plan, nil
}

// claudeFloorAdoptable reports a drop-in that DefenseClaw's record names and
// that holds DefenseClaw's rendering of the current floor, while the record
// holds another postimage: DefenseClaw replaced the drop-in (a release that
// raised the floor) and was stopped before it saved the record. The drop-in
// is DefenseClaw's. Any other change to it makes it the administrator's.
func claudeFloorAdoptable(record *ownershipRecord, path string, current []byte, exists bool) bool {
	if !exists || record == nil || record.Path != path || sha256Hex(current) == record.PostimageSHA256 {
		return false
	}
	floor := ClaudeVersionFloor()
	if floor == "" {
		return false
	}
	rendered, err := renderClaudeVersionFloor(floor)
	return err == nil && bytes.Equal(current, rendered)
}

// adoptClaudeVersionFloor records an adoptable drop-in as DefenseClaw's
// again, keeping the rest of its record, so publishing, withdrawing and
// removing it treat it as DefenseClaw's.
func adoptClaudeVersionFloor(opts Options, path string, state *State) error {
	record, err := loadRecord(opts, claudeVersionFloorRecord)
	if err != nil || record == nil {
		return err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil || !claudeFloorAdoptable(record, path, current, exists) {
		return err
	}
	record.PostimageSHA256 = sha256Hex(current)
	if err := saveRecord(opts, record); err != nil {
		return err
	}
	state.detail("Claude Code version floor: %s holds DefenseClaw's floor, but the ownership record was not saved when it was written; recorded it again", path)
	return nil
}

// claudeDropInSortsAfterFloor reports whether source is a managed-settings.d
// drop-in that Claude Code merges after DefenseClaw's floor drop-in (drop-ins
// merge in name order, the same order readClaudeFileSources reads them).
// The base managed-settings.json merges before every drop-in.
func claudeDropInSortsAfterFloor(opts Options, source string) bool {
	dir, err := ClaudeManagedDir(opts)
	if err != nil || source == joinFor(opts, dir, "managed-settings.json") {
		return false
	}
	name := source[strings.LastIndexAny(source, `/\`)+1:]
	return name > ClaudeVersionFloorDropInName
}

// wanted reports whether DefenseClaw's floor drop-in should be in place:
// under enforce and merge, while no administrator value applies and no
// administrator file holds the drop-in name. An administrator value that is
// not a version and merges before the drop-in does not count: Claude Code
// ignores it, and the drop-in's later value replaces it.
func (p claudeFloorPlan) wanted(policy config.ResolvedConnectorPolicy) bool {
	return p.mode == config.ClaudeVersionFloorEnforce && p.floor != "" && !p.effectiveAdmin() && !p.occupied() &&
		policy.Ownership == config.MachinePolicyOwnershipMerge
}

// applyClaudeVersionFloor writes DefenseClaw's floor drop-in when the plan
// wants it and withdraws it otherwise (verify_only never writes or removes).
// It runs on every reconcile, so an administrator who sets the key gets the
// drop-in withdrawn at the next cycle, and one who removes theirs gets the
// floor back.
func applyClaudeVersionFloor(opts Options, policy config.ResolvedConnectorPolicy, state *State) error {
	sources, err := readClaudeFileSources(opts)
	if err != nil {
		return err
	}
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return err
	}
	if err := adoptClaudeVersionFloor(opts, path, state); err != nil {
		return err
	}
	// An unreadable higher-precedence source is reported by the inspection;
	// here it can only lead to a floor that source overrides anyway.
	higher, _ := claudeHigherSources(opts)
	plan, err := planClaudeVersionFloor(opts, sources, higher)
	if err != nil {
		return err
	}
	if plan.wanted(policy) {
		rendered, err := renderClaudeVersionFloor(plan.floor)
		if err != nil {
			return err
		}
		if !plan.exists && (plan.record == nil || plan.record.Path != plan.path) {
			// The first write records the drop-in before writing it: a crash
			// between the two steps must not leave DefenseClaw's floor looking
			// like an administrator's file.
			if err := saveRecord(opts, &ownershipRecord{Connector: claudeVersionFloorRecord, Path: plan.path, PostimageSHA256: sha256Hex(rendered)}); err != nil {
				return err
			}
		}
		changed, err := publishWithRecord(opts, claudeVersionFloorRecord, plan.path, plan.current, plan.exists, rendered,
			plan.owned && bytes.Equal(plan.current, rendered), claudeVersionFloorStrip(), state)
		state.Changed = state.Changed || changed
		return err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly {
		return nil
	}
	return withdrawClaudeVersionFloor(opts, plan, state)
}

// withdrawClaudeVersionFloor removes DefenseClaw's floor drop-in when the
// file is what DefenseClaw last wrote, and drops the record of one that
// changed since. Without a record there is nothing of DefenseClaw's to
// withdraw: a file under the drop-in name is the administrator's and stays.
func withdrawClaudeVersionFloor(opts Options, plan claudeFloorPlan, state *State) error {
	if plan.record == nil {
		return nil
	}
	return restoreOrStrip(opts, claudeVersionFloorRecord, plan.path, claudeVersionFloorStrip(), true, state)
}

// removeClaudeVersionFloor removes the floor drop-in DefenseClaw recorded
// writing (uninstall, retire), while the file is still what DefenseClaw
// wrote. Without a record, or once the file changed, it is the
// administrator's (for example the `version-floor` export they deployed) and
// stays.
func removeClaudeVersionFloor(opts Options, state *State) error {
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return err
	}
	if err := adoptClaudeVersionFloor(opts, path, state); err != nil {
		return err
	}
	return restoreOrStrip(opts, claudeVersionFloorRecord, path, claudeVersionFloorStrip(), true, state)
}

// ClaudeVersionFloorRecorded reports whether DefenseClaw still records
// owning a Claude Code version floor drop-in; an uninstall must end with
// false.
func ClaudeVersionFloorRecorded(opts Options) (bool, error) {
	return recordExists(opts, claudeVersionFloorRecord)
}

func recordExists(opts Options, name string) (bool, error) {
	path, err := recordPath(opts, name)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

// claudeVersionFloorPresent reports whether DefenseClaw records a floor
// drop-in, so a pass with nothing to write or remove takes no lock and
// creates no directory. An unrecorded file under the drop-in name is the
// administrator's and never needs the lock.
func claudeVersionFloorPresent(opts Options) (bool, error) {
	return recordExists(opts, claudeVersionFloorRecord)
}

// claudeFloorTransaction runs fn with the managed-settings.d directory under
// the lock of the lifecycle that owns Claude Code's managed settings.
type claudeFloorTransaction func(fn func(policyDir string) error) error

// reconcileClaudeVersionFloorFor is the version floor pass of a platform
// whose lifecycle, not this package, owns Claude Code's managed settings
// (Windows). It applies the floor while claudecode is published through
// machine policy and removes DefenseClaw's drop-in otherwise, inside
// transaction, never touching the hook drop-in.
func reconcileClaudeVersionFloorFor(opts Options, connectors []string, transaction claudeFloorTransaction, state *State) error {
	policy := opts.PolicyFor(claudeConnector)
	active := false
	for _, name := range MachinePolicyConnectors(opts, connectors) {
		active = active || name == claudeConnector
	}
	write := active && policy.Ownership == config.MachinePolicyOwnershipMerge &&
		opts.claudeVersionFloorMode() == config.ClaudeVersionFloorEnforce
	if !write {
		present, err := claudeVersionFloorPresent(opts)
		if err != nil || !present {
			return err
		}
	}
	return transaction(func(policyDir string) error {
		if err := requireClaudeFloorDir(opts, policyDir); err != nil {
			return err
		}
		if !active {
			return removeClaudeVersionFloor(opts, state)
		}
		return applyClaudeVersionFloor(opts, policy, state)
	})
}

// requireClaudeFloorDir refuses a transaction whose lock guards a different
// directory than the one the floor is written to.
func requireClaudeFloorDir(opts Options, policyDir string) error {
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return err
	}
	want := dirFor(opts, path)
	got := strings.TrimRight(policyDir, `\/`)
	same := got == want
	if opts.goos() == "windows" {
		same = strings.EqualFold(filepath.Clean(got), filepath.Clean(want))
	}
	if !same {
		return fmt.Errorf("Claude Code managed policy lock guards %s, not %s", policyDir, want)
	}
	return nil
}

// removeClaudeVersionFloorWith removes DefenseClaw's floor drop-in inside
// transaction (the Windows uninstall).
func removeClaudeVersionFloorWith(opts Options, transaction claudeFloorTransaction, state *State) error {
	present, err := claudeVersionFloorPresent(opts)
	if err != nil || !present {
		return err
	}
	return transaction(func(policyDir string) error {
		if err := requireClaudeFloorDir(opts, policyDir); err != nil {
			return err
		}
		return removeClaudeVersionFloor(opts, state)
	})
}

// inspectClaudeVersionFloor reports requiredMinimumVersion and who sets it.
// Under version_floor: enforce with ownership: merge, a state in which no
// floor reaches the builds it is meant to stop is a conflict: DefenseClaw's
// drop-in missing, an administrator value that is not a version and that
// DefenseClaw's drop-in cannot replace, or a higher-precedence source without
// the key (unless higher_precedence_sources: warn). An administrator version,
// even one below the floor, always wins and is reported.
func inspectClaudeVersionFloor(opts Options, policy config.ResolvedConnectorPolicy, sources []claudeSource, higher []higherClaudeSource, state *State) error {
	plan, err := planClaudeVersionFloor(opts, sources, higher)
	if err != nil {
		return err
	}
	floor := &VersionFloorState{Mode: plan.mode, Floor: plan.floor, Path: plan.path, Owner: VersionFloorOwnerNone}
	state.VersionFloor = floor
	if plan.floor == "" {
		state.detail("Claude Code version floor: no verified hook contract has a lower bound, so DefenseClaw sets no requiredMinimumVersion")
		return nil
	}
	promised := plan.mode == config.ClaudeVersionFloorEnforce && policy.Ownership == config.MachinePolicyOwnershipMerge
	switch {
	case plan.effectiveAdmin() && plan.owned && !plan.adminOutranks:
		// An administrator version in a file that merges before DefenseClaw's
		// drop-in (set after DefenseClaw wrote it): the drop-in's later value
		// is the one Claude Code applies until DefenseClaw withdraws it.
		floor.Owner = VersionFloorOwnerDefenseClaw
		floor.Source = plan.path
		floor.Value = claudeVersionFloorFileValue(plan.current)
		floor.Overridden = claudeFloorValueText(plan.admin.value)
		floor.OverriddenSource = plan.admin.source
		message := fmt.Sprintf("Claude Code version floor: %s sets requiredMinimumVersion %s, but DefenseClaw's %s merges after it and replaces it with %s, which is the value Claude Code applies", plan.admin.source, floor.Overridden, plan.path, floor.Value)
		if policy.Ownership == config.MachinePolicyOwnershipMerge {
			// Drift: the lifecycle re-applies, which withdraws the drop-in.
			state.Drift = true
			state.conflict("%s; the next lifecycle run that applies changes (ensure, repair or reconcile) removes DefenseClaw's drop-in so the administrator's value applies", message)
		} else {
			state.detail("%s; with ownership: %s DefenseClaw does not remove it (uninstall does)", message, policy.Ownership)
		}
	case plan.effectiveAdmin():
		floor.Owner = VersionFloorOwnerAdministrator
		floor.Source = plan.admin.source
		floor.Value = claudeFloorValueText(plan.admin.value)
		version, _ := plan.admin.value.(string)
		version = strings.TrimSpace(version)
		switch {
		case plan.adminInvalid:
			floor.Invalid = true
			message := fmt.Sprintf("Claude Code version floor: %s sets requiredMinimumVersion to %s, which is not a major.minor.patch version, and it merges after DefenseClaw's %s; Claude Code ignores an invalid value, so builds below %s can start; set a version such as %q there or remove the key", plan.admin.source, floor.Value, plan.path, plan.floor, plan.floor)
			if plan.admin.source == plan.path {
				message = fmt.Sprintf("Claude Code version floor: %s, a file DefenseClaw did not write under its drop-in name, sets requiredMinimumVersion to %s, which is not a major.minor.patch version; DefenseClaw never edits that file and Claude Code ignores an invalid value, so builds below %s can start; set a version such as %q there, or remove the file so DefenseClaw can write its floor", plan.path, floor.Value, plan.floor, plan.floor)
			}
			if promised {
				state.conflict("%s", message)
			} else {
				state.detail("%s", message)
			}
		case compareVersions(version, plan.floor) < 0:
			floor.BelowFloor = true
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion %s, below %s, the lowest Claude Code version with a verified DefenseClaw hook contract; builds from %s up to %s start without one", plan.admin.source, version, plan.floor, version, plan.floor)
		default:
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion %s; DefenseClaw keeps the administrator's value and writes no floor of its own", plan.admin.source, version)
		}
		if plan.owned && policy.Ownership == config.MachinePolicyOwnershipMerge {
			state.detail("Claude Code version floor: DefenseClaw's %s is still present; the next reconcile removes it", plan.path)
		}
	case plan.owned:
		floor.Owner = VersionFloorOwnerDefenseClaw
		floor.Source = plan.path
		floor.Value = claudeVersionFloorFileValue(plan.current)
		state.detail("Claude Code version floor: DefenseClaw's %s sets requiredMinimumVersion %s; %s", plan.path, floor.Value, claudeFloorReach(floor.Value))
		if plan.admin != nil {
			floor.Overridden = claudeFloorValueText(plan.admin.value)
			floor.OverriddenSource = plan.admin.source
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion to %s, which is not a major.minor.patch version; Claude Code ignores it and applies DefenseClaw's value, which merges later", plan.admin.source, floor.Overridden)
		}
		switch {
		case plan.wanted(policy) && floor.Value != plan.floor:
			state.detail("Claude Code version floor: the next reconcile raises it to %s", plan.floor)
		case !plan.wanted(policy) && policy.Ownership == config.MachinePolicyOwnershipMerge:
			state.detail("Claude Code version floor: the next reconcile removes it (version_floor: %s)", plan.mode)
		}
	default:
		unset := "no managed settings source sets requiredMinimumVersion"
		if plan.admin != nil {
			unset = fmt.Sprintf("%s sets requiredMinimumVersion to %s, which is not a major.minor.patch version and which Claude Code ignores", plan.admin.source, claudeFloorValueText(plan.admin.value))
		}
		switch {
		case promised && plan.occupied():
			state.conflict("Claude Code version floor: %s, and %s holds a file DefenseClaw did not write, which it never edits or replaces, so Claude Code builds below %s can start; add \"requiredMinimumVersion\": %q to that file, or move its settings to another drop-in and remove it so DefenseClaw can write its floor", unset, plan.path, plan.floor, plan.floor)
		case promised:
			floor.Missing = true
			restore := "the next lifecycle run that applies changes (ensure, repair or reconcile) writes it"
			if opts.goos() == "windows" {
				restore = "the guardian's next cycle writes it"
			}
			state.conflict("Claude Code version floor: %s and DefenseClaw's %s is missing, so Claude Code builds below %s can start; %s", unset, plan.path, plan.floor, restore)
		case plan.mode == config.ClaudeVersionFloorEnforce:
			state.detail("Claude Code version floor: %s; deploy the output of `defenseclaw-gateway enterprise policy export --connector claudecode --format version-floor` through your policy tool, or set the key yourself (Claude Code reads it from %s)", unset, claudeFloorSettingVersion)
		case plan.mode == config.ClaudeVersionFloorReport:
			state.detail("Claude Code version floor: %s, so Claude Code builds below %s can start (version_floor: report)", unset, plan.floor)
		default:
			state.detail("Claude Code version floor: version_floor: off; DefenseClaw does not manage requiredMinimumVersion")
		}
	}
	if plan.ignoredBy != "" && (floor.Owner != VersionFloorOwnerNone || plan.mode != config.ClaudeVersionFloorOff) {
		floor.IgnoredBy = plan.ignoredBy
		message := fmt.Sprintf("Claude Code version floor: %s outranks the managed settings files and does not set requiredMinimumVersion; Claude Code builds below %s predate managedSourcesBehavior: merge (%s), read only that source and ignore requiredMinimumVersion in the files, so no floor stops them; add \"requiredMinimumVersion\": %q to %s (DefenseClaw's claude-hklm-json, reg, plist and intune-settings-catalog exports include it)", plan.ignoredBy, plan.floor, claudeMergeMinimumVersion, plan.floor, plan.ignoredBy)
		if promised && policy.HigherPrecedenceSources != config.HigherPrecedenceWarn {
			state.conflict("%s", message)
		} else {
			state.detail("%s", message)
		}
	}
	return nil
}

func claudeVersionFloorFileValue(data []byte) string {
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return ""
	}
	value, _ := doc.get(claudeVersionFloorKey)
	return claudeFloorValueText(value)
}

// claudeFloorValueText renders a decoded JSON value for a report.
func claudeFloorValueText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return string(canonicalJSON(value))
}

// exportClaudeVersionFloor renders DefenseClaw's floor drop-in for an
// administrator's own policy tool.
func exportClaudeVersionFloor(opts Options) ([]byte, error) {
	if opts.claudeVersionFloorMode() == config.ClaudeVersionFloorOff {
		return nil, errors.New("the Claude Code version floor is off (enterprise.machine_policy.connectors.claudecode.version_floor)")
	}
	floor := ClaudeVersionFloor()
	if floor == "" {
		return nil, errors.New("no verified Claude Code hook contract has a lower bound")
	}
	return renderClaudeVersionFloor(floor)
}
