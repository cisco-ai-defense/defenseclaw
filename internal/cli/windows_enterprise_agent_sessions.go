// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An agent reads its hooks when it starts. Agents already open when Setup
// activated DefenseClaw kept running uninspected, and an action-profile user
// ran a call the profile blocks, while status, verify and the Setup result
// said nothing (GAP-0967). They now name each such session per account, as
// the Linux and macOS lifecycles do (agent_sessions_restart_required).
//
// The same holds after the hook guardian puts back hooks a standard user
// changed or removed: a Hermes session started while the hooks block was
// empty kept running without DefenseClaw after the restore, and status read
// security_complete (GAP-0440). Hermes keeps the callbacks it loaded and has
// no reload the guardian could trigger, so status, verify and ensure name
// that account's sessions of the connector that started before the restore
// and report security_complete false until they are restarted.

const windowsAgentSessionsRestartCode = "agent_sessions_restart_required"

// windowsEnterpriseActivationFileName records, beside deployment.json, when
// this deployment was activated. deployment.json itself is not extended: an
// earlier release decodes it strictly and must still read it after a
// rollback.
const windowsEnterpriseActivationFileName = "activation-state.json"

// windowsEnterpriseActivationMaxBytes bounds activation-state.json, which
// holds a time for each account and connector enrolled after the install.
const windowsEnterpriseActivationMaxBytes = 1 << 20

type windowsEnterpriseActivationRecord struct {
	ActivatedAt          string            `json:"activated_at,omitempty"`
	Pending              bool              `json:"pending,omitempty"`
	ConnectorActivatedAt map[string]string `json:"connector_activated_at,omitempty"`
	PendingConnectors    []string          `json:"pending_connectors,omitempty"`
	// EnrollmentActivatedAt dates each target (account and connector, keyed
	// as windowsEnterpriseManifestRowKey) that a later change enrolled for
	// an enabled connector: its sessions started earlier never read the
	// hooks (GAP-1435).
	EnrollmentActivatedAt map[string]string `json:"enrollment_activated_at,omitempty"`
	PendingEnrollments    []string          `json:"pending_enrollments,omitempty"`
}

// Seams for the deployment record and the running agents; tests replace them.
var (
	windowsEnterpriseActivationMetadata = func() (string, bool) {
		deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone)
		if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || deployment.MetadataPath == "" {
			return "", false
		}
		return deployment.MetadataPath, true
	}
	windowsEnterpriseAgentProcesses = inventory.RunningWindowsAgentProcesses
	// windowsEnterpriseActivationNow dates an activation when the change
	// action finished, after the lifecycle installed the hooks: an agent
	// started while they were being installed did not read them (GAP-1352).
	windowsEnterpriseActivationNow = time.Now
	// windowsEnterpriseEnrolledTargets returns the targets the installed
	// guardian manifest enrolls, keyed as windowsEnterpriseManifestRowKey.
	windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) {
		layout, err := managed.StandaloneWindowsLayout()
		if err != nil {
			return nil, err
		}
		manifest, err := enterprisehooks.LoadManifest(layout.ManifestPath)
		if err != nil {
			return nil, err
		}
		targets := make(map[string]bool, len(manifest.Targets))
		for _, target := range manifest.Targets {
			if target.Enabled == nil || *target.Enabled {
				targets[windowsEnterpriseManifestRowKey(target)] = true
			}
		}
		return targets, nil
	}
	// windowsEnterpriseAccountSID resolves the account an agent process runs
	// as to its SID, or "".
	windowsEnterpriseAccountSID = func(account string) string {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil || sid == nil {
			return ""
		}
		return sid.String()
	}
	// windowsEnterpriseGuardianRestores returns when the hook guardian last
	// put back each target's hooks, keyed as windowsEnterpriseManifestRowKey,
	// or an error when its record stays unreadable.
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) {
		layout, err := managed.StandaloneWindowsLayout()
		if err != nil {
			return nil, err
		}
		return readEnterpriseHookGuardianRestores(layout.DataDir)
	}
)

// windowsMachinePolicyHookConnectors keep DefenseClaw's hook registration in
// administrator-owned vendor machine policy on a standalone Windows
// deployment (Claude Code managed settings, Codex machine requirements,
// Cursor's machine hooks file), which a standard user cannot change. Their
// per-user target holds only the runtime the hook binary reads at each call,
// so once the guardian puts that back a running session is inspected again
// at its next call and needs no restart (GAP-0440).
var windowsMachinePolicyHookConnectors = map[string]bool{"claudecode": true, "codex": true, "cursor": true}

// windowsEnterpriseRecoveredFailedInstallCode is the warning an ensure adds
// when its repair rolled back a failed initial install before it installed.
const windowsEnterpriseRecoveredFailedInstallCode = "recovered_failed_install"

// windowsEnterpriseResultRecoveredFailedInstall reports whether this run
// rolled back a failed initial install (GAP-1366).
func windowsEnterpriseResultRecoveredFailedInstall(result *enterprisestatus.Result) bool {
	for _, warning := range result.Warnings {
		if warning.Code == windowsEnterpriseRecoveredFailedInstallCode {
			return true
		}
	}
	return false
}

// windowsEnterpriseStandaloneInstalled reports a standalone deployment that
// is installed now; a change action reads it before it runs.
func windowsEnterpriseStandaloneInstalled() bool {
	_, installed := windowsEnterpriseActivationMetadata()
	return installed
}

// applyWindowsEnterpriseAgentSessions records the activation of a deployment
// a change action just installed, and warns about each account's agent
// sessions that started before the activation.
func applyWindowsEnterpriseAgentSessions(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil || opts == nil || !result.Installed || result.TransactionPending {
		return
	}
	switch result.Action {
	case "status", "verify", "install", "upgrade", "repair", "ensure":
	default:
		return
	}
	// Bundle status has already scanned and attached the live sessions. Do
	// not run a second inventory here and risk a contradictory status warning.
	if result.Action == "status" && result.Bundle != nil && result.Bundle.SessionsRestartRequired != nil {
		return
	}
	metadata, ok := windowsEnterpriseActivationMetadata()
	if !ok {
		return
	}
	path := filepath.Join(filepath.Dir(metadata), windowsEnterpriseActivationFileName)
	record, activated := readWindowsEnterpriseActivation(path)
	// A first install and a staged first install still use the deployment
	// activation time. Later upgrades can enable individual connectors. An
	// ensure that rolled back a failed initial install and then installed is
	// a first install too: the failed install had written deployment.json, so
	// the host looked installed before the run (GAP-1366). A missing
	// activation record is not the signal: an upgrade from a build that
	// predates the record has none either, and must not warn.
	firstInstall := !opts.activationStartedAt.IsZero() &&
		(!opts.installedBeforeRun || windowsEnterpriseResultRecoveredFailedInstall(result)) &&
		len(result.Errors) == 0
	activatePending := !opts.activationStartedAt.IsZero() && record.Pending && !opts.noStart &&
		len(result.Errors) == 0 && result.Readiness.Gateway
	writeRecord := firstInstall || activatePending
	activatedAt := windowsEnterpriseActivationNow().UTC()
	if writeRecord {
		record.Pending = opts.noStart
		if !opts.noStart {
			activated = activatedAt
			record.ActivatedAt = activated.Format(time.RFC3339Nano)
		}
	}

	// Read the installed config after the transaction. A failed or unreadable
	// config must not invent an activation or replace the previous record.
	current, currentErr := windowsEnterpriseEnrolledConnectors()
	currentSet := make(map[string]bool, len(current))
	if currentErr == nil {
		for _, name := range current {
			currentSet[strings.ToLower(name)] = true
		}
	}
	changeSucceeded := !opts.activationStartedAt.IsZero() && opts.installedBeforeRun &&
		len(result.Errors) == 0 && currentErr == nil
	if changeSucceeded {
		previous := make(map[string]bool, len(opts.previousConnectors))
		for _, name := range opts.previousConnectors {
			previous[strings.ToLower(name)] = true
		}
		pending := make(map[string]bool, len(record.PendingConnectors))
		for _, name := range record.PendingConnectors {
			name = strings.ToLower(name)
			if currentSet[name] {
				pending[name] = true
			}
		}
		if opts.previousConnectorsKnown {
			for name := range currentSet {
				if !previous[name] {
					pending[name] = true
				}
			}
		}
		if len(pending) > 0 {
			if !opts.noStart && result.Readiness.Gateway {
				if record.ConnectorActivatedAt == nil {
					record.ConnectorActivatedAt = map[string]string{}
				}
				for name := range pending {
					record.ConnectorActivatedAt[name] = activatedAt.Format(time.RFC3339Nano)
				}
				record.PendingConnectors = nil
			} else {
				record.PendingConnectors = make([]string, 0, len(pending))
				for name := range pending {
					record.PendingConnectors = append(record.PendingConnectors, name)
				}
				sort.Strings(record.PendingConnectors)
			}
			writeRecord = true
		} else if len(record.PendingConnectors) > 0 {
			record.PendingConnectors = nil
			writeRecord = true
		}
		// A change that enrolls an account for a connector already enabled
		// leaves the connector set as it was; its targets show the account
		// (GAP-1435). A newly enabled connector is dated above.
		if current, err := windowsEnterpriseEnrolledTargets(); err == nil && opts.previousTargetsKnown {
			enrolled := map[string]bool{}
			for _, key := range record.PendingEnrollments {
				if current[key] {
					enrolled[key] = true
				}
			}
			for key := range current {
				_, connector, _ := strings.Cut(key, "\x00")
				if !opts.previousTargets[key] && (!opts.previousConnectorsKnown || previous[connector]) {
					enrolled[key] = true
				}
			}
			for key := range record.EnrollmentActivatedAt {
				if !current[key] {
					delete(record.EnrollmentActivatedAt, key)
					writeRecord = true
				}
			}
			switch {
			case len(enrolled) > 0 && !opts.noStart && result.Readiness.Gateway:
				if record.EnrollmentActivatedAt == nil {
					record.EnrollmentActivatedAt = map[string]string{}
				}
				for key := range enrolled {
					record.EnrollmentActivatedAt[key] = activatedAt.Format(time.RFC3339Nano)
				}
				record.PendingEnrollments = nil
				writeRecord = true
			case len(enrolled) > 0:
				record.PendingEnrollments = make([]string, 0, len(enrolled))
				for key := range enrolled {
					record.PendingEnrollments = append(record.PendingEnrollments, key)
				}
				sort.Strings(record.PendingEnrollments)
				writeRecord = true
			case len(record.PendingEnrollments) > 0:
				record.PendingEnrollments = nil
				writeRecord = true
			}
		}
	}
	if writeRecord {
		data, err := json.Marshal(record)
		if err == nil {
			err = writeFileKeepingDACL(path, append(data, '\n'), metadata)
		}
		if err != nil {
			result.AddWarning("activation_unrecorded", "could not record "+windowsEnterpriseActivationFileName+": "+err.Error())
		}
	}
	// An unreadable restore record leaves each session's restart status
	// unknown, which is named instead of read as "no restore".
	restores, restoresErr := windowsEnterpriseGuardianRestores()
	if restoresErr != nil {
		result.SecurityComplete = false
	}
	processes, err := windowsEnterpriseAgentProcesses()
	if err != nil {
		if restoresErr != nil {
			result.AddWarning(windowsAgentSessionsRestartCode, "restart status unknown: the hook guardian's restore record and running agent sessions could not be read")
		}
		return
	}
	// A session another warning of this run already names (the hot config
	// path names those of a newly enabled connector) is not named twice.
	var named []string
	for _, warning := range result.Warnings {
		if warning.Code == windowsAgentSessionsRestartCode {
			named = append(named, warning.Message)
		}
	}
	alreadyNamed := func(label string) bool {
		for _, message := range named {
			if strings.Contains(message, label) {
				return true
			}
		}
		return false
	}
	byUser := map[string][]string{}
	connectorSessions := map[string]map[string][]string{}
	enrollmentSessions := map[string]map[string][]string{}
	restoredSessions := map[string]map[string][]string{}
	unknownSessions := map[string][]string{}
	unknownOwners := map[string][]string{}
	// Sessions whose account name did not resolve (a deleted account whose
	// process kept running, or an unreachable directory): judged by their SID
	// below, and named as unknown if no verdict and no enrolled target covers
	// them (GAP-0591).
	type sidOnlySession struct{ sid, connector, label string }
	var sidOnly []sidOnlySession
	sids := map[string]string{}
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		sid := process.OwnerSID
		name := strings.ToLower(process.Connector)
		if name == "" || windowsServiceIdentity(user) || windowsServiceSID(sid) {
			continue
		}
		label := fmt.Sprintf("%s (pid %d)", process.Connector, process.PID)
		if alreadyNamed(label) {
			continue
		}
		if user == "" && sid == "" {
			unknownOwners[name] = append(unknownOwners[name], label)
			continue
		}
		if user == "" {
			user = sid
			sidOnly = append(sidOnly, sidOnlySession{sid: sid, connector: name, label: label})
		}
		if process.StartedAt.IsZero() {
			continue
		}
		if !activated.IsZero() && process.StartedAt.Before(activated) {
			byUser[user] = append(byUser[user], label)
			continue
		}
		if currentErr != nil || !currentSet[name] {
			continue
		}
		if at, parseErr := time.Parse(time.RFC3339Nano, record.ConnectorActivatedAt[name]); parseErr == nil && process.StartedAt.Before(at) {
			if connectorSessions[user] == nil {
				connectorSessions[user] = map[string][]string{}
			}
			connectorSessions[user][name] = append(connectorSessions[user][name], label)
			continue
		}
		if len(record.EnrollmentActivatedAt) == 0 && len(restores) == 0 && restoresErr == nil {
			continue
		}
		if sid == "" {
			var resolved bool
			sid, resolved = sids[user]
			if !resolved {
				sid = windowsEnterpriseAccountSID(user)
				sids[user] = sid
			}
		}
		if sid == "" {
			if restoresErr != nil && !windowsMachinePolicyHookConnectors[name] {
				unknownSessions[user] = append(unknownSessions[user], label)
			}
			continue
		}
		key := windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: name})
		if at, parseErr := time.Parse(time.RFC3339Nano, record.EnrollmentActivatedAt[key]); parseErr == nil && process.StartedAt.Before(at) {
			if enrollmentSessions[user] == nil {
				enrollmentSessions[user] = map[string][]string{}
			}
			enrollmentSessions[user][key] = append(enrollmentSessions[user][key], label)
			continue
		}
		if windowsMachinePolicyHookConnectors[name] {
			continue
		}
		if restoresErr != nil {
			unknownSessions[user] = append(unknownSessions[user], label)
			continue
		}
		if at, ok := restores[key]; ok && process.StartedAt.Before(at) {
			if restoredSessions[user] == nil {
				restoredSessions[user] = map[string][]string{}
			}
			restoredSessions[user][key] = append(restoredSessions[user][key], label)
		}
	}
	users := make([]string, 0, len(byUser))
	for user := range byUser {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
			"user %s runs %s, started before DefenseClaw was activated on this computer at %s; an agent reads its hooks when it starts, so these sessions run without DefenseClaw until they are restarted: ask that user to restart them",
			user, strings.Join(byUser[user], ", "), activated.Format(time.RFC3339)))
	}
	users = users[:0]
	for user := range connectorSessions {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		names := make([]string, 0, len(connectorSessions[user]))
		for name := range connectorSessions[user] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
				"user %s runs %s, started before its connector was enabled at %s; an agent reads its hooks when it starts, so ask that user to restart these sessions",
				user, strings.Join(connectorSessions[user][name], ", "), record.ConnectorActivatedAt[name]))
		}
	}
	users = users[:0]
	for user := range enrollmentSessions {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		keys := make([]string, 0, len(enrollmentSessions[user]))
		for key := range enrollmentSessions[user] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
				"user %s runs %s, started before the account was enrolled at %s; an agent reads its hooks when it starts, so ask that user to restart these sessions",
				user, strings.Join(enrollmentSessions[user][key], ", "), record.EnrollmentActivatedAt[key]))
		}
	}
	users = users[:0]
	for user := range restoredSessions {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		keys := make([]string, 0, len(restoredSessions[user]))
		for key := range restoredSessions[user] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			_, connectorName, _ := strings.Cut(key, "\x00")
			result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
				"user %s runs %s, started before the hook guardian put back the account's changed or removed %s hooks at %s; an agent keeps the hooks it loaded when it started, so a session started while they were missing runs without DefenseClaw until it is restarted: ask that user to restart these sessions",
				user, strings.Join(restoredSessions[user][key], ", "), connectorName, restores[key].UTC().Format(time.RFC3339)))
		}
	}
	users = users[:0]
	for user := range unknownSessions {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
			"user %s runs %s; restart status unknown: the hook guardian's restore record could not be read (%v), so DefenseClaw cannot tell whether these sessions started before the guardian put back the account's hooks and run without DefenseClaw: ask that user to restart them",
			user, strings.Join(unknownSessions[user], ", "), restoresErr))
	}
	if restoresErr != nil && len(unknownSessions) == 0 {
		result.AddWarning(windowsAgentSessionsRestartCode, "restart status unknown: the hook guardian's restore record could not be read")
	}
	if len(sidOnly) > 0 {
		// A SID no enabled target enrolls has no activation, enrollment or
		// restore time to judge its session by, so silence would read as "no
		// session to restart" while it runs without DefenseClaw. An unreadable
		// manifest or connector set is no proof of coverage either.
		targets, targetsErr := windowsEnterpriseEnrolledTargets()
		for _, session := range sidOnly {
			if (currentErr == nil && !currentSet[session.connector]) ||
				windowsEnterpriseSessionNamed(session.sid, session.label,
					[]map[string][]string{byUser, unknownSessions},
					[]map[string]map[string][]string{connectorSessions, enrollmentSessions, restoredSessions}) {
				continue
			}
			key := windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: session.sid, Connector: session.connector})
			if targetsErr == nil && targets[key] {
				continue
			}
			unknownOwners[session.connector] = append(unknownOwners[session.connector], session.label+" as "+session.sid)
		}
	}
	warnWindowsEnterpriseUnknownOwnerSessions(result, unknownOwners)
	if len(restoredSessions) > 0 {
		result.SecurityComplete = false
	}
}

func readWindowsEnterpriseActivation(path string) (windowsEnterpriseActivationRecord, time.Time) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > windowsEnterpriseActivationMaxBytes {
		return windowsEnterpriseActivationRecord{}, time.Time{}
	}
	var record windowsEnterpriseActivationRecord
	if json.Unmarshal(data, &record) != nil {
		return windowsEnterpriseActivationRecord{}, time.Time{}
	}
	activated, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.ActivatedAt))
	return record, activated
}

// windowsServiceIdentity reports a built-in service or system account,
// which no agent session of a user runs as.
func windowsServiceIdentity(user string) bool {
	domain, _, found := strings.Cut(user, `\`)
	if !found {
		return false
	}
	switch strings.ToUpper(domain) {
	case "NT AUTHORITY", "NT SERVICE", "WINDOW MANAGER", "FONT DRIVER HOST":
		return true
	}
	return false
}

// windowsServiceSID reports a process owner SID that names no interactive
// user account: a built-in, virtual or IIS application pool service
// identity, which may have no account name in a process snapshot. It
// classifies owners as the enumerator does (GAP-0673).
func windowsServiceSID(sid string) bool {
	sid = strings.TrimSpace(sid)
	return sid != "" && !enterprisehooks.WindowsInteractiveUserSID(sid)
}

// windowsEnterpriseSessionNamed reports whether a restart-status verdict of
// this run already names label for user.
func windowsEnterpriseSessionNamed(user, label string, flat []map[string][]string, nested []map[string]map[string][]string) bool {
	lists := make([][]string, 0, len(flat)+len(nested))
	for _, byUser := range flat {
		lists = append(lists, byUser[user])
	}
	for _, byUser := range nested {
		for _, labels := range byUser[user] {
			lists = append(lists, labels)
		}
	}
	for _, labels := range lists {
		for _, named := range labels {
			if named == label {
				return true
			}
		}
	}
	return false
}

// warnWindowsEnterpriseUnknownOwnerSessions keeps the restart status
// incomplete when the account behind a running agent cannot be identified.
func warnWindowsEnterpriseUnknownOwnerSessions(result *enterprisestatus.Result, sessions map[string][]string) {
	connectors := make([]string, 0, len(sessions))
	for connector := range sessions {
		connectors = append(connectors, connector)
	}
	sort.Strings(connectors)
	for _, connector := range connectors {
		labels := sessions[connector]
		sort.Strings(labels)
		result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
			"restart status unknown: the account running each agent session %s could not be identified, so DefenseClaw cannot tell whether it started before hooks were installed, enabled or put back and runs without DefenseClaw; ask that these sessions be restarted",
			strings.Join(labels, ", ")))
	}
	if len(connectors) > 0 {
		result.SecurityComplete = false
	}
}

// warnWindowsEnterpriseHotAgentSessions names sessions that opened before a
// newly enabled connector got hooks. The deployment activation record cannot
// catch sessions opened after the original install.
func warnWindowsEnterpriseHotAgentSessions(result *enterprisestatus.Result, previous, next []byte, changedAt time.Time) {
	type connectorDocument struct {
		Guardrail struct {
			Connectors map[string]struct {
				Enabled *bool `yaml:"enabled"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	var before, after connectorDocument
	if yaml.Unmarshal(previous, &before) != nil || yaml.Unmarshal(next, &after) != nil {
		return
	}
	enabled := map[string]bool{}
	for name, target := range after.Guardrail.Connectors {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		prior, existed := before.Guardrail.Connectors[name]
		if !existed || (prior.Enabled != nil && !*prior.Enabled) {
			enabled[strings.ToLower(name)] = true
		}
	}
	if len(enabled) == 0 {
		return
	}
	processes, err := windowsEnterpriseAgentProcesses()
	if err != nil {
		return
	}
	byUser := map[string][]string{}
	unknownOwners := map[string][]string{}
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		sid := process.OwnerSID
		name := strings.ToLower(process.Connector)
		if !enabled[name] || windowsServiceIdentity(user) || windowsServiceSID(sid) {
			continue
		}
		label := fmt.Sprintf("%s (pid %d)", process.Connector, process.PID)
		if user == "" && sid == "" {
			unknownOwners[name] = append(unknownOwners[name], label)
			continue
		}
		if process.StartedAt.IsZero() || !process.StartedAt.Before(changedAt) {
			continue
		}
		if user == "" {
			user = sid
		}
		byUser[user] = append(byUser[user], label)
	}
	users := make([]string, 0, len(byUser))
	for user := range byUser {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		sort.Strings(byUser[user])
		result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
			"user %s runs %s, started before its connector was enabled at %s; an agent reads its hooks when it starts, so ask that user to restart these sessions",
			user, strings.Join(byUser[user], ", "), changedAt.Format(time.RFC3339)))
	}
	warnWindowsEnterpriseUnknownOwnerSessions(result, unknownOwners)
}
