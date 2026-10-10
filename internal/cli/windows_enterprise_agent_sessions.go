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

	"gopkg.in/yaml.v3"

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

const windowsAgentSessionsRestartCode = "agent_sessions_restart_required"

// windowsEnterpriseActivationFileName records, beside deployment.json, when
// this deployment was activated. deployment.json itself is not extended: an
// earlier release decodes it strictly and must still read it after a
// rollback.
const windowsEnterpriseActivationFileName = "activation-state.json"

type windowsEnterpriseActivationRecord struct {
	ActivatedAt          string            `json:"activated_at,omitempty"`
	Pending              bool              `json:"pending,omitempty"`
	ConnectorActivatedAt map[string]string `json:"connector_activated_at,omitempty"`
	PendingConnectors    []string          `json:"pending_connectors,omitempty"`
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
)

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
	metadata, ok := windowsEnterpriseActivationMetadata()
	if !ok {
		return
	}
	path := filepath.Join(filepath.Dir(metadata), windowsEnterpriseActivationFileName)
	record, activated := readWindowsEnterpriseActivation(path)
	// A first install and a staged first install still use the deployment
	// activation time. Later upgrades can enable individual connectors.
	firstInstall := !opts.activationStartedAt.IsZero() && !opts.installedBeforeRun && len(result.Errors) == 0
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
	if activated.IsZero() && len(record.ConnectorActivatedAt) == 0 {
		return
	}
	processes, err := windowsEnterpriseAgentProcesses()
	if err != nil {
		return
	}
	byUser := map[string][]string{}
	connectorSessions := map[string]map[string][]string{}
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		if user == "" || process.StartedAt.IsZero() || windowsServiceIdentity(user) {
			continue
		}
		label := fmt.Sprintf("%s (pid %d)", process.Connector, process.PID)
		if !activated.IsZero() && process.StartedAt.Before(activated) {
			byUser[user] = append(byUser[user], label)
			continue
		}
		name := strings.ToLower(process.Connector)
		if currentErr != nil || !currentSet[name] {
			continue
		}
		at, parseErr := time.Parse(time.RFC3339Nano, record.ConnectorActivatedAt[name])
		if parseErr != nil || !process.StartedAt.Before(at) {
			continue
		}
		if connectorSessions[user] == nil {
			connectorSessions[user] = map[string][]string{}
		}
		connectorSessions[user][name] = append(connectorSessions[user][name], label)
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
}

func readWindowsEnterpriseActivation(path string) (windowsEnterpriseActivationRecord, time.Time) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 {
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
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		if user == "" || windowsServiceIdentity(user) || process.StartedAt.IsZero() ||
			!process.StartedAt.Before(changedAt) || !enabled[strings.ToLower(process.Connector)] {
			continue
		}
		byUser[user] = append(byUser[user], fmt.Sprintf("%s (pid %d)", process.Connector, process.PID))
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
}
