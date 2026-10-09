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
	ActivatedAt string `json:"activated_at"`
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
	activated := readWindowsEnterpriseActivation(path)
	// Only a run that found no deployment and started one activates it. A
	// host upgraded from a release without the record gets none: its
	// sessions had hooks already, and a guessed time would name them.
	if !opts.activationStartedAt.IsZero() && !opts.installedBeforeRun && !opts.noStart && len(result.Errors) == 0 {
		activated = opts.activationStartedAt.UTC()
		data, err := json.Marshal(windowsEnterpriseActivationRecord{ActivatedAt: activated.Format(time.RFC3339Nano)})
		if err == nil {
			err = writeFileKeepingDACL(path, append(data, '\n'), metadata)
		}
		if err != nil {
			result.AddWarning("activation_unrecorded", "could not record "+windowsEnterpriseActivationFileName+": "+err.Error())
		}
	}
	if activated.IsZero() {
		return
	}
	processes, err := windowsEnterpriseAgentProcesses()
	if err != nil {
		return
	}
	byUser := map[string][]string{}
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		if user == "" || process.StartedAt.IsZero() || !process.StartedAt.Before(activated) || windowsServiceIdentity(user) {
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
		result.AddWarning(windowsAgentSessionsRestartCode, fmt.Sprintf(
			"user %s runs %s, started before DefenseClaw was activated on this computer at %s; an agent reads its hooks when it starts, so these sessions run without DefenseClaw until they are restarted: ask that user to restart them",
			user, strings.Join(byUser[user], ", "), activated.Format(time.RFC3339)))
	}
}

func readWindowsEnterpriseActivation(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 {
		return time.Time{}
	}
	var record windowsEnterpriseActivationRecord
	if json.Unmarshal(data, &record) != nil {
		return time.Time{}
	}
	activated, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.ActivatedAt))
	if err != nil {
		return time.Time{}
	}
	return activated
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
