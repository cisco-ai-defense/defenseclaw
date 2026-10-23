// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

const windowsManagedLaunchUninspected = "managed_launch_uninspected"
const windowsManagedLaunchScanUnknown = "managed_launch_scan_unknown"
const windowsManagedLaunchAuditUnavailable = "managed_launch_audit_unavailable"

var windowsManagedLaunchAudit = reportWindowsManagedLaunchCoverage
var windowsManagedInstallAudit = reportWindowsManagedInstallCoverage
var windowsManagedLaunchAuditEndpoint = managedScanGatewayEndpoint
var windowsManagedLaunchEnvironment = agentprocess.LaunchEnvironmentForPID

// applyWindowsEnterpriseLaunchCoverage uses the native process inventory
// after the installer has established managed readiness. The elevated CLI
// reads selected launch selectors from process memory and resolves the
// account profile from the process owner SID. An unreadable process remains
// unverified, never treated as proof that it loaded the managed connector.
func applyWindowsEnterpriseLaunchCoverage(result *enterprisestatus.Result) {
	if result == nil || !result.Installed || result.TransactionPending ||
		(result.Action != "status" && result.Action != "verify") {
		return
	}
	enabled, err := windowsEnterpriseEnrolledConnectors()
	if err != nil {
		return // installed-config errors are reported by the lifecycle
	}
	selected := map[string]bool{}
	for _, name := range enabled {
		if name == "opencode" || name == "amp" || name == "kiro" ||
			name == "devin" || name == "hermes" || name == "antigravity" {
			selected[name] = true
		}
	}
	if len(selected) == 0 {
		return
	}
	processes, err := windowsEnterpriseAgentProcesses()
	if err != nil {
		windowsLaunchCoverageWarning(result, windowsManagedLaunchScanUnknown,
			"the Windows agent process scan failed, so active agent launches cannot be verified: "+err.Error())
		return
	}
	for _, process := range processes {
		name := strings.ToLower(process.Connector)
		if !selected[name] || windowsServiceIdentity(process.User) || windowsServiceSID(process.OwnerSID) {
			continue
		}
		launchEnv, envErr := windowsManagedLaunchEnvironment(process.PID)
		home := ""
		ownerSID := process.OwnerSID
		if ownerSID == "" && process.User != "" {
			ownerSID = windowsEnterpriseAccountSID(process.User)
		}
		if ownerSID != "" {
			home, _ = enterpriseHookSIDProfilePath(ownerSID)
		}
		reason := enterprisestatus.PluginLaunchCoverage(name, process.Args, launchEnv, envErr == nil, home)
		if reason == "" && !process.ArgsKnown {
			reason = "launch_arguments_unverified"
		}
		if reason == "" {
			continue
		}
		who := process.User
		if who == "" {
			who = process.OwnerSID
		}
		if who == "" {
			who = "unknown account"
		}
		message := fmt.Sprintf("user %s runs %s (pid %d): %s; its managed hook or plugin load is not proven, so tool calls in this session may be uninspected. Close this session and restart without the bypass", who, name, process.PID, reason)
		windowsLaunchCoverageWarning(result, windowsManagedLaunchUninspected, message)
		if err := windowsManagedLaunchAudit(process, name, reason); err != nil {
			result.AddWarning(windowsManagedLaunchAuditUnavailable,
				fmt.Sprintf("could not audit the uninspected %s session (pid %d): %v", name, process.PID, err))
		}
	}
}

// The elevated standalone CLI uses the protected gateway token to write one
// canonical audit alert. Its request contains fixed classifications and
// process identity, never argv, environment or prompt text.
func reportWindowsManagedLaunchCoverage(process inventory.AgentProcess, connector, reason string) error {
	details := map[string]any{"connector": connector, "process_pid": process.PID,
		"coverage_reason": reason, "coverage_state": "incomplete"}
	if !process.StartedAt.IsZero() {
		details["process_started_at"] = process.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if process.OwnerSID != "" {
		details["actor_id_kind"] = "windows_sid"
		details["actor_id"] = process.OwnerSID
	}
	return postWindowsManagedCoverageAlert("managed-launch-coverage", windowsManagedLaunchUninspected, details)
}

func reportWindowsManagedInstallCoverage(agent enterprisehooks.UnprotectedAgent) error {
	reason := "unsupported_installed_version"
	if agent.Version == "" {
		reason = "installed_version_unverified"
	}
	details := map[string]any{"connector": agent.Connector, "agent_install_path": agent.InstallPath,
		"agent_version": agent.Version, "coverage_reason": reason, "coverage_state": "incomplete"}
	if agent.SID != "" {
		details["actor_id_kind"] = "windows_sid"
		details["actor_id"] = agent.SID
	}
	return postWindowsManagedCoverageAlert("managed-install-coverage", "managed_agent_install_unprotected", details)
}

func postWindowsManagedCoverageAlert(source, summary string, details map[string]any) error {
	base, token, managedHost, err := windowsManagedLaunchAuditEndpoint()
	if err != nil {
		return err
	}
	if !managedHost || token == "" {
		return errors.New("managed gateway audit endpoint is unavailable")
	}
	body, err := json.Marshal(map[string]any{"kind": "alert", "alert": map[string]any{
		"source": source, "severity": "HIGH",
		"summary": summary, "details": details,
	}})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/observability/cli", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("gateway audit returned HTTP %d", response.StatusCode)
	}
	return nil
}

func windowsLaunchCoverageWarning(result *enterprisestatus.Result, code, message string) {
	result.AddWarning(code, message)
	result.CoverageComplete, result.SecurityComplete = false, false
	if result.Action == "verify" {
		result.AddError(code, message)
	}
}
