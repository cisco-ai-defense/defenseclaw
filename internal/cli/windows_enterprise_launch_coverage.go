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
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
// Only the launches of enrolled accounts are judged (windowsLaunchEnrollment).
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
	enrolled := loadWindowsLaunchEnrollment()
	for _, process := range processes {
		name := strings.ToLower(process.Connector)
		if !selected[name] || windowsServiceIdentity(process.User) || windowsServiceSID(process.OwnerSID) {
			continue
		}
		home := ""
		ownerSID := process.OwnerSID
		if ownerSID == "" && process.User != "" {
			ownerSID = windowsEnterpriseAccountSID(process.User)
		}
		if ownerSID != "" {
			home, _ = enterpriseHookSIDProfilePath(ownerSID)
		}
		if !enrolled.covers(ownerSID, process.User, home, name) {
			continue // excluded, exempt or not enrolled: DefenseClaw does not protect this account
		}
		launchEnv, envErr := windowsManagedLaunchEnvironment(process.PID)
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
	// The administrator's token, the account and the install path go only
	// to the gateway service's own socket: another account that holds the
	// port while the service is down receives nothing (GAP-0962 class).
	target, err := url.Parse(base)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Path != "" {
		return errors.New("managed gateway audit endpoint is invalid")
	}
	client, err := managedGatewayClientFactory(2*time.Second, target.Host, managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
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

// windowsEnterpriseEnrollmentPolicy returns the installed config's
// enterprise.enrollment; replaceable in tests.
var windowsEnterpriseEnrollmentPolicy = func() (config.EnterpriseEnrollmentConfig, error) {
	cfg, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return config.EnterpriseEnrollmentConfig{}, err
	}
	return cfg.Enterprise.Enrollment, nil
}

// windowsLaunchEnrollment is the accounts whose agent launches count toward
// managed coverage: the profiles the guardian manifest enrolls. The
// enumerator gives an excluded profile no rows, and an exempt one only its
// machine-policy rows (and the per-user rows it already had), so an
// excluded or exempt account's launch neither lowers status and verify nor
// reaches the audit. An unreadable manifest, or an owner whose SID is
// unknown, is judged as enrolled.
type windowsLaunchEnrollment struct {
	known bool
	// rows are the enabled manifest rows (windowsEnterpriseManifestRowKey);
	// identities the SIDs (or users) that have at least one.
	rows, identities map[string]bool
	exclude, exempt  []string
}

func loadWindowsLaunchEnrollment() windowsLaunchEnrollment {
	e := windowsLaunchEnrollment{identities: map[string]bool{}}
	if rows, err := windowsEnterpriseEnrolledTargets(); err == nil {
		e.known, e.rows = true, rows
		for key := range rows {
			identity, _, _ := strings.Cut(key, "\x00")
			e.identities[identity] = true
		}
	}
	if enrollment, err := windowsEnterpriseEnrollmentPolicy(); err == nil {
		e.exclude, e.exempt = enrollment.ExcludeUsers, enrollment.ExemptUsers
	}
	return e
}

// covers reports whether the owner of a connector process is an enrolled
// account. enterprise.enrollment entries match a SID, profile folder name,
// account name or DOMAIN\account, case-insensitively, as the enumerator
// matches them.
func (e windowsLaunchEnrollment) covers(sid, user, home, connector string) bool {
	sid, user = strings.TrimSpace(sid), strings.TrimSpace(user)
	names := []string{sid, user}
	if home = strings.TrimSpace(home); home != "" {
		names = append(names, filepath.Base(filepath.Clean(home)))
	}
	if _, account, ok := strings.Cut(user, `\`); ok {
		names = append(names, account)
	}
	row := sid != "" && e.rows[windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: connector})]
	if windowsLaunchListMatches(e.exclude, names) || (!row && windowsLaunchListMatches(e.exempt, names)) {
		return false
	}
	if !e.known || sid == "" || row {
		return true
	}
	return e.identities[strings.ToUpper(sid)] || (user != "" && e.identities[user])
}

func windowsLaunchListMatches(list, names []string) bool {
	for _, entry := range list {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		for _, name := range names {
			if name != "" && strings.EqualFold(entry, name) {
				return true
			}
		}
	}
	return false
}

func windowsLaunchCoverageWarning(result *enterprisestatus.Result, code, message string) {
	result.AddWarning(code, message)
	result.CoverageComplete, result.SecurityComplete = false, false
	if result.Action == "verify" {
		result.AddError(code, message)
	}
}
