// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsManagedLaunchCoverageNamesPureModeAndAuditsItsWarning(t *testing.T) {
	priorConnectors, priorProcesses, priorAudit := windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses, windowsManagedLaunchAudit
	t.Cleanup(func() {
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses = priorConnectors, priorProcesses
		windowsManagedLaunchAudit = priorAudit
	})
	var audited []string
	windowsManagedLaunchAudit = func(process inventory.AgentProcess, connector, reason string) error {
		audited = append(audited, connector+":"+reason)
		return nil
	}
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) {
		return []string{"opencode", "amp", "kiro", "devin", "hermes"}, nil
	}
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 33, Connector: "opencode", User: `DCFC\alice`, Args: []string{"opencode.exe", "--pure"}, ArgsKnown: true},
			{PID: 34, Connector: "amp", User: `DCFC\alice`, Args: []string{"amp.exe"}, ArgsKnown: true},
			{PID: 36, Connector: "kiro", User: `DCFC\alice`, Args: []string{"kiro-cli.exe", "--agent", "mine"}, ArgsKnown: true},
			{PID: 37, Connector: "devin", User: `DCFC\alice`, Args: []string{"devin.exe", "--config", `C:\other.json`}, ArgsKnown: true},
			{PID: 38, Connector: "hermes", User: `DCFC\alice`, Args: []string{"hermes.exe", "--safe-mode"}, ArgsKnown: true},
			{PID: 35, Connector: "codex", User: `DCFC\alice`, Args: []string{"codex.exe", "--pure"}, ArgsKnown: true},
		}, nil
	}
	for _, action := range []string{"status", "verify"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
		applyWindowsEnterpriseLaunchCoverage(result)
		if result.CoverageComplete || result.SecurityComplete || len(result.Warnings) != 5 {
			t.Fatalf("%s silently reported healthy: %+v", action, result)
		}
		message := result.Warnings[0].Message
		if !strings.Contains(message, "opencode (pid 33)") || !strings.Contains(message, "opencode_pure") || strings.Contains(message, "codex") {
			t.Fatalf("%s did not name the pure process: %q", action, message)
		}
		if !strings.Contains(result.Warnings[2].Message, "kiro_alternate_agent") {
			t.Fatalf("%s did not name the alternate Kiro agent: %+v", action, result.Warnings)
		}
		if !strings.Contains(result.Warnings[3].Message, "devin_config_override") ||
			!strings.Contains(result.Warnings[4].Message, "hermes_safe_mode") {
			t.Fatalf("%s did not name other uninspected launch modes: %+v", action, result.Warnings)
		}
		if !strings.Contains(windowsEnterpriseEventMessage(result), windowsManagedLaunchUninspected) {
			t.Fatalf("%s Windows audit event omitted the coverage code", action)
		}
		if action == "verify" && len(result.Errors) != 5 {
			t.Fatalf("verify did not fail on uninspected launches: %+v", result.Errors)
		}
	}
	if len(audited) != 10 || audited[0] != "opencode:opencode_pure" || audited[2] != "kiro:kiro_alternate_agent" ||
		audited[3] != "devin:devin_config_override" || audited[4] != "hermes:hermes_safe_mode" {
		t.Fatalf("uninspected Windows launches were not centrally audited: %v", audited)
	}
	upgrade := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.0.4")
	upgrade.Installed, upgrade.CoverageComplete, upgrade.SecurityComplete = true, true, true
	applyWindowsEnterpriseLaunchCoverage(upgrade)
	if len(upgrade.Warnings) != 0 || !upgrade.CoverageComplete || !upgrade.SecurityComplete {
		t.Fatalf("running clients changed the committed upgrade result: %+v", upgrade)
	}
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return nil, errors.New("snapshot failed") }
	result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.4")
	result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
	applyWindowsEnterpriseLaunchCoverage(result)
	if result.CoverageComplete || result.SecurityComplete || len(result.Errors) != 1 || result.Errors[0].Code != windowsManagedLaunchScanUnknown {
		t.Fatalf("unknown scan reported healthy: %+v", result)
	}
}

func TestWindowsManagedLaunchCoverageNormalProfilesStayHealthy(t *testing.T) {
	priorConnectors, priorProcesses := windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses
	priorEnvironment, priorProfile, priorAudit := windowsManagedLaunchEnvironment, enterpriseHookSIDProfilePath, windowsManagedLaunchAudit
	priorAccountSID := windowsEnterpriseAccountSID
	t.Cleanup(func() {
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses = priorConnectors, priorProcesses
		windowsManagedLaunchEnvironment, enterpriseHookSIDProfilePath, windowsManagedLaunchAudit = priorEnvironment, priorProfile, priorAudit
		windowsEnterpriseAccountSID = priorAccountSID
	})
	const sid = "S-1-5-21-111-222-333-1001"
	const profile = `C:\Users\alice`
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) {
		return []string{"opencode", "amp", "devin", "hermes", "antigravity"}, nil
	}
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 7133, Connector: "opencode", User: `DCFC\alice`, OwnerSID: sid, Args: []string{"opencode.exe"}, ArgsKnown: true},
			{PID: 7134, Connector: "amp", User: `DCFC\alice`, Args: []string{"amp.exe"}, ArgsKnown: true},
			{PID: 7135, Connector: "devin", User: `DCFC\alice`, OwnerSID: sid, Args: []string{"devin.exe"}, ArgsKnown: true},
			{PID: 7136, Connector: "hermes", User: `DCFC\alice`, OwnerSID: sid, Args: []string{"hermes.exe"}, ArgsKnown: true},
			{PID: 7137, Connector: "antigravity", User: `DCFC\alice`, OwnerSID: sid, Args: []string{"agy.exe"}, ArgsKnown: true},
		}, nil
	}
	windowsEnterpriseAccountSID = func(string) string { return sid }
	enterpriseHookSIDProfilePath = func(string) (string, error) { return profile, nil }
	windowsManagedLaunchEnvironment = func(pid int) (map[string]string, error) {
		env := map[string]string{"USERPROFILE": `c:\users\ALICE`,
			"APPDATA": profile + `\AppData\Roaming`, "LOCALAPPDATA": profile + `\AppData\Local`,
			"PROGRAMDATA": os.Getenv("ProgramData")}
		switch pid {
		case 7133:
			env["OPENCODE_PURE"] = "false"
			env["OPENCODE_CONFIG_DIR"] = profile + `\.config\opencode`
		case 7136:
			env["HERMES_SAFE_MODE"] = "0"
		}
		return env, nil
	}
	var audited []string
	windowsManagedLaunchAudit = func(_ inventory.AgentProcess, connector, reason string) error {
		audited = append(audited, connector+":"+reason)
		return nil
	}
	verify := func(wantWarnings int) *enterprisestatus.Result {
		result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
		applyWindowsEnterpriseLaunchCoverage(result)
		if len(result.Warnings) != wantWarnings || len(result.Errors) != wantWarnings ||
			result.CoverageComplete != (wantWarnings == 0) || result.SecurityComplete != (wantWarnings == 0) {
			t.Fatalf("Windows launch coverage (want %d warnings): %+v", wantWarnings, result)
		}
		return result
	}
	verify(0)
	if len(audited) != 0 {
		t.Fatalf("normal launches raised audit alerts: %v", audited)
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) { return nil, errors.New("access denied") }
	verify(5)
	if len(audited) != 5 {
		t.Fatalf("unreadable launches had no audit alerts: %v", audited)
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) {
		return map[string]string{"USERPROFILE": profile, "OPENCODE_PURE": "1"}, nil
	}
	result := verify(1)
	if !strings.Contains(result.Warnings[0].Message, "opencode_pure") {
		t.Fatalf("environment bypass was missed: %+v", result.Warnings)
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) {
		return map[string]string{"USERPROFILE": profile, "APPDATA": `C:\other\Roaming`,
			"LOCALAPPDATA": profile + `\AppData\Local`}, nil
	}
	result = verify(1)
	if !strings.Contains(result.Warnings[0].Message, "devin (pid 7135)") ||
		!strings.Contains(result.Warnings[0].Message, "user_config_relocated") {
		t.Fatalf("redirected Devin AppData was missed: %+v", result.Warnings)
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) {
		return map[string]string{"USERPROFILE": profile, "APPDATA": profile + `\AppData\Roaming`,
			"LOCALAPPDATA": `C:\other\Local`}, nil
	}
	result = verify(1)
	if !strings.Contains(result.Warnings[0].Message, "hermes (pid 7136)") ||
		!strings.Contains(result.Warnings[0].Message, "hermes_config_relocated") {
		t.Fatalf("redirected Hermes AppData was missed: %+v", result.Warnings)
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) {
		return map[string]string{"USERPROFILE": profile, "OPENCODE_PURE": "1"}, nil
	}
	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", errors.New("profile unavailable") }
	result = verify(5)
	if !strings.Contains(result.Warnings[0].Message, "opencode_pure") {
		t.Fatalf("specific bypass was masked by missing profile: %+v", result.Warnings)
	}
}

func TestWindowsManagedKiroResumePlacementIsUnverified(t *testing.T) {
	priorConnectors, priorProcesses, priorAudit := windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses, windowsManagedLaunchAudit
	priorEnvironment := windowsManagedLaunchEnvironment
	priorProfile := enterpriseHookSIDProfilePath
	t.Cleanup(func() {
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseAgentProcesses = priorConnectors, priorProcesses
		windowsManagedLaunchAudit, windowsManagedLaunchEnvironment = priorAudit, priorEnvironment
		enterpriseHookSIDProfilePath = priorProfile
	})
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"kiro"}, nil }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{PID: 7192, Connector: "kiro", User: `DCFC\alice`, OwnerSID: "S-1-5-21-111-222-333-1001",
			Args: []string{"kiro-cli.exe", "--resume-id", "cloud-session-id"}, ArgsKnown: true}}, nil
	}
	windowsManagedLaunchEnvironment = func(int) (map[string]string, error) { return map[string]string{}, nil }
	enterpriseHookSIDProfilePath = func(string) (string, error) { return `C:\Users\alice`, nil }
	var audited []string
	windowsManagedLaunchAudit = func(_ inventory.AgentProcess, connector, reason string) error {
		audited = append(audited, connector+":"+reason)
		return nil
	}
	for _, action := range []string{"status", "verify"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
		applyWindowsEnterpriseLaunchCoverage(result)
		if result.CoverageComplete || result.SecurityComplete || len(result.Warnings) != 1 ||
			!strings.Contains(result.Warnings[0].Message, "kiro_resume_placement_unverified") {
			t.Fatalf("%s missed Kiro cloud resume: %+v", action, result)
		}
	}
	if len(audited) != 2 || audited[0] != "kiro:kiro_resume_placement_unverified" {
		t.Fatalf("Kiro resume audits = %+v", audited)
	}
}

func TestWindowsManagedLaunchCoverageWritesCanonicalGatewayAuditWithoutArguments(t *testing.T) {
	priorEndpoint := windowsManagedLaunchAuditEndpoint
	t.Cleanup(func() { windowsManagedLaunchAuditEndpoint = priorEndpoint })
	bodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/observability/cli" || r.Header.Get("Authorization") != "Bearer managed-token" {
			t.Errorf("unexpected gateway request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		var decoded map[string]any
		if err != nil || json.Unmarshal(body, &decoded) != nil || strings.Contains(string(body), "secret-prompt") {
			t.Errorf("unsafe or invalid audit body: %q, %v", body, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	windowsManagedLaunchAuditEndpoint = func() (string, string, bool, error) {
		return server.URL, "managed-token", true, nil
	}
	started := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	process := inventory.AgentProcess{PID: 7133, Connector: "opencode", OwnerSID: "S-1-5-21-1234",
		StartedAt: started, Args: []string{"opencode.exe", "--pure", "secret-prompt"}}
	if err := reportWindowsManagedLaunchCoverage(process, "opencode", "opencode_pure"); err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	if err := json.Unmarshal(<-bodies, &captured); err != nil {
		t.Fatal(err)
	}
	alert, ok := captured["alert"].(map[string]any)
	if !ok || captured["kind"] != "alert" || alert["summary"] != windowsManagedLaunchUninspected || alert["source"] != "managed-launch-coverage" {
		t.Fatalf("missing canonical audit alert: %+v", captured)
	}
	details, ok := alert["details"].(map[string]any)
	if !ok || details["connector"] != "opencode" || details["coverage_reason"] != "opencode_pure" ||
		details["process_pid"] != float64(7133) || details["actor_id"] != process.OwnerSID {
		t.Fatalf("missing safe process identity: %+v", details)
	}
	install := enterprisehooks.UnprotectedAgent{SID: process.OwnerSID, Connector: "claudecode", Version: "2.0.77",
		InstallPath: `C:\Users\alice\private\node_modules\@anthropic-ai\claude-code`}
	if err := reportWindowsManagedInstallCoverage(install); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(<-bodies, &captured); err != nil {
		t.Fatal(err)
	}
	alert, ok = captured["alert"].(map[string]any)
	if !ok || alert["summary"] != "managed_agent_install_unprotected" || alert["source"] != "managed-install-coverage" {
		t.Fatalf("missing private install alert: %+v", captured)
	}
	details, ok = alert["details"].(map[string]any)
	if !ok || details["agent_install_path"] != install.InstallPath || details["agent_version"] != "2.0.77" || details["actor_id"] != process.OwnerSID {
		t.Fatalf("private install audit lost copy identity: %+v", details)
	}
}
