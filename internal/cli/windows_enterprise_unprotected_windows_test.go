// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubWindowsUnprotectedAgents(t *testing.T, agents []enterprisehooks.UnprotectedAgent, err error) {
	t.Helper()
	previous := windowsEnterpriseUnprotectedAgentsReader
	t.Cleanup(func() { windowsEnterpriseUnprotectedAgentsReader = previous })
	windowsEnterpriseUnprotectedAgentsReader = func() ([]enterprisehooks.UnprotectedAgent, error) { return agents, err }
}

// Agents the enumerator found installed but could not enroll run without
// DefenseClaw (or are refused by machine policy); status and verify name
// them for their account and report the deployment security-incomplete, and
// verify still passes.
func TestWindowsStandaloneStatusAndVerifyReportUnprotectedAgents(t *testing.T) {
	stubWindowsUnprotectedAgents(t, []enterprisehooks.UnprotectedAgent{{
		User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "cursor", Version: "4.1.0",
		Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
		Reason: "version 4.1.0 is not verified against a known hook contract; its machine-policy hooks refuse this user's tool calls until it is enrolled",
	}}, nil)
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(status, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		OK: true, Installed: true, SecurityComplete: true, GuardianReady: true, GatewayReady: true,
	}, windowsEnterpriseStandaloneRun{})
	if status.SecurityComplete {
		t.Fatal("status reports security_complete with an unprotected agent")
	}
	found := false
	for _, warning := range status.Warnings {
		found = found || (warning.Code == enterprisehooks.UnprotectedCodeHookContractUnverified &&
			strings.Contains(warning.Message, "cursor 4.1.0 for user alice (S-1-5-21-1-2-3-1001) is not protected"))
	}
	if !found || len(status.Errors) != 0 {
		t.Fatalf("status warnings %+v errors %+v", status.Warnings, status.Errors)
	}

	verify := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.0")
	verify.SecurityComplete = true
	applyWindowsEnterpriseUnprotectedAgents(verify)
	if len(verify.Errors) != 0 || len(verify.Warnings) != 1 ||
		verify.Warnings[0].Code != enterprisehooks.UnprotectedCodeHookContractUnverified || verify.SecurityComplete {
		t.Fatalf("verify = %+v, want a warning for the unprotected agent", verify)
	}

	// No record, or a record this token cannot read, reports nothing.
	for _, err := range []error{os.ErrNotExist, os.ErrPermission} {
		stubWindowsUnprotectedAgents(t, nil, err)
		quiet := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
		quiet.SecurityComplete = true
		applyWindowsEnterpriseUnprotectedAgents(quiet)
		if !quiet.SecurityComplete || len(quiet.Warnings) != 0 {
			t.Fatalf("%v: %+v", err, quiet)
		}
	}
	// A record that is present but untrusted or malformed is itself a gap.
	stubWindowsUnprotectedAgents(t, nil, errors.New("noncanonical owner"))
	broken := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	broken.SecurityComplete = true
	applyWindowsEnterpriseUnprotectedAgents(broken)
	if broken.SecurityComplete || len(broken.Warnings) != 1 || !strings.Contains(broken.Warnings[0].Message, "record is unreadable") {
		t.Fatalf("broken record: %+v", broken)
	}
}

// A config that enrols no connector (before GAP-0221 the loader dropped the
// documented claudecode: {} entries) left every service healthy and verify
// passing while DefenseClaw protected no agent: verify fails on it, status
// warns, and a config that enrols a connector reports nothing.
func TestWindowsStandaloneVerifyFailsWhenNoConnectorIsEnrolled(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previous := windowsEnterpriseEnrolledConnectors
	t.Cleanup(func() { windowsEnterpriseEnrolledConnectors = previous })
	var enrolled []string
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return enrolled, nil }
	run := func(action string) *enterprisestatus.Result {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
			OK: true, Installed: true, SecurityComplete: true, GuardianReady: true, GatewayReady: true,
		}, windowsEnterpriseStandaloneRun{})
		return result
	}
	verify := run("verify")
	if !strings.Contains(fmt.Sprint(verify.Errors), "no_connectors_enabled") || verify.SecurityComplete {
		t.Fatalf("verify with no enrolled connector = errors %+v security_complete %t", verify.Errors, verify.SecurityComplete)
	}
	status := run("status")
	if strings.Contains(fmt.Sprint(status.Errors), "no_connectors_enabled") ||
		!strings.Contains(fmt.Sprint(status.Warnings), "no_connectors_enabled") || status.SecurityComplete {
		t.Fatalf("status with no enrolled connector = %+v", status)
	}
	enrolled = []string{"claudecode"}
	if verify := run("verify"); strings.Contains(fmt.Sprint(verify.Errors, verify.Warnings), "no_connectors_enabled") {
		t.Fatalf("verify with claudecode enrolled = %+v", verify)
	}
}

// Status names why an installed gateway is not running, from the last error
// it logged, and reports the rows DefenseClaw keeps for a deleted account
// whose profile folder is still there.
func TestWindowsStandaloneStatusNamesGatewayStartFailureAndDeletedAccount(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previousFailure, previousAccounts, previousDeleted, previousFolder := windowsEnterpriseGatewayStartFailure, windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir
	t.Cleanup(func() {
		windowsEnterpriseGatewayStartFailure, windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir = previousFailure, previousAccounts, previousDeleted, previousFolder
	})
	windowsEnterpriseAccountCreatedDataDir = func(string, string) bool { return false }
	windowsEnterpriseGatewayStartFailure = func() (string, string) {
		return `failed to load config: observability.local.path: cannot inspect configured path C:\ProgramData\Cisco\DefenseClaw\runtime\audit.db: Access is denied.`,
			`C:\ProgramData\Cisco\DefenseClaw\logs\gateway\gateway.log`
	}
	home := t.TempDir()
	windowsEnterpriseManifestAccounts = func() ([]windowsEnterpriseManifestAccount, error) {
		return []windowsEnterpriseManifestAccount{
			{User: "alice", SID: "S-1-5-21-1-2-3-1001", Home: home, Rows: 2},
			{User: "bob", SID: "S-1-5-21-1-2-3-1002", Home: home, Rows: 1},
		}, nil
	}
	windowsEnterpriseAccountDeleted = func(sid string) bool { return sid == "S-1-5-21-1-2-3-1001" }
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(status, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Installed: true, GatewayService: "DefenseClawGateway", GatewayServiceState: "stopped",
	}, windowsEnterpriseStandaloneRun{ExitCode: 1})
	if len(status.Errors) != 1 || status.Errors[0].Code != "gateway_start_failed" ||
		!strings.Contains(status.Errors[0].Message, "cannot inspect configured path") ||
		!strings.Contains(status.Errors[0].Message, "enterprise windows repair") {
		t.Fatalf("errors = %+v, want the gateway's start failure named", status.Errors)
	}
	deleted := 0
	for _, warning := range status.Warnings {
		if warning.Code == "deleted_account_rows" {
			deleted++
			if !strings.Contains(warning.Message, "alice (S-1-5-21-1-2-3-1001)") || !strings.Contains(warning.Message, "2 enrollment row(s)") {
				t.Fatalf("deleted account warning %q", warning.Message)
			}
		}
	}
	if deleted != 1 {
		t.Fatalf("warnings = %+v, want one deleted-account warning", status.Warnings)
	}
	// An unresolvable SID outside this computer's accounts (a domain account
	// whose directory may be unreachable) is never reported deleted.
	if previousDeleted("S-1-5-21-1-2-3-1001") {
		t.Fatal("a non-local SID whose lookup failed was reported deleted")
	}

	// Human status prints the start failure once: the summary lists it, and
	// the returned error names only its code.
	previousObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() { windowsEnterpriseStandaloneObserver = previousObserver })
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := finishWindowsEnterpriseStandalone(cmd, &windowsEnterpriseLifecycleOptions{}, status, 0)
	if err == nil || strings.Count(out.String()+err.Error(), "cannot inspect configured path") != 1 {
		t.Fatalf("human status printed the start failure other than once: %q, %v", out.String(), err)
	}

	// Verify names the service whose access a managed path lost, and what
	// restores it, instead of only its service SID.
	previousServiceName := windowsEnterpriseServiceSIDName
	t.Cleanup(func() { windowsEnterpriseServiceSIDName = previousServiceName })
	windowsEnterpriseServiceSIDName = func(string) string { return "DefenseClawGateway" }
	verify := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(verify, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Installed: true, GatewayService: "DefenseClawGateway", GatewayServiceState: "running",
		Errors: []string{`managed path is missing required rights for S-1-5-80-1-2-3-4-5 (required=ReadAndExecute actual=0): C:\ProgramData\Cisco\DefenseClaw`},
	}, windowsEnterpriseStandaloneRun{ExitCode: 1})
	named := false
	for _, message := range verify.Errors {
		named = named || (strings.Contains(message.Message, "DefenseClawGateway service") &&
			strings.Contains(message.Message, "enterprise windows repair"))
	}
	if !named {
		t.Fatalf("verify errors = %+v, want the service named with the repair that restores it", verify.Errors)
	}
}

// Every Windows per-user row is written deferred; status counts as pending
// only the targets the guardian's last reconcile left waiting for a session.
func TestWindowsStandaloneEnrollmentCountsOnlyPendingTargets(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets:\n"+
		"  - {sid: S-1-5-21-1-2-3-1001, connector: codex, enabled: true, deferred: true}\n"+
		"  - {sid: S-1-5-21-1-2-3-1002, connector: codex, enabled: true, deferred: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(enterpriseHookGuardianState{
		Version: 1, OK: true, TargetCount: 2, SuccessCount: 1, PendingCount: 1,
		Results: []enterpriseHookReconcileRow{
			{SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
			{SID: "S-1-5-21-1-2-3-1002", Connector: "codex", Pending: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookGuardianStateFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if err != nil || enrollment.Targets != 2 || enrollment.Pending != 1 {
		t.Fatalf("enrollment = %+v, %v; want 2 targets, 1 pending", enrollment, err)
	}
	// Each account and its connectors' states (GAP-1073).
	if len(enrollment.Accounts) != 2 || enrollment.Accounts[0].Connectors["codex"] != "enrolled" ||
		enrollment.Accounts[1].Connectors["codex"] != "pending" {
		t.Fatalf("enrollment accounts = %+v", enrollment.Accounts)
	}
}

// Status and verify of a computer with a pending transaction name it and the
// Setup command that recovers it; verify said "run Repair", which cannot.
func TestWindowsStandaloneInspectionNamesAPendingTransaction(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previousFailure := windowsEnterpriseGatewayStartFailure
	t.Cleanup(func() { windowsEnterpriseGatewayStartFailure = previousFailure })
	windowsEnterpriseGatewayStartFailure = func() (string, string) { return "", "" }
	for action, report := range map[string]*windowsEnterpriseInstallerReport{
		"status": {Installed: true, TransactionPending: true},
		"verify": {Installed: true, TransactionPending: true, Error: "cannot verify while a lifecycle transaction is pending; run Repair"},
	} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{}, report, windowsEnterpriseStandaloneRun{ExitCode: 1})
		text := fmt.Sprintf("%+v %+v", result.Errors, result.Warnings)
		if !strings.Contains(text, "as LocalSystem: "+windowsEnterpriseStandaloneSetupName+" /ensure") || strings.Contains(text, "run Repair") {
			t.Fatalf("%s of a pending transaction: %s", action, text)
		}
	}
}

// While the gateway service runs but another process holds its API port,
// status names each holder (a loopback and a wildcard listener, and one this
// account cannot identify) instead of the bare not_ready fallback, and never
// names the gateway's own listener.
func TestWindowsStandaloneStatusNamesAPIPortHolders(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previousListeners, previousPID, previousIdentity, previousFailure := windowsEnterpriseAPIListeners, windowsEnterpriseServicePID, windowsEnterpriseProcessIdentity, windowsEnterpriseGatewayStartFailure
	previousPort := windowsEnterpriseConfigAPIPort
	t.Cleanup(func() {
		windowsEnterpriseAPIListeners, windowsEnterpriseServicePID, windowsEnterpriseProcessIdentity, windowsEnterpriseGatewayStartFailure = previousListeners, previousPID, previousIdentity, previousFailure
		windowsEnterpriseConfigAPIPort = previousPort
	})
	windowsEnterpriseConfigAPIPort = func(string) (int, error) { return 18970, nil }
	windowsEnterpriseGatewayStartFailure = func() (string, string) { return "", "" }
	loopback, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Close()
	wildcard, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wildcard.Close()
	// The real listener table rows of this test's two listeners stand in for
	// holders of the API port, plus the gateway's own row and a holder whose
	// process this account cannot open.
	const gatewayPID, hiddenPID = 7, 4242
	windowsEnterpriseAPIListeners = func(host string, _ int) ([]daemon.Listener, error) {
		var rows []daemon.Listener
		for _, listener := range []net.Listener{loopback, wildcard} {
			found, err := daemon.Listeners(host, listener.Addr().(*net.TCPAddr).Port)
			if err != nil {
				return nil, err
			}
			rows = append(rows, found...)
		}
		return append(rows, daemon.Listener{Address: "127.0.0.1:18970", PID: gatewayPID}, daemon.Listener{Address: "0.0.0.0:18970", PID: hiddenPID}), nil
	}
	windowsEnterpriseServicePID = func(string) int { return gatewayPID }
	windowsEnterpriseProcessIdentity = func(pid int) (string, string) {
		if pid == hiddenPID {
			return "", ""
		}
		return describeWindowsEnterpriseProcess(pid)
	}
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(status, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Installed: true, GatewayService: "DefenseClawGateway", GatewayServiceState: "running",
	}, windowsEnterpriseStandaloneRun{ExitCode: 1})
	if len(status.Errors) != 1 || status.Errors[0].Code != "api_port_held" {
		t.Fatalf("errors = %+v, want only api_port_held", status.Errors)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	message := status.Errors[0].Message
	for _, want := range []string{
		"127.0.0.1:18970", "listening on 127.0.0.1:", "listening on 0.0.0.0:", filepath.Base(self),
		"pid 4242 (a process this account cannot identify)", "Stop those processes", "takes the port back by itself",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("api_port_held message %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "pid 7 ") || len(status.APIPortHolders) != 3 || status.APIPortHolders[0].PID != os.Getpid() ||
		status.APIPortHolders[0].Account == "" || status.APIPortHolders[2].Image != "" {
		t.Fatalf("holders = %+v, message %q; want this process twice and the hidden holder, not the gateway", status.APIPortHolders, message)
	}

	// GAP-1029: another process answered the readiness probe's /health, so
	// the report says ready, but the gateway holds no listener: status
	// still names the holder and the gateway is not ready. With its own
	// listener present a ready gateway names none.
	ready := &windowsEnterpriseInstallerReport{Installed: true, OK: true, GatewayReady: true,
		GatewayService: "DefenseClawGateway", GatewayServiceState: "running"}
	allListeners := windowsEnterpriseAPIListeners
	windowsEnterpriseAPIListeners = func(string, int) ([]daemon.Listener, error) {
		return []daemon.Listener{{Address: "127.0.0.1:18970", PID: hiddenPID}}, nil
	}
	fooled := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(fooled, &windowsEnterpriseLifecycleOptions{}, ready, windowsEnterpriseStandaloneRun{})
	if len(fooled.Errors) != 1 || fooled.Errors[0].Code != "api_port_held" || fooled.Readiness.Gateway ||
		len(fooled.APIPortHolders) != 1 || fooled.APIPortHolders[0].PID != hiddenPID {
		t.Fatalf("probe answered by a holder: errors = %+v readiness = %+v holders = %+v", fooled.Errors, fooled.Readiness, fooled.APIPortHolders)
	}
	windowsEnterpriseAPIListeners = allListeners
	served := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(served, &windowsEnterpriseLifecycleOptions{}, ready, windowsEnterpriseStandaloneRun{})
	if len(served.Errors) != 0 || !served.Readiness.Gateway {
		t.Fatalf("a ready gateway on its own port: errors = %+v readiness = %+v", served.Errors, served.Readiness)
	}
	// A foreign listener on the default port does not hold a gateway whose
	// installed config uses another port.
	windowsEnterpriseConfigAPIPort = func(string) (int, error) { return 18971, nil }
	windowsEnterpriseAPIListeners = func(_ string, port int) ([]daemon.Listener, error) {
		if port != 18971 {
			return []daemon.Listener{{Address: "127.0.0.1:18970", PID: hiddenPID}}, nil
		}
		return []daemon.Listener{{Address: "127.0.0.1:18971", PID: gatewayPID}}, nil
	}
	custom := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(custom, &windowsEnterpriseLifecycleOptions{}, ready, windowsEnterpriseStandaloneRun{})
	if len(custom.Errors) != 0 || !custom.Readiness.Gateway || len(custom.APIPortHolders) != 0 {
		t.Fatalf("healthy custom-port gateway: errors = %+v readiness = %+v holders = %+v",
			custom.Errors, custom.Readiness, custom.APIPortHolders)
	}
	windowsEnterpriseConfigAPIPort = func(string) (int, error) { return 18970, nil }
	windowsEnterpriseAPIListeners = allListeners

	// A lifecycle that failed before it read the deployment (a CLI from
	// another build, GAP-1658) names no gateway service: the installed
	// DefenseClawGateway service is still not a holder of its own port, and
	// the error names the build mismatch and the installed CLI instead.
	uninstall := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(uninstall, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Error: `DefenseClaw enterprise installer rejected its module before import: DefenseClaw enterprise installer module SHA-256 ` +
			`does not match the pinned payload manifest: C:\ProgramData\DefenseClaw-Installer-0f\DefenseClawEnterprise.psm1`,
	}, windowsEnterpriseStandaloneRun{ExitCode: 1603})
	if len(uninstall.Errors) == 0 || uninstall.Errors[0].Code != "installer_build_mismatch" ||
		!strings.Contains(uninstall.Errors[0].Message, "enterprise windows uninstall --profile standalone") {
		t.Fatalf("mismatched CLI uninstall errors = %+v", uninstall.Errors)
	}
	for _, e := range uninstall.Errors {
		if e.Code == "api_port_held" {
			t.Fatalf("a lifecycle that never started a gateway named a port holder: %+v", uninstall.Errors)
		}
	}
	// A failed lifecycle whose report names no service still does not name
	// the installed gateway service as a holder of its own port.
	failed := enterprisestatus.New("repair", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(failed, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Error: "enterprise readiness timed out: broker_ready=True gateway_ready=False guardian_ready=False",
	}, windowsEnterpriseStandaloneRun{ExitCode: 1603})
	for _, e := range failed.Errors {
		if e.Code == "api_port_held" && strings.Contains(e.Message, "pid 7 ") {
			t.Fatalf("the installed gateway service was named a port holder: %+v", failed.Errors)
		}
	}

	// A first install that timed out waiting for the gateway names the
	// holders too; with no gateway running, every listener is one.
	windowsEnterpriseServicePID = func(string) int { return 0 }
	ensure := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(ensure, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Error: "enterprise readiness timed out: broker_ready=True gateway_ready=False guardian_ready=False",
	}, windowsEnterpriseStandaloneRun{ExitCode: 1603})
	held := false
	for _, e := range ensure.Errors {
		held = held || (e.Code == "api_port_held" && strings.Contains(e.Message, "could not start") && strings.Contains(e.Message, "pid 7 "))
	}
	if !held || len(ensure.APIPortHolders) != 4 {
		t.Fatalf("failed ensure errors = %+v holders = %+v, want api_port_held naming every listener", ensure.Errors, ensure.APIPortHolders)
	}
}

func TestWindowsStandaloneEnsureNamesPerUserInstallLeftovers(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previousListeners, previousPID, previousIdentity, previousFailure := windowsEnterpriseAPIListeners, windowsEnterpriseServicePID, windowsEnterpriseProcessIdentity, windowsEnterpriseGatewayStartFailure
	t.Cleanup(func() {
		windowsEnterpriseAPIListeners, windowsEnterpriseServicePID, windowsEnterpriseProcessIdentity, windowsEnterpriseGatewayStartFailure = previousListeners, previousPID, previousIdentity, previousFailure
	})
	windowsEnterpriseGatewayStartFailure = func() (string, string) { return "", "" }
	windowsEnterpriseAPIListeners = func(string, int) ([]daemon.Listener, error) {
		return []daemon.Listener{{Address: "127.0.0.1:18970", PID: 736}}, nil
	}
	windowsEnterpriseServicePID = func(string) int { return 0 }
	windowsEnterpriseProcessIdentity = func(int) (string, string) {
		return `C:\Users\alice\.local\bin\defenseclaw-gateway.exe`, `HOST\alice`
	}
	ensure := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(ensure, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Errors: []string{`target runtime planning failed with exit 1: Error: enterprise hooks: reject noncanonical managed runtime baseline: ` +
			`enterprise hooks: managed Windows DACL on C:\Users\alice\.defenseclaw has 2 ACEs, expected 4`},
	}, windowsEnterpriseStandaloneRun{ExitCode: 1603})
	var all []string
	for _, e := range ensure.Errors {
		all = append(all, e.Message)
	}
	message := strings.Join(all, "\n")
	for _, want := range []string{
		`the permissions on C:\Users\alice\.defenseclaw are not the ones DefenseClaw set`,
		`move C:\Users\alice\.defenseclaw out of the profile`,
		"pid 736 is a per-user DefenseClaw gateway",
		"`defenseclaw uninstall --all --binaries --yes`",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("ensure errors %q do not contain %q", message, want)
		}
	}
	// A managed gateway runs as its service identity and is not per-user.
	if windowsEnterprisePerUserGatewayHolder(`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`, `NT SERVICE\DefenseClawGateway`) {
		t.Fatal("the managed gateway service was named a per-user gateway")
	}
}
