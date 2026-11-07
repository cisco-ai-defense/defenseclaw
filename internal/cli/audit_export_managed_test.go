// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// withAuditExportManagedSeams makes this a managed Windows host (or not)
// and the caller an administrator (or not), with the deployment at
// testAdministratorPinLayout, which it returns. The pinned commands load the
// config the pin names into the package cfg, so cfg is set back too.
func withAuditExportManagedSeams(t *testing.T, managedHost, administrator bool) managed.StandaloneLayout {
	t.Helper()
	pinned := testAdministratorPinLayout(t)
	host, admin, layout, previousCfg := auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout, cfg
	auditExportManagedHost = func() bool { return managedHost }
	auditExportCallerIsAdministrator = func() bool { return administrator }
	auditExportManagedLayout = func() (managed.StandaloneLayout, error) { return pinned, nil }
	t.Cleanup(func() {
		auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout = host, admin, layout
		cfg = previousCfg
	})
	for _, key := range []string{
		"DEFENSECLAW_HOME", managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		managed.WindowsServiceAccountEnv, connector.WindowsGatewayServiceNameEnv,
	} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	return pinned
}

// testAdministratorPinLayout is the standalone Windows layout the
// administrator pin tests point at. On Windows its roots are in the test's
// temp folder: on a managed computer C:\ProgramData holds the real
// deployment, and a pinned command loaded its config into the package cfg
// and its runtime .env, with the gateway token, into the test process
// (GAP-0093). Elsewhere no process can open a C:\ path, so the product's
// own roots stay.
func testAdministratorPinLayout(t *testing.T) managed.StandaloneLayout {
	t.Helper()
	programFiles, programData := `C:\Program Files`, `C:\ProgramData`
	if runtime.GOOS == "windows" {
		root := t.TempDir()
		programFiles, programData = filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData")
	}
	layout, err := managed.StandaloneWindowsLayoutForRoots(programFiles, programData)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

// An elevated administrator's export reads the managed deployment,
// with the same identity pins the lifecycle gives gateway commands.
func TestAuditExportManagedEnvironmentPointsAnAdministratorAtTheDeployment(t *testing.T) {
	layout := withAuditExportManagedSeams(t, true, true)
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	want := map[string]string{
		"DEFENSECLAW_HOME":                     layout.DataDir,
		managed.ConfigPathEnv:                  layout.ConfigPath,
		managed.DeploymentModeEnv:              "managed_enterprise",
		managed.EnterpriseProfileEnv:           managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv:       `NT SERVICE\DefenseClawGateway`,
		connector.WindowsGatewayServiceNameEnv: "DefenseClawGateway",
	}
	for key, value := range want {
		if got := os.Getenv(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
	// enterprise acp enroll|verify|revoke get the same pins (GAP-0249), for
	// the deployment of the second setup.
	layout = withAuditExportManagedSeams(t, true, true)
	want["DEFENSECLAW_HOME"], want[managed.ConfigPathEnv] = layout.DataDir, layout.ConfigPath
	if err := pinEnterpriseACPAdministratorEnv(enterpriseACPEnrollCmd); err != nil {
		t.Fatalf("enterprise acp: %v", err)
	}
	for key, value := range want {
		if got := os.Getenv(key); got != value {
			t.Fatalf("enterprise acp: %s = %q, want %q", key, got, value)
		}
	}
}

// GAP-2039: a standard account's read-only managed view (AI Discovery,
// machine policy, audit export) gets the elevation_required answer and
// exit 5 that status and verify give, naming the elevated command, and
// the discovery view does not wrap it in an internal prefix.
func TestManagedAdministratorViewRefusesAStandardAccountWithElevationRequired(t *testing.T) {
	withAuditExportManagedSeams(t, true, false)
	restoreAccount, restoreReport := managedHostCurrentAccount, enterpriseDiscoveryGatewayReport
	t.Cleanup(func() { managedHostCurrentAccount, enterpriseDiscoveryGatewayReport = restoreAccount, restoreReport })
	managedHostCurrentAccount = func() string { return `HOST\dcw-std1` }
	refusal := func() string {
		return windowsManagedStandardUserViewAnswer("the AI Discovery inventory",
			"enterprise", "windows", "discovery", "--user", managedHostCurrentAccountName())
	}
	err := pinManagedAdministratorEnvironment("enterprise windows discovery", refusal)
	if err == nil || commandExitCode(err) != 5 {
		t.Fatalf("refusal = %v (exit %d), want exit 5", err, commandExitCode(err))
	}
	for _, want := range []string{"the AI Discovery inventory", "enterprise windows discovery --user dcw-std1`", "Nothing was changed."} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal lacks %q: %q", want, err)
		}
	}
	// GAP-2262: the sentence alone, as status and verify print it; the code
	// stays in --json errors[].code.
	if strings.Contains(err.Error(), "elevation_required") {
		t.Fatalf("refusal text names the internal code: %q", err)
	}
	var refused bytes.Buffer
	writeManagedViewRefusalJSON(&refused, err)
	if !strings.Contains(refused.String(), `"code":"elevation_required","message":"the AI Discovery inventory`) {
		t.Fatalf("--json refusal = %s", refused.String())
	}
	if err := prepareManagedAuditExportEnvironment(); commandExitCode(err) != 5 || !strings.Contains(fmt.Sprint(err), "audit export -o <file>") {
		t.Fatalf("audit export refusal = %v", err)
	}
	enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
		return enterpriseGatewayAIUsage{}, "", pinManagedAdministratorEnvironment("enterprise windows discovery", refusal)
	}
	err = writeWindowsEnterpriseDiscovery(io.Discard, "", false)
	if commandExitCode(err) != 5 || !strings.HasPrefix(err.Error(), "the AI Discovery inventory of a managed computer") {
		t.Fatalf("discovery = %v (exit %d)", err, commandExitCode(err))
	}
}

// The rollback database option belongs to per-user and standalone installs,
// while a managed audit export must use the deployment store. (Secure Client
// drops --db from its command tree: TestSecureClientKeepsTheEnterpriseViews.)
func TestAuditExportDBFlagAndManagedBoundary(t *testing.T) {
	withAuditExportManagedSeams(t, true, false)
	previousDB := auditExportDB
	auditExportDB = "previous/audit.db"
	t.Cleanup(func() { auditExportDB = previousDB })
	if err := auditExportPersistentPreRunE(nil, nil); commandExitCode(err) != 5 {
		t.Fatalf("managed standard account with --db = %v, want elevation refusal", err)
	}
	auditExportCallerIsAdministrator = func() bool { return true }
	if err := auditExportPersistentPreRunE(nil, nil); err != nil {
		t.Fatalf("managed administrator with --db = %v, want read-only copy access", err)
	}
	auditExportManagedHost = func() bool { return false }
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if err := auditExportPersistentPreRunE(nil, nil); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("managed unix mode without administrator = %v, want administrator refusal", err)
	}
}
