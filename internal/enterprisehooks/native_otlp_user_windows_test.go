// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// GAP-1396: run as LocalSystem (the native suite's account on the managed
// hosts), two fixtures failed for prerequisites of the fixture, not of the
// code: the cleanup impersonates the running account as the target, which
// enterprise hooks refuse for LocalSystem (as
// TestWindowsClaudeManagedVerifyAndRepairStalePerUserNativeOTLP skips), and
// assigning another account (Guest) as a file owner needs a privilege the
// token may not hold. Each now skips with its prerequisite.
func skipNativeOTLPFixtureAsLocalSystem(t *testing.T, sid *windows.SID) {
	t.Helper()
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("skipped as LocalSystem: the fixture targets the running account, and enterprise hooks refuse LocalSystem as a target; run the package as an interactive administrator")
	}
}

func assignNativeOTLPFixtureOwnerOrSkip(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	set := func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}
	err := RunWithWindowsAdministratorOwnerRestorePrivilege(set)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		err = RunWithWindowsOwnerRestorePrivilege(set)
	}
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// Outside LocalSystem the helper above runs set unchanged, so an
		// interactive administrator (the dcw-preflight account) enables its
		// own SeRestorePrivilege on this thread (GAP-1943).
		var held bool
		err, held = runWithFixtureRestorePrivilege(set)
		if !held {
			t.Skipf("this token does not hold SeRestorePrivilege, which assigning another account as the owner of a fixture file needs: %v", err)
		}
	}
	if err != nil {
		t.Fatalf("assign test owner on %s: %v", path, err)
	}
}

// runWithFixtureRestorePrivilege runs fn on a locked thread impersonating
// this process with SeRestorePrivilege enabled; held is false when the token
// does not hold the privilege.
func runWithFixtureRestorePrivilege(fn func() error) (err error, held bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return err, false
	}
	defer func() { _ = windows.RevertToSelf() }()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token); err != nil {
		return err, false
	}
	defer token.Close()
	if err := enableWindowsThreadPrivilege(token, "SeRestorePrivilege"); err != nil {
		return err, false
	}
	return fn(), true
}

// A managed profile directory gives the target write access but reserves
// WRITE_DAC for SYSTEM. The native exporter edit must not try to replace that
// directory's DACL while impersonating the target account.
func TestWindowsManagedNativeOTLPCleanupKeepsProtectedDataDir(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid
	skipNativeOTLPFixtureAsLocalSystem(t, sid)
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []connector.OTLPPathTokenScope{
		connector.OTLPScopeCodex,
		connector.OTLPScopeClaude,
	} {
		if _, err := connector.EnsureOTLPPathToken(dataDir, scope); err != nil {
			t.Fatalf("seed %s scoped token: %v", scope, err)
		}
	}
	if err := windows.SetNamedSecurityInfo(dataDir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(dataDir, sid, true); err != nil {
		t.Fatal(err)
	}

	paths := map[string]string{
		filepath.Join(home, ".codex", "config.toml"):    "[otel.exporter.otlp-http]\nendpoint = 'http://127.0.0.1:19010/v1/logs'\n[otel.exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\nx-defenseclaw-client = 'codex-otel/1.0'\n",
		filepath.Join(home, ".claude", "settings.json"): `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010/otlp/claudecode/` + strings.Repeat("a", 64) + `","OTEL_EXPORTER_OTLP_HEADERS":"x-defenseclaw-source=claudecode,x-defenseclaw-client=claudecode-otel/1.0"}}`,
	}
	for path, body := range paths {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectDirectory(parent); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(path); err != nil {
			t.Fatal(err)
		}
	}
	oldCodex, oldClaude := connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride
	connector.CodexConfigPathOverride = filepath.Join(home, ".codex", "config.toml")
	connector.ClaudeCodeSettingsPathOverride = filepath.Join(home, ".claude", "settings.json")
	t.Cleanup(func() {
		connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride = oldCodex, oldClaude
	})
	impersonation, err := createWindowsManagedRuntimeRestrictedToken()
	if err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	for _, name := range []string{"codex", "claudecode"} {
		err := connector.WithUserHomeDir(home, func() error {
			return runWindowsEnterpriseImpersonatedCallback(impersonation, sid, func() error {
				return removeWindowsManagedUserNativeOTLPAsTarget(name, dataDir)
			})
		})
		if err != nil {
			t.Fatalf("%s: cleanup: %v", name, err)
		}
		if err := windowsManagedUserNativeOTLPAbsent(name, home, dataDir, sid); err != nil {
			t.Fatalf("%s: cleanup left product exporter: %v", name, err)
		}
	}
	for _, scope := range []connector.OTLPPathTokenScope{
		connector.OTLPScopeCodex,
		connector.OTLPScopeClaude,
	} {
		path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s scoped token survived cleanup: %v", scope, err)
		}
	}
	if err := validateWindowsUserPathElement(dataDir, sid, true, true, true); err != nil {
		t.Fatalf("native exporter cleanup changed the managed data directory ACL: %v", err)
	}
}

// GAP-0836: on the managed Windows host std1's Codex and Claude Code configs
// kept the exporters of an earlier per-user install on 127.0.0.1:19010 while
// the managed gateway served 18970. Verify must report that row so the
// guardian repairs it, and install must remove the exporters and their
// credentials from the account's profile.
func TestWindowsManagedRowRefusesAndRemovesStalePerUserNativeOTLP(t *testing.T) {
	previous := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return errors.New("read-only verification attempted target impersonation")
	}
	t.Cleanup(func() { windowsEnterpriseTargetImpersonation = previous })
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	bearer := strings.Repeat("e7", 32)
	codex := "model = \"gpt-5\"\r\n[otel]\r\nlog_user_prompt = true\r\n"
	for _, pair := range [][2]string{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		codex += "[otel." + pair[0] + ".otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/" + pair[1] + "'\r\nprotocol = 'json'\r\n" +
			"[otel." + pair[0] + ".otlp-http.headers]\r\nauthorization = 'Bearer " + bearer + "'\r\n" +
			"x-defenseclaw-source = 'codex'\r\nx-defenseclaw-client = 'codex-otel/1.0'\r\n"
	}
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	claude := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp","OTEL_METRICS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `",` +
		`"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:19010/v1/logs","OTEL_EXPORTER_OTLP_LOGS_HEADERS":"` + headers + `"}}`
	files := map[string]string{
		filepath.Join(home, ".codex", "config.toml"):    codex,
		filepath.Join(home, ".claude", "settings.json"): claude,
		// The per-user install also left its ordinary connector lock files.
		filepath.Join(home, ".codex", "config.toml.lock"):    "",
		filepath.Join(home, ".claude", "settings.json.lock"): "",
	}
	for _, scope := range []connector.OTLPPathTokenScope{connector.OTLPScopeCodex, connector.OTLPScopeClaude} {
		path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = bearer
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		setWindowsTestPathExactOwner(t, filepath.Dir(path), sid)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		setWindowsTestPathExactOwner(t, path, sid)
	}
	setWindowsTestPathExactOwner(t, home, sid)
	setWindowsTestPathExactOwner(t, dataDir, sid)

	for _, name := range []string{"codex", "claudecode"} {
		err := windowsManagedUserNativeOTLPAbsent(name, home, dataDir, sid)
		if err == nil || !strings.Contains(err.Error(), "native OTLP exporter") {
			t.Fatalf("%s: verify accepted a stale per-user exporter: %v", name, err)
		}
		if strings.Contains(err.Error(), bearer) || strings.Contains(err.Error(), "19010") {
			t.Fatalf("%s: verify error carries a value: %v", name, err)
		}
		if err := connector.WithUserHomeDir(home, func() error {
			return removeWindowsManagedUserNativeOTLPAsTarget(name, dataDir)
		}); err != nil {
			t.Fatalf("%s: remove: %v", name, err)
		}
		if err := windowsManagedUserNativeOTLPAbsent(name, home, dataDir, sid); err != nil {
			t.Fatalf("%s: verify after repair: %v", name, err)
		}
	}
	for path := range files {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(path, ".token") {
			t.Fatalf("stale native OTLP credential remains: %s", filepath.Base(path))
		}
		if strings.Contains(string(data), "19010") || strings.Contains(string(data), bearer) {
			t.Fatalf("%s keeps the stale exporter:\n%s", filepath.Base(path), data)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml")); !strings.Contains(string(data), "model = \"gpt-5\"") {
		t.Fatalf("unrelated Codex setting changed:\n%s", data)
	}
}

// Verify runs as the guardian, not the account that owns its old per-user
// token. It reports an orphaned token as residue without treating the
// guardian's different SID as a settings-inspection failure.
func TestWindowsManagedNativeOTLPVerifyIgnoresOtherUserToken(t *testing.T) {
	viewer, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	target, _, _, err := windows.LookupSID("", "Guest")
	if err != nil {
		t.Fatal(err)
	}
	if viewer.User.Sid.Equals(target) {
		t.Skip("verification must use a SID distinct from the token owner")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	operatorSettings := []byte(`{"model":"opus","env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example.test"}}`)
	if err := os.WriteFile(settingsPath, operatorSettings, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, connector.OTLPScopeClaude)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	assignNativeOTLPFixtureOwnerOrSkip(t, tokenPath, target)
	if _, err := connector.LoadOTLPPathToken(dataDir, connector.OTLPScopeClaude); err == nil {
		t.Fatal("foreign-owned token unexpectedly passed the gateway trust check")
	}
	if err := windowsManagedUserNativeOTLPAbsent("claudecode", home, dataDir, target); err == nil ||
		!strings.Contains(err.Error(), "native OTLP exporter") || strings.Contains(err.Error(), "load Claude native OTLP credential") {
		t.Fatalf("verify did not report only the orphaned token residue: %v", err)
	}
	markedSettings := []byte(`{"model":"opus","env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example.test","OTEL_EXPORTER_OTLP_HEADERS":"authorization=Bearer ` +
		strings.Repeat("a", 64) + `,x-defenseclaw-source=claudecode"}}`)
	if err := os.WriteFile(settingsPath, markedSettings, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedUserNativeOTLPAbsent("claudecode", home, dataDir, target); err == nil ||
		!strings.Contains(err.Error(), "native OTLP exporter") || strings.Contains(err.Error(), "load Claude native OTLP credential") {
		t.Fatalf("marked exporter failed inspection on foreign token: %v", err)
	}
	if err := os.WriteFile(settingsPath, operatorSettings, 0o600); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, tokenPath, viewer.User.Sid)
	if err := connector.WithUserHomeDir(home, func() error {
		return removeWindowsManagedUserNativeOTLPAsTarget("claudecode", dataDir)
	}); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedUserNativeOTLPAbsent("claudecode", home, dataDir, target); err != nil {
		t.Fatalf("verify after target cleanup: %v", err)
	}
}

// The same row through the real Claude Code managed Install and Verify.
func TestWindowsClaudeManagedVerifyAndRepairStalePerUserNativeOTLP(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(fixture.home, ".claude", "settings.json")
	if connector.ClaudeCodeSettingsPathOverride != "" {
		settingsPath = connector.ClaudeCodeSettingsPathOverride
	}
	bearer := strings.Repeat("f3", 32)
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	stale := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `"},"model":"opus"}`
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, filepath.Dir(settingsPath), fixture.targetSID)
	setWindowsTestPathExactOwner(t, settingsPath, fixture.targetSID)
	setWindowsTestPathExactOwner(t, settingsPath+".lock", fixture.targetSID)
	// A released per-user install records this same bearer in its scoped
	// sidecar; without that evidence a changed operator bearer is retained.
	tokenPath, err := connector.OTLPPathTokenFilePath(filepath.Join(fixture.home, ".defenseclaw"), connector.OTLPScopeClaude)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(bearer), 0o600); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, tokenPath, fixture.targetSID)
	if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "native OTLP exporter") {
		t.Fatalf("Verify accepted a stale per-user exporter: %v", err)
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "19010") || strings.Contains(string(data), bearer) || !strings.Contains(string(data), "opus") {
		t.Fatalf("repair left the stale exporter or lost a setting:\n%s", data)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify after repair: %v", err)
	}
}

// GAP-1170: an earlier per-user exporter in a config behind a link (for
// example a .codex folder redirected to a network share the account cannot
// write) is never read by the read-only Verify, and repair keeps the scoped
// credential while a config still references it. Verify passed all the same,
// and the exporter kept sending prompt telemetry to the old port. Verify now
// fails with the step while that credential is in the data directory, and
// passes a linked config once repair revoked it.
func TestWindowsManagedNativeOTLPVerifyFailsOnLinkedConfigWithCredential(t *testing.T) {
	for _, tc := range []struct {
		name, dir, file, body string
		scope                 connector.OTLPPathTokenScope
	}{
		{"codex", ".codex", "config.toml", "[otel.exporter.otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/logs'\r\n" +
			"[otel.exporter.otlp-http.headers]\r\nauthorization = 'Bearer " + strings.Repeat("e7", 32) + "'\r\n", connector.OTLPScopeCodex},
		{"claudecode", ".claude", "settings.json", `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010",` +
			`"OTEL_EXPORTER_OTLP_HEADERS":"authorization=Bearer ` + strings.Repeat("e7", 32) + `"}}`, connector.OTLPScopeClaude},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			share := filepath.Join(t.TempDir(), "share")
			if err := os.MkdirAll(share, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(share, tc.file), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			makeTestJunction(t, filepath.Join(home, tc.dir), share)
			tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte(strings.Repeat("e7", 32)), 0o600); err != nil {
				t.Fatal(err)
			}
			err = windowsManagedUserNativeOTLPAbsent(tc.name, home, dataDir, nil)
			if err == nil || !strings.Contains(err.Error(), "hooks/"+filepath.Base(tokenPath)) || !strings.Contains(err.Error(), "as that user") {
				t.Fatalf("verify passed a linked config while the earlier install's credential is kept: %v", err)
			}
			if strings.Contains(err.Error(), "e7e7") || strings.Contains(err.Error(), "19010") {
				t.Fatalf("verify error carries a value: %v", err)
			}
			if err := os.Remove(tokenPath); err != nil {
				t.Fatal(err)
			}
			if err := windowsManagedUserNativeOTLPAbsent(tc.name, home, dataDir, nil); err != nil {
				t.Fatalf("verify of a linked config without the credential: %v", err)
			}
		})
	}
}

// GAP-1170 (refix 1): a signed-out user's take-back runs under an S4U token
// with no network credentials, so it cannot read a .codex or .claude linked
// to a network share, writable or not, clean or not. The install kept the
// scoped credential, the linked-config Verify failed, and the managed
// upgrade rolled back (1603). The take-back now revokes the credential anyway
// and names the account's step, and Verify passes the install.
func TestWindowsManagedNativeOTLPTakeBackRevokesCredentialWhenLinkedConfigUnreadable(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dir, file, body string
		scope                 connector.OTLPPathTokenScope
	}{
		{"codex", ".codex", "config.toml", "[otel.exporter.otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/logs'\r\n" +
			"[otel.exporter.otlp-http.headers]\r\nauthorization = 'Bearer " + strings.Repeat("e7", 32) + "'\r\n", connector.OTLPScopeCodex},
		{"claudecode", ".claude", "settings.json", `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010",` +
			`"OTEL_EXPORTER_OTLP_HEADERS":"authorization=Bearer ` + strings.Repeat("e7", 32) + `"}}`, connector.OTLPScopeClaude},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			share := filepath.Join(t.TempDir(), "share")
			if err := os.MkdirAll(share, 0o700); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(share, tc.file)
			if err := os.WriteFile(config, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			makeTestJunction(t, filepath.Join(home, tc.dir), share)
			denyWindowsTestPathReadForTest(t, config, user.User.Sid)
			if _, err := os.ReadFile(filepath.Join(home, tc.dir, tc.file)); err == nil {
				t.Fatal("fixture: the linked config is still readable")
			}
			tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte(strings.Repeat("e7", 32)), 0o600); err != nil {
				t.Fatal(err)
			}
			report := captureWindowsTestStderr(t, func() {
				if err := connector.WithUserHomeDir(home, func() error {
					return removeWindowsManagedUserNativeOTLPAsTarget(tc.name, dataDir)
				}); err != nil {
					t.Fatalf("take-back failed the install: %v", err)
				}
			})
			if _, err := os.Lstat(tokenPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("take-back kept the scoped credential beside an unreadable linked config: %v", err)
			}
			// GAP-1839: nothing retries a config the install cannot read, so the
			// report does not promise a retry.
			if !strings.Contains(report, "revoked its scoped credential") || !strings.Contains(report, "as that user") ||
				strings.Contains(report, "retries") {
				t.Fatalf("take-back report does not name the step: %q", report)
			}
			if strings.Contains(report, "e7e7") || strings.Contains(report, "19010") {
				t.Fatalf("take-back report carries a value: %q", report)
			}
			if err := windowsManagedUserNativeOTLPAbsent(tc.name, home, dataDir, user.User.Sid); err != nil {
				t.Fatalf("verify fails the install on a linked config after the credential was revoked: %v", err)
			}
		})
	}
}

// denyWindowsTestPathReadForTest denies sid read access to path, as an S4U
// token meets a share it has no credentials for, and puts the DACL back on
// cleanup so the temporary directory can be removed.
func denyWindowsTestPathReadForTest(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	denied, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_GENERIC_READ,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, denied, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	})
}

// captureWindowsTestStderr returns what fn writes to os.Stderr.
func captureWindowsTestStderr(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	func() {
		defer func() { os.Stderr = previous }()
		fn()
	}()
	_ = writer.Close()
	out := <-done
	_ = reader.Close()
	return out
}
