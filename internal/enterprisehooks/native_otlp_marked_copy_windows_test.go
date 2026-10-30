// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func gap2568MarkedCodexConfig() []byte {
	var b strings.Builder
	b.WriteString("model = \"gpt-5\"\n\n[otel]\nenvironment = 'windows'\nlog_user_prompt = true\n\n")
	for _, signal := range []struct{ key, path string }{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		b.WriteString("[otel." + signal.key + ".otlp-http]\nendpoint = 'http://127.0.0.1:19010/v1/" + signal.path + "'\nprotocol = 'json'\n\n")
		b.WriteString("[otel." + signal.key + ".otlp-http.headers]\nauthorization = 'Bearer 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\n" +
			"x-defenseclaw-client = 'codex-otel/1.0'\nx-defenseclaw-source = 'codex'\n\n")
	}
	return []byte(b.String())
}

func gap2568Copies(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var copies []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), connector.NativeOTLPMarkedOrphanBackupSuffix) {
			copies = append(copies, entry.Name())
		}
	}
	return copies
}

// GAP-2568: a marked exporter in a configuration whose edit is refused (a
// CODEX_HOME config.toml another owner holds) was copied again on every
// guardian cycle, until the ninth copy failed with "The file exists" and the
// take-back could never finish. A refused edit now leaves no copy, and a copy
// an earlier build left with the same bytes is reused once the edit can run.
func TestWindowsManagedMarkedTakeBackLeavesNoCopyPerRefusedRetry(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	skipNativeOTLPFixtureAsLocalSystem(t, user.User.Sid)
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := connector.UserNativeOTLPConfigPathFor("codex", home)
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	original := gap2568MarkedCodexConfig()
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	previousWarn := windowsNativeOTLPWarn
	var warnings []string
	windowsNativeOTLPWarn = func(message string) { warnings = append(warnings, message) }
	previousRemove := windowsRemoveUserNativeOTLPAt
	refuse := true
	windowsRemoveUserNativeOTLPAt = func(name, path string, opts connector.SetupOpts) ([]string, error) {
		if refuse {
			return nil, errors.New("refusing to rewrite protection on a config not owned by the current user or enrolled target")
		}
		return previousRemove(name, path, opts)
	}
	t.Cleanup(func() {
		windowsNativeOTLPWarn = previousWarn
		windowsRemoveUserNativeOTLPAt = previousRemove
	})
	served := []string{"127.0.0.1:18970", "127.0.0.1:4000"}
	takeBack := func() {
		t.Helper()
		warnings = nil
		if err := connector.WithUserHomeDir(home, func() error {
			removeWindowsManagedUserNativeOTLPAsTarget("codex", user.User.Sid, home, dataDir, served...)
			return nil
		}); err != nil {
			t.Fatalf("take-back failed the install: %v", err)
		}
	}
	for cycle := 0; cycle < 12; cycle++ {
		takeBack()
		if copies := gap2568Copies(t, filepath.Dir(config)); len(copies) != 0 {
			t.Fatalf("cycle %d: a refused edit left copies %v (warnings %q)", cycle, copies, warnings)
		}
		if !connector.NativeOTLPTakeBackPending(dataDir, "codex") {
			t.Fatalf("cycle %d: a refused edit left no take-back-pending marker (warnings %q)", cycle, warnings)
		}
		if strings.Contains(strings.Join(warnings, "\n"), "The file exists") {
			t.Fatalf("cycle %d: the copy scan ran out of names: %q", cycle, warnings)
		}
	}
	data, err := os.ReadFile(config)
	if err != nil || string(data) != string(original) {
		t.Fatalf("a refused edit changed the configuration (err %v)", err)
	}

	// An earlier build left nine copies of the same bytes; once the edit can
	// run, the take-back reuses one of them and finishes.
	dir, base := filepath.Dir(config), filepath.Base(config)
	for n := 0; n < 9; n++ {
		name := base + connector.NativeOTLPMarkedOrphanBackupSuffix
		if n > 0 {
			name = base + "." + string(rune('0'+n)) + connector.NativeOTLPMarkedOrphanBackupSuffix
		}
		if err := os.WriteFile(filepath.Join(dir, name), original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refuse = false
	takeBack()
	data, err = os.ReadFile(config)
	if err != nil || strings.Contains(string(data), "19010") {
		t.Fatalf("take-back did not remove the exporter (err %v, warnings %q)", err, warnings)
	}
	if connector.NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatalf("take-back kept the pending marker after it removed the exporter (warnings %q)", warnings)
	}
	if copies := gap2568Copies(t, dir); len(copies) != 9 {
		t.Fatalf("copies = %v, want the nine earlier copies reused, none added", copies)
	}
	if !connector.NativeOTLPMarkedOrphanRemoved(dataDir, "codex") {
		t.Fatalf("the removal was not recorded for status and verify (warnings %q)", warnings)
	}
}

// GAP-2568 live shape: the CODEX_HOME config.toml is owned by
// Administrators. The take-back copies and edits nothing while another
// account owns it, keeps the pending marker, and verify names it as a
// warning (its credential is revoked) instead of failing the row, which
// rolled the whole managed upgrade back. Once the account owns the file, the
// next take-back removes the exporter.
func TestWindowsManagedMarkedTakeBackLeavesAForeignOwnedConfigAlone(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	skipNativeOTLPFixtureAsLocalSystem(t, user.User.Sid)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.Equals(administrators) {
		t.Skip("the running account is Administrators")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := connector.UserNativeOTLPConfigPathFor("codex", home)
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	original := gap2568MarkedCodexConfig()
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	assignNativeOTLPFixtureOwnerOrSkip(t, config, administrators)
	t.Cleanup(func() { assignNativeOTLPFixtureOwnerOrSkip(t, config, user.User.Sid) })
	previousWarn := windowsNativeOTLPWarn
	var warnings []string
	windowsNativeOTLPWarn = func(message string) { warnings = append(warnings, message) }
	t.Cleanup(func() { windowsNativeOTLPWarn = previousWarn })
	served := []string{"127.0.0.1:18970", "127.0.0.1:4000"}
	takeBack := func() {
		t.Helper()
		warnings = nil
		if err := connector.WithUserHomeDir(home, func() error {
			removeWindowsManagedUserNativeOTLPAsTarget("codex", user.User.Sid, home, dataDir, served...)
			return nil
		}); err != nil {
			t.Fatalf("take-back failed the install: %v", err)
		}
	}
	for cycle := 0; cycle < 10; cycle++ {
		takeBack()
		if copies := gap2568Copies(t, filepath.Dir(config)); len(copies) != 0 {
			t.Fatalf("cycle %d: copies %v of a file another account owns (warnings %q)", cycle, copies, warnings)
		}
		if !connector.NativeOTLPTakeBackPending(dataDir, "codex") {
			t.Fatalf("cycle %d: no take-back-pending marker (warnings %q)", cycle, warnings)
		}
		report := strings.Join(warnings, "\n")
		if !strings.Contains(report, "a file another account owns") || strings.Contains(report, "19010") || strings.Contains(report, "abab") {
			t.Fatalf("cycle %d: warnings = %q", cycle, report)
		}
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != string(original) {
		t.Fatalf("the take-back changed a file another account owns (err %v)", err)
	}
	warnings = nil
	if err := windowsManagedUserNativeOTLPAbsent("codex", home, dataDir, user.User.Sid, served...); err != nil {
		t.Fatalf("verify fails the row on an exporter repair cannot edit, with its credential revoked: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "a file another account owns") {
		t.Fatalf("verify did not name the exporter: %q", warnings)
	}

	assignNativeOTLPFixtureOwnerOrSkip(t, config, user.User.Sid)
	takeBack()
	if data, err := os.ReadFile(config); err != nil || strings.Contains(string(data), "19010") {
		t.Fatalf("take-back did not remove the exporter once the account owns the file (err %v, warnings %q)", err, warnings)
	}
	if connector.NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatalf("take-back kept the pending marker (warnings %q)", warnings)
	}
	if copies := gap2568Copies(t, filepath.Dir(config)); len(copies) != 1 {
		t.Fatalf("copies = %v, want one", copies)
	}
}
